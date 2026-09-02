from app.models import models
from app.services.risk_service import compute_risk_for_asset
from app.services.cbom_service import generate_cbom, cbom_to_csv


def test_cbom_generation(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.flush()
    asset = models.Asset(scan_id=scan.id, algorithm_name="RSA-2048", key_size=2048,
                          purpose="key_establishment", location="a.py:10", name="RSA-2048 test", confidence=0.9)
    db_session.add(asset)
    db_session.flush()
    compute_risk_for_asset(db_session, asset)
    db_session.commit()

    cbom = generate_cbom(db_session, scan.id)
    assert cbom["componentCount"] == 1
    assert cbom["components"][0]["algorithm"] == "RSA-2048"
    assert cbom["components"][0]["risk_score"] is not None
    assert "CycloneDX" in cbom["note"]


def test_cbom_csv_export(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.flush()
    asset = models.Asset(scan_id=scan.id, algorithm_name="AES-256", purpose="encryption", name="AES test", confidence=0.9)
    db_session.add(asset)
    db_session.commit()

    cbom = generate_cbom(db_session, scan.id)
    csv_text = cbom_to_csv(cbom)
    assert "AES-256" in csv_text
    assert "algorithm" in csv_text.splitlines()[0]


def test_cbom_empty_scan(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.commit()
    cbom = generate_cbom(db_session, scan.id)
    assert cbom["componentCount"] == 0
