from app.models import models
from app.services.risk_service import compute_risk_for_asset, compute_mosca_for_asset, build_assets_from_artefacts


def _make_scan_and_asset(db, algorithm="RSA-2048", key_size=2048, purpose="key_establishment", business_asset=None):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db.add(scan)
    db.flush()
    asset = models.Asset(
        scan_id=scan.id, business_asset_id=business_asset.id if business_asset else None,
        name=f"{algorithm} test", algorithm_name=algorithm, key_size=key_size,
        purpose=purpose, confidence=0.9,
    )
    db.add(asset)
    db.flush()
    return scan, asset


def test_risk_score_higher_for_quantum_vulnerable(db_session):
    _, rsa_asset = _make_scan_and_asset(db_session, algorithm="RSA-2048")
    _, aes_asset = _make_scan_and_asset(db_session, algorithm="AES-256", purpose="encryption")
    rsa_risk = compute_risk_for_asset(db_session, rsa_asset)
    aes_risk = compute_risk_for_asset(db_session, aes_asset)
    db_session.commit()
    assert rsa_risk.score > aes_risk.score


def test_weak_rsa_key_size_increases_score(db_session):
    _, weak = _make_scan_and_asset(db_session, algorithm="RSA-1024", key_size=1024)
    _, strong = _make_scan_and_asset(db_session, algorithm="RSA-2048", key_size=2048)
    weak_risk = compute_risk_for_asset(db_session, weak)
    strong_risk = compute_risk_for_asset(db_session, strong)
    db_session.commit()
    assert weak_risk.score > strong_risk.score


def test_business_criticality_increases_score(db_session):
    critical_ba = models.BusinessAsset(name="Payments", business_criticality="CRITICAL",
                                        data_sensitivity="RESTRICTED", internet_exposed=True)
    low_ba = models.BusinessAsset(name="Internal Tool", business_criticality="LOW",
                                   data_sensitivity="PUBLIC", internet_exposed=False)
    db_session.add_all([critical_ba, low_ba])
    db_session.flush()

    _, a1 = _make_scan_and_asset(db_session, algorithm="RSA-2048", business_asset=critical_ba)
    _, a2 = _make_scan_and_asset(db_session, algorithm="RSA-2048", business_asset=low_ba)
    r1 = compute_risk_for_asset(db_session, a1)
    r2 = compute_risk_for_asset(db_session, a2)
    db_session.commit()
    assert r1.score > r2.score


def test_severity_thresholds(db_session):
    from app.services.risk_service import _severity_for_score
    assert _severity_for_score(10) == "LOW"
    assert _severity_for_score(40) == "MEDIUM"
    assert _severity_for_score(60) == "HIGH"
    assert _severity_for_score(90) == "CRITICAL"


def test_mosca_urgent_migration_when_far_exceeds_horizon(db_session):
    _, asset = _make_scan_and_asset(db_session, algorithm="RSA-2048")
    mosca = compute_mosca_for_asset(db_session, asset, x_override=15, y_override=3, z_override=10)
    db_session.commit()
    assert mosca.x_plus_y == 18
    assert mosca.exceeds_horizon is True
    assert mosca.result == "URGENT MIGRATION"


def test_mosca_monitor_when_within_horizon(db_session):
    _, asset = _make_scan_and_asset(db_session, algorithm="RSA-2048")
    mosca = compute_mosca_for_asset(db_session, asset, x_override=2, y_override=1, z_override=10)
    db_session.commit()
    assert mosca.exceeds_horizon is False
    assert mosca.result == "MONITOR"


def test_mosca_low_priority_for_non_quantum_vulnerable(db_session):
    _, asset = _make_scan_and_asset(db_session, algorithm="AES-256", purpose="encryption")
    mosca = compute_mosca_for_asset(db_session, asset, x_override=20, y_override=5, z_override=10)
    db_session.commit()
    assert mosca.result == "LOW PRIORITY"


def test_build_assets_from_artefacts_groups_correctly(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.flush()
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, artefact_type="source", algorithm="RSA-2048",
        file="a.py", line=1, purpose="key_establishment", confidence=0.9,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, artefact_type="source", algorithm="RSA-2048",
        file="a.py", line=1, purpose="key_establishment", confidence=0.7,
    ))
    db_session.commit()
    build_assets_from_artefacts(db_session, scan.id)
    assets = db_session.query(models.Asset).filter(models.Asset.scan_id == scan.id).all()
    assert len(assets) == 1  # grouped into a single asset
    assert assets[0].confidence == 0.9  # kept highest-confidence value
    assert assets[0].risk_assessment is not None
    assert assets[0].mosca_assessment is not None
