"""Tests for the Tier 2 Harvest-now-decrypt-later (HNDL) exposure lens."""
import os
import tempfile

from app.models import models
from app.services.hndl_service import evaluate_hndl, resolve_threshold
from app.services.report_service import build_report_data, hndl_to_csv
from app.services.risk_service import compute_risk_for_asset
from app.cli import main


def _auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _seed(db, specs):
    """Create a scan plus one Asset per spec tied to a BusinessAsset.
    spec: dict(business={...}, asset={...})"""
    scan = models.Scan(target="/tmp/fake", status="completed")
    db.add(scan)
    db.flush()
    for s in specs:
        ba = models.BusinessAsset(**s["business"])
        db.add(ba)
        db.flush()
        a = models.Asset(scan_id=scan.id, business_asset_id=ba.id, **s["asset"])
        db.add(a)
        db.flush()
        compute_risk_for_asset(db, a)
    db.commit()
    return scan


FULL_MATCH = {
    "business": {"name": "Gateway", "internet_exposed": True,
                 "data_sensitivity": "CONFIDENTIAL", "data_retention_years": 15},
    "asset": {"name": "TLS RSA key", "algorithm_name": "RSA-2048", "key_size": 2048,
              "purpose": "key_establishment", "location": "gw/tls.py:5", "component": "openssl"},
}


def test_hndl_flags_only_full_match(db_session):
    non_matching_encryption = {
        "business": {"name": "Vault", "internet_exposed": True,
                     "data_sensitivity": "RESTRICTED", "data_retention_years": 20},
        "asset": {"name": "AES vault", "algorithm_name": "AES-256", "purpose": "encryption",
                  "location": "vault/crypto.py:1", "component": "cryptography"},
    }
    scan = _seed(db_session, [FULL_MATCH, non_matching_encryption])

    matched = evaluate_hndl(db_session, scan_id=scan.id)
    assert len(matched) == 1
    m = matched[0]
    assert m["algorithm_name"] == "RSA-2048"
    assert m["hndl_exposed"] is True
    assert "internet-exposed" in m["hndl_reason"]
    assert "quantum-vulnerable key exchange" in m["hndl_reason"]
    assert "long data shelf-life" in m["hndl_reason"]
    assert "not Q-Day" in m["hndl_reason"]


def test_hndl_requires_all_three_factors(db_session):
    # Missing shelf-life (short retention) -> not flagged.
    short_shelf = {
        "business": {"name": "Short Session", "internet_exposed": True,
                     "data_sensitivity": "PUBLIC", "data_retention_years": 1},
        "asset": {"name": "Short RSA", "algorithm_name": "RSA-2048", "purpose": "key_establishment",
                  "location": "s/tls.py:1", "component": "openssl"},
    }
    scan = _seed(db_session, [short_shelf])
    matched = evaluate_hndl(db_session, scan_id=scan.id)
    assert matched == []
    # The derived field should be persisted as False for non-matching assets.
    a = db_session.query(models.Asset).first()
    assert a.hndl_exposed is False
    assert a.hndl_reason == ""


def test_hndl_captured_in_transit_not_internet(db_session):
    # Not internet-exposed, but component names a transport protocol.
    transit = {
        "business": {"name": "Intranet Relay", "internet_exposed": False,
                     "data_sensitivity": "CONFIDENTIAL", "data_retention_years": 12},
        "asset": {"name": "TLS relay key", "algorithm_name": "RSA-2048", "purpose": "key_establishment",
                  "location": "relay/tls.py:3", "component": "TLS 1.2"},
    }
    scan = _seed(db_session, [transit])
    matched = evaluate_hndl(db_session, scan_id=scan.id)
    assert len(matched) == 1
    assert "captured-in-transit" in matched[0]["hndl_reason"]


def test_hndl_threshold_is_configurable(db_session):
    # 7-year shelf-life: not flagged at default threshold (10), flagged at 5.
    seven_year = {
        "business": {"name": "Mid Shelf", "internet_exposed": True,
                     "data_sensitivity": "INTERNAL", "data_retention_years": 7},
        "asset": {"name": "mid RSA", "algorithm_name": "RSA-2048", "purpose": "key_establishment",
                  "location": "m/tls.py:1", "component": "openssl"},
    }
    scan = _seed(db_session, [seven_year])

    assert evaluate_hndl(db_session, scan_id=scan.id) == []
    matched = evaluate_hndl(db_session, scan_id=scan.id, shelf_life_threshold_years=5)
    assert len(matched) == 1
    assert resolve_threshold(5) == 5
    assert resolve_threshold(None) == 10


def test_hndl_empty_scan_is_safe(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.commit()
    assert evaluate_hndl(db_session, scan_id=scan.id) == []


def test_hndl_csv_section(db_session):
    scan = _seed(db_session, [FULL_MATCH])
    csv_text = hndl_to_csv(db_session, scan.id)
    assert "RSA-2048" in csv_text
    assert "hndl_exposed" in csv_text.splitlines()[0]
    assert "not Q-Day" in csv_text


def test_hndl_report_json_section(db_session):
    scan = _seed(db_session, [FULL_MATCH])
    data = build_report_data(db_session, scan.id)
    assert "hndl_lens" in data
    assert data["hndl_lens"]["count"] == 1
    assert data["hndl_lens"]["assets"][0]["hndl_reason"]


def test_hndl_api_endpoint(client, admin_token, db_session):
    scan = _seed(db_session, [FULL_MATCH])
    resp = client.get(f"/api/hndl?scan_id={scan.id}", headers=_auth(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["threshold_years"] == 10
    assert body["count"] == 1
    assert body["assets"][0]["hndl_reason"]


def test_hndl_api_empty_state(client, admin_token):
    resp = client.get("/api/hndl", headers=_auth(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert "threshold_years" in body
    assert body["count"] == 0
    assert body["assets"] == []


def test_hndl_cli_json_subcommand(db_session):
    scan = _seed(db_session, [FULL_MATCH])
    ret = main(["hndl", "whatever", "--scan-id", scan.id, "--json"])
    assert ret == 0


def test_hndl_cli_no_scan_returns_2():
    with tempfile.TemporaryDirectory() as tmp:
        ret = main(["hndl", tmp])
        assert ret == 2