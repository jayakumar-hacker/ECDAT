"""
Tests for Feature F14: Crypto-posture drift dashboard.
"""
import datetime
from fastapi.testclient import TestClient
from app.models import models
from app.services.drift_service import (
    compute_posture_drift,
    is_pqc_algorithm,
)
from app.cli import main


def test_is_pqc_algorithm():
    assert is_pqc_algorithm("ML-KEM-768") is True
    assert is_pqc_algorithm("ML-DSA-65") is True
    assert is_pqc_algorithm("SLH-DSA-128") is True
    assert is_pqc_algorithm("Kyber768") is True
    assert is_pqc_algorithm("Dilithium3") is True
    assert is_pqc_algorithm("X25519MLKEM768") is True
    assert is_pqc_algorithm("RSA-2048") is False
    assert is_pqc_algorithm("AES-256") is False
    assert is_pqc_algorithm("SHA-256") is False
    assert is_pqc_algorithm("ECDSA") is False


def test_drift_empty_state(db_session):
    res = compute_posture_drift(db_session, target="/nonexistent/target/xyz")
    assert res["target"] == "/nonexistent/target/xyz"
    assert res["scans_tracked"] == 0
    assert res["history"] == []
    assert res["delta"] is None


def test_posture_drift_chronological_trends(db_session):
    target = "/app/service-crypto"

    # Scan 1: Historical baseline (High risk, no PQC)
    t1 = datetime.datetime(2026, 1, 1, 10, 0, 0)
    scan1 = models.Scan(target=target, status="completed", created_at=t1, end_time=t1)
    db_session.add(scan1)
    db_session.flush()

    for i in range(5):
        db_session.add(models.CryptographicArtefact(
            scan_id=scan1.id, algorithm="RSA-2048", artefact_type="source", file=f"src/{i}.py"
        ))
    asset1 = models.Asset(scan_id=scan1.id, name="Asset 1", algorithm_name="RSA-2048", migration_priority=2.5)
    db_session.add(asset1)
    db_session.flush()
    db_session.add(models.RiskAssessment(asset_id=asset1.id, score=80, severity="HIGH"))

    # Scan 2: Later scan (Migrated 3 usages to ML-KEM, lower risk)
    t2 = datetime.datetime(2026, 6, 1, 10, 0, 0)
    scan2 = models.Scan(target=target, status="completed", created_at=t2, end_time=t2)
    db_session.add(scan2)
    db_session.flush()

    for i in range(2):
        db_session.add(models.CryptographicArtefact(
            scan_id=scan2.id, algorithm="RSA-2048", artefact_type="source", file=f"src/{i}.py"
        ))
    for i in range(3):
        db_session.add(models.CryptographicArtefact(
            scan_id=scan2.id, algorithm="ML-KEM-768", artefact_type="source", file=f"src/pqc_{i}.py"
        ))
    asset2 = models.Asset(scan_id=scan2.id, name="Asset 2", algorithm_name="ML-KEM-768", migration_priority=0.5)
    db_session.add(asset2)
    db_session.flush()
    db_session.add(models.RiskAssessment(asset_id=asset2.id, score=20, severity="LOW"))

    db_session.commit()

    drift = compute_posture_drift(db_session, target=target)
    assert drift["scans_tracked"] == 2
    h1, h2 = drift["history"]

    assert h1["vulnerable_artefacts_count"] == 5
    assert h1["pqc_adoption_percentage"] == 0.0
    assert h1["average_migration_priority"] == 2.5
    assert h1["high_risks"] == 1

    assert h2["vulnerable_artefacts_count"] == 2
    assert h2["pqc_adoption_percentage"] == 60.0
    assert h2["average_migration_priority"] == 0.5
    assert h2["high_risks"] == 0

    delta = drift["delta"]
    assert delta is not None
    assert delta["vulnerable_artefacts_delta"] == -3
    assert delta["pqc_adoption_percentage_delta"] == 60.0
    assert delta["average_migration_priority_delta"] == -2.0
    assert delta["posture_improved"] is True


def test_api_dashboard_drift_endpoint(client: TestClient):
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "EcdatDemo123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/dashboard/drift", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "scans_tracked" in data
    assert "history" in data
    assert "target" in data


def test_cli_drift_command():
    ret = main(["drift", "--json"])
    assert ret == 0
