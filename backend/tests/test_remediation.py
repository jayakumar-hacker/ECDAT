"""
Tests for Feature F9: Library-and-version-aware remediation drafts.
"""
from fastapi.testclient import TestClient
from app.crypto.remediation import (
    get_remediation_draft,
    REMEDIATION_TABLE,
    RemediationEntry,
)
from app.services.migration_service import simulate_migration
from app.main import app


def test_remediation_table_is_populated():
    assert len(REMEDIATION_TABLE) >= 8
    for entry in REMEDIATION_TABLE:
        assert isinstance(entry, RemediationEntry)
        assert entry.language
        assert entry.current_library
        assert entry.algorithm
        assert entry.target_library
        assert entry.minimum_version
        assert entry.replacement_api
        assert entry.hybrid_construction
        assert entry.diff_template.startswith("--- ")


def test_remediation_python_cryptography_rsa_kem():
    draft = get_remediation_draft(
        language="python",
        current_library="cryptography",
        algorithm="RSA-2048",
        purpose="key_establishment",
    )
    assert draft["read_only"] is True
    assert "cryptography" in draft["target_library"].lower()
    assert ">=42" in draft["minimum_version"]
    assert "ML-KEM" in draft["hybrid_construction"] or "ML-KEM" in draft["replacement_api"]
    assert "--- a/" in draft["diff_suggestion"]
    assert "+++ b/" in draft["diff_suggestion"]
    assert "manual" in draft["note"].lower()


def test_remediation_java_bouncycastle():
    draft = get_remediation_draft(
        language="java",
        current_library="bcprov-jdk15on",
        algorithm="RSA",
        purpose="key_establishment",
    )
    assert draft["read_only"] is True
    assert "bcprov-jdk18on" in draft["target_library"]
    assert ">=1.78" in draft["minimum_version"]
    assert "Kyber" in draft["replacement_api"] or "ML-KEM" in draft["replacement_api"]
    assert "pom.xml" in draft["diff_suggestion"]


def test_remediation_javascript_node():
    draft = get_remediation_draft(
        language="javascript",
        current_library="crypto",
        algorithm="RSA",
        purpose="digital_signature",
    )
    assert draft["read_only"] is True
    assert "node" in draft["target_library"].lower()
    assert ">=22" in draft["minimum_version"]
    assert "ml-dsa" in draft["replacement_api"].lower()
    assert "--- a/" in draft["diff_suggestion"]


def test_remediation_fallback_unknown_combination():
    draft = get_remediation_draft(
        language="cobol",
        current_library="custom-lib",
        algorithm="CUSTOM-ALGO",
        purpose="key_establishment",
    )
    assert draft["read_only"] is True
    assert draft["language"] == "cobol"
    assert "diff_suggestion" in draft
    assert "--- a/" in draft["diff_suggestion"]
    assert "+++ b/" in draft["diff_suggestion"]


def test_simulate_migration_includes_remediation():
    result = simulate_migration(
        current_algorithm="RSA-2048",
        proposed_algorithm="ML-KEM-768",
        user_supplied={
            "language": "python",
            "current_library": "cryptography",
            "purpose": "key_establishment",
        },
    )
    assert "remediation" in result
    rem = result["remediation"]
    assert rem["read_only"] is True
    assert ">=42" in rem["minimum_version"]
    assert "--- a/" in rem["diff_suggestion"]
    assert "ML-KEM-768" in rem["replacement_api"]
    # Check that standard simulation output remains intact
    assert result["comparison"]["latency"] == "Not measured"
    assert result["current"]["algorithm"] == "RSA-2048"
    assert result["proposed"]["algorithm"] == "ML-KEM-768"


def test_simulate_migration_api_endpoint(client: TestClient):
    # Authenticate
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "EcdatDemo123!"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    req_payload = {
        "current_algorithm": "RSA-2048",
        "proposed_algorithm": "ML-KEM-768",
        "language": "python",
        "current_library": "cryptography",
        "purpose": "key_establishment",
    }
    res = client.post("/api/migration-plans/simulate", json=req_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "remediation" in data
    assert data["remediation"]["read_only"] is True
    assert "--- a/" in data["remediation"]["diff_suggestion"]
    assert "cryptography" in data["remediation"]["target_library"].lower()
