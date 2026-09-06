"""Tests for the Tier 2 AI-authored / copy-pasted insecure crypto heuristic:
CryptographicArtefact.provenance_risk + its policy condition."""
import os
import tempfile

from app.crypto.provenance import (
    assess_provenance_risk,
    PROVENANCE_UNKNOWN,
    PROVENANCE_AI_SUSPECTED,
    PROVENANCE_PATTERNS,
)
from app.crypto.classifier import classify_line
from app.models import models
from app.services.policy_service import evaluate_policy
from app.cli import main


def test_provenance_heuristic_flags_tutorial_patterns():
    flagged = [
        'iv = b"0000000000000000"',
        'salt = "0123456789abcdef"',
        'nonce = "0000000000000000"',
        'secret_key = "supersecret12345"',
        'private_key = b"my-private-material"',
        'cipher = AES.new(key, AES.MODE_ECB)',
        'plaintext = b"attack at dawn"',
        'ciphertext = "deadbeefcafe0123"',
    ]
    for line in flagged:
        assert assess_provenance_risk(line) == PROVENANCE_AI_SUSPECTED, line


def test_provenance_heuristic_ignores_benign_bindings():
    benign = [
        'key = os.environ["AES_KEY"]',
        'iv = os.urandom(16)',
        'secret_key = get_secret_from_vault("env:CRYPTO_KEY")',
        'cipher = AES.new(key, AES.MODE_GCM)',
        'plaintext = api.encrypt(raw_data)',   # value is an expression, not a literal
        'KEY = "AES"',   # bare "KEY" identifier is deliberately not flagged
    ]
    for line in benign:
        assert assess_provenance_risk(line) == PROVENANCE_UNKNOWN, line


def test_pattern_list_is_small_and_labelled():
    assert len(PROVENANCE_PATTERNS) <= 8
    for label, pattern in PROVENANCE_PATTERNS:
        assert label.strip()
        assert pattern.pattern


def test_classify_line_sets_provenance_risk():
    # ECB mode on the crypto-call line flags the finding.
    findings = classify_line('cipher = AES.new(key, AES.MODE_ECB)', "x.py", 1, "python")
    assert findings
    for f in findings:
        assert f["provenance_risk"] == PROVENANCE_AI_SUSPECTED

    # Clean GCM usage stays unknown.
    clean = classify_line("cipher = AES.new(key, AES.MODE_GCM)", "y.py", 1, "python")
    for f in clean:
        assert f["provenance_risk"] == PROVENANCE_UNKNOWN

    # Hardcoded IV on the immediately preceding line flags the crypto finding.
    flagged = classify_line('cipher = AES.new(key, AES.MODE_CBC, iv)', "z.py", 2, "python",
                            prev_line='iv = b"0000000000000000"')
    assert flagged
    for f in flagged:
        assert f["provenance_risk"] == PROVENANCE_AI_SUSPECTED


def test_run_scan_sets_provenance_risk_on_source_artefacts(db_session):
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "tutorial.py"), "w") as f:
            f.write('from Crypto.Cipher import AES\niv = b"0000000000000000"\ncipher = AES.new(key, AES.MODE_ECB, iv)\n')
        with open(os.path.join(tmp, "clean.py"), "w") as f:
            f.write('from Crypto.Cipher import AES\niv = os.urandom(16)\ncipher = AES.new(key, AES.MODE_GCM, iv)\n')

        scan = models.Scan(target=tmp, status="pending", scanners_requested=["source"])
        db_session.add(scan)
        db_session.commit()

        from app.services.scan_service import run_scan
        run_scan(db_session, scan)

        artefacts = db_session.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.scan_id == scan.id
        ).all()
        by_file = {os.path.basename(a.file): a for a in artefacts}
        assert "tutorial.py" in by_file
        assert by_file["tutorial.py"].provenance_risk == PROVENANCE_AI_SUSPECTED
        assert by_file["clean.py"].provenance_risk == PROVENANCE_UNKNOWN


def test_policy_rule_provenance_risk_ai_suspected(db_session):
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    a = models.Asset(scan_id=scan.id, name="tutorial AES", algorithm_name="AES", location="t.py:1")
    db_session.add(a)
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a.id, artefact_type="source", algorithm="AES",
        file="t.py", line=1, provenance_risk=PROVENANCE_AI_SUSPECTED,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a.id, artefact_type="source", algorithm="AES",
        file="clean.py", line=2, provenance_risk=PROVENANCE_UNKNOWN,
    ))
    db_session.commit()

    policy = {
        "name": "Provenance Policy",
        "rules": [
            {
                "id": "ai-suspected-signoff",
                "name": "AI-suspected crypto requires human sign-off",
                "provenance_risk": "ai_suspected",
                "severity": "HIGH",
            }
        ],
    }

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "ai-suspected-signoff"
    assert "t.py" in violations[0]["file"]
    assert "human" in violations[0]["message"]


def test_cli_scan_with_provenance_policy_gates():
    with tempfile.TemporaryDirectory() as tmp:
        policy_content = 'version: "1"\nname: "CI Provenance Policy"\nrules:\n  - id: ai-suspected-signoff\n    name: "AI-suspected crypto requires human sign-off"\n    provenance_risk: "ai_suspected"\n    severity: "HIGH"\n'
        with open(os.path.join(tmp, "ecdat-policy.yaml"), "w") as f:
            f.write(policy_content)
        with open(os.path.join(tmp, "tutorial.py"), "w") as f:
            f.write("from Crypto.Cipher import AES\niv = b\"0000000000000000\"\ncipher = AES.new(key, AES.MODE_ECB, iv)\n")
        with open(os.path.join(tmp, "clean.py"), "w") as f:
            f.write("from Crypto.Cipher import AES\niv = os.urandom(16)\ncipher = AES.new(key, AES.MODE_GCM, iv)\n")

        ret_fail = main(["scan", tmp, "--scanners", "source"])
        assert ret_fail == 1

        os.remove(os.path.join(tmp, "tutorial.py"))
        ret_pass = main(["scan", tmp, "--scanners", "source"])
        assert ret_pass == 0