import os
import subprocess
import tempfile
import yaml
from app.models import models
from app.services.scan_service import run_scan
from app.services.policy_service import load_policy, evaluate_policy, format_policy_report, match_glob
from app.cli import main


def _init_git_repo(path: str):
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True, capture_output=True)


def test_glob_matching():
    assert match_glob("src/auth.py", "*.py")
    assert match_glob("tests/test_auth.py", "**/test*/**")
    assert match_glob("backend/tests/test_crypto.py", "**/tests/**")
    assert match_glob("test_crypto.py", "test_*")
    assert not match_glob("src/auth.py", "**/tests/**")
    assert not match_glob("app/crypto.py", "**/test/**")


def test_diff_native_scan(db_session):
    with tempfile.TemporaryDirectory() as tmp:
        _init_git_repo(tmp)

        # Commit 1: base file with AES-256
        f1 = os.path.join(tmp, "base.py")
        with open(f1, "w") as f:
            f.write('from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n')
        subprocess.run(["git", "add", "."], cwd=tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp, check=True, capture_output=True)

        # Commit 2: new file with RSA-1024
        f2 = os.path.join(tmp, "new_feature.py")
        with open(f2, "w") as f:
            f.write('from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n')
        subprocess.run(["git", "add", "."], cwd=tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "add rsa feature"], cwd=tmp, check=True, capture_output=True)

        # Run scan with since_ref="HEAD~1"
        scan = models.Scan(target=tmp, status="pending", scanners_requested=["source"])
        db_session.add(scan)
        db_session.commit()

        run_scan(db_session, scan, since_ref="HEAD~1")
        assert scan.status == "completed"

        # Verify only new_feature.py was scanned, NOT base.py
        artefacts = db_session.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.scan_id == scan.id
        ).all()

        scanned_files = {os.path.basename(a.file) for a in artefacts}
        assert "new_feature.py" in scanned_files
        assert "base.py" not in scanned_files


def test_policy_no_new_rsa_under_3072(db_session):
    policy = {
        "name": "RSA Size Policy",
        "rules": [
            {
                "id": "no-weak-rsa",
                "name": "No new RSA < 3072",
                "algorithm": "RSA",
                "min_key_size": 3072,
                "severity": "CRITICAL",
            }
        ]
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Weak RSA-2048 asset
    a_weak = models.Asset(scan_id=scan.id, name="RSA-2048", algorithm_name="RSA", key_size=2048, location="auth.py:10")
    # Compliant RSA-4096 asset
    a_strong = models.Asset(scan_id=scan.id, name="RSA-4096", algorithm_name="RSA", key_size=4096, location="root.py:1")
    db_session.add_all([a_weak, a_strong])
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_weak.id, algorithm="RSA", key_size=2048, file="auth.py", line=10,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_strong.id, algorithm="RSA", key_size=4096, file="root.py", line=1,
    ))
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "no-weak-rsa"
    assert "2048" in violations[0]["message"]
    assert "auth.py" in violations[0]["file"]


def test_policy_no_md5_outside_tests(db_session):
    policy = {
        "name": "No MD5 Outside Tests Policy",
        "rules": [
            {
                "id": "no-md5-prod",
                "name": "No MD5 outside **/test/**",
                "algorithm": "MD5",
                "exclude_paths": ["**/test/**", "**/tests/**", "test_*"],
                "severity": "HIGH",
            }
        ]
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # MD5 in production code
    a_prod = models.Asset(scan_id=scan.id, name="MD5 in payment.py", algorithm_name="MD5", location="src/payment.py:5")
    # MD5 in test code
    a_test = models.Asset(scan_id=scan.id, name="MD5 in test_crypto.py", algorithm_name="MD5", location="tests/test_crypto.py:20")
    db_session.add_all([a_prod, a_test])
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_prod.id, algorithm="MD5", file="src/payment.py", line=5,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_test.id, algorithm="MD5", file="tests/test_crypto.py", line=20,
    ))
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "no-md5-prod"
    assert "src/payment.py" in violations[0]["file"]


def test_policy_internet_exposed_must_be_pqc_ready(db_session):
    policy = {
        "name": "PQC Readiness Policy",
        "rules": [
            {
                "id": "exposed-pqc-ready",
                "name": "Internet-exposed assets must be pqc_ready",
                "condition": "internet_exposed",
                "require_pqc_ready": True,
                "deadline": "2030-01-01",
                "severity": "CRITICAL",
            }
        ]
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Internet-exposed business asset
    ba = models.BusinessAsset(name="Public Gateway", internet_exposed=True)
    db_session.add(ba)
    db_session.flush()

    # Non-PQC quantum vulnerable asset on exposed system
    a_vulnerable = models.Asset(
        scan_id=scan.id, business_asset_id=ba.id, name="ECDSA Key",
        algorithm_name="ECDSA", location="gateway.py:10",
    )
    # Quantum-safe asset on exposed system
    a_safe = models.Asset(
        scan_id=scan.id, business_asset_id=ba.id, name="ML-KEM Key Exchange",
        algorithm_name="ML-KEM", location="gateway.py:25",
    )
    db_session.add_all([a_vulnerable, a_safe])
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "exposed-pqc-ready"
    assert "ECDSA" in violations[0]["algorithm"]


def test_cli_scan_and_policy_exit_codes():
    with tempfile.TemporaryDirectory() as tmp:
        _init_git_repo(tmp)

        # Create ecdat-policy.yaml with no-rsa-under-3072 rule
        policy_content = """version: "1"
name: "CI Policy"
rules:
  - id: "no-weak-rsa"
    name: "No new RSA < 3072"
    algorithm: "RSA"
    min_key_size: 3072
    severity: "CRITICAL"
"""
        with open(os.path.join(tmp, "ecdat-policy.yaml"), "w") as f:
            f.write(policy_content)

        # Write code violating policy (RSA-1024)
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n")

        # Running CLI scan should detect violation and exit with code 1
        ret_code = main(["scan", tmp, "--scanners", "source"])
        assert ret_code == 1

        # Now replace with compliant code (AES-256)
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n")

        # Running CLI scan should now pass and exit with code 0
        ret_code_clean = main(["scan", tmp, "--scanners", "source"])
        assert ret_code_clean == 0
