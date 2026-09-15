import json
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


def test_policy_disallow_algorithms_rule(db_session):
    policy = {
        "name": "No Legacy Ciphers Policy",
        "rules": [
            {
                "id": "no-legacy-ciphers",
                "name": "No RC4 / 3DES",
                "disallow_algorithms": ["RC4", "3DES", "DES"],
                "severity": "CRITICAL",
            }
        ],
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    a_rc4 = models.Asset(scan_id=scan.id, name="RC4 stream", algorithm_name="RC4", location="legacy/net.py:3")
    a_aes = models.Asset(scan_id=scan.id, name="AES-GCM", algorithm_name="AES", location="modern/crypto.py:9")
    db_session.add_all([a_rc4, a_aes])
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_rc4.id, algorithm="RC4", file="legacy/net.py", line=3,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_aes.id, algorithm="AES-256-GCM", file="modern/crypto.py", line=9,
    ))
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "no-legacy-ciphers"
    assert "RC4" in violations[0]["algorithm"]
    assert "legacy/net.py" in violations[0]["file"]


def test_policy_include_paths_filter(db_session):
    policy = {
        "name": "No MD5 in src",
        "rules": [
            {
                "id": "no-md5-src",
                "name": "No MD5 under src/**",
                "algorithm": "MD5",
                "include_paths": ["**/src/**"],
                "severity": "HIGH",
            }
        ],
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    a_src = models.Asset(scan_id=scan.id, name="MD5 in src", algorithm_name="MD5", location="src/hash.py:5")
    a_tests = models.Asset(scan_id=scan.id, name="MD5 in tests", algorithm_name="MD5", location="tests/hash_test.py:2")
    db_session.add_all([a_src, a_tests])
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_src.id, algorithm="MD5", file="src/hash.py", line=5,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a_tests.id, algorithm="MD5", file="tests/hash_test.py", line=2,
    ))
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    # Only the artefact under src/** should flag; the tests/** one is filtered out.
    assert len(violations) == 1
    assert "src/hash.py" in violations[0]["file"]


def test_policy_min_agility_score_rule(db_session):
    policy = {
        "name": "Agility Floor Policy",
        "rules": [
            {
                "id": "agility-floor",
                "name": "Assets must have agility score >= 70",
                "min_agility_score": 70,
                "severity": "MEDIUM",
            }
        ],
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    a_low = models.Asset(scan_id=scan.id, name="Compile-time constant AES", algorithm_name="AES", agility_score=30, location="static/crypto.py:1")
    a_high = models.Asset(scan_id=scan.id, name="Provider-injected RSA", algorithm_name="RSA", agility_score=90, location="dynamic/crypto.py:1")
    db_session.add_all([a_low, a_high])
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "agility-floor"
    assert "30" in violations[0]["message"]


def test_policy_max_risk_score_rule(db_session):
    policy = {
        "name": "Risk Ceiling Policy",
        "rules": [
            {
                "id": "risk-ceiling",
                "name": "No asset may exceed risk score 60",
                "max_risk_score": 60,
                "severity": "HIGH",
            }
        ],
    }

    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    a_high = models.Asset(scan_id=scan.id, name="TLS 1.0 service", algorithm_name="TLS", location="svc/tls.py:1")
    a_low = models.Asset(scan_id=scan.id, name="AES-256 vault", algorithm_name="AES", location="vault/crypto.py:1")
    db_session.add_all([a_high, a_low])
    db_session.flush()

    db_session.add(models.RiskAssessment(asset_id=a_high.id, score=88, severity="CRITICAL"))
    db_session.add(models.RiskAssessment(asset_id=a_low.id, score=12, severity="LOW"))
    db_session.commit()

    violations = evaluate_policy(policy, scan, db_session)
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "risk-ceiling"
    assert "88" in violations[0]["message"]


def test_load_policy_returns_none_when_missing():
    with tempfile.TemporaryDirectory() as tmp:
        policy_dict, loaded_path = load_policy(tmp)
        assert policy_dict is None
        assert loaded_path is None


def _write_policy(path: str, rules: list[dict], name: str = "CI Policy") -> str:
    """Helper: write an ecdat-policy.yaml and return its path."""
    content = {"version": "1", "name": name, "rules": rules}
    p = os.path.join(path, "ecdat-policy.yaml")
    with open(p, "w") as f:
        yaml.safe_dump(content, f, sort_keys=False)
    return p


def test_cli_json_output(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        _write_policy(tmp, [
            {"id": "no-weak-rsa", "name": "No new RSA < 3072", "algorithm": "RSA", "min_key_size": 3072, "severity": "CRITICAL"},
        ])
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n")

        ret_code = main(["scan", tmp, "--scanners", "source", "--json"])
        # Violation present so the gate fails, but output is still valid JSON.
        assert ret_code == 1
        out = capsys.readouterr().out
        report = json.loads(out)
        assert report["scan_id"]
        assert report["policy_status"] == "FAIL"
        assert len(report["policy_violations"]) >= 1
        assert report["policy_violations"][0]["rule_id"] == "no-weak-rsa"


def test_cli_no_fail_on_violation():
    with tempfile.TemporaryDirectory() as tmp:
        _write_policy(tmp, [
            {"id": "no-weak-rsa", "name": "No new RSA < 3072", "algorithm": "RSA", "min_key_size": 3072, "severity": "CRITICAL"},
        ])
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n")

        # With --no-fail-on-violation the scan reports but does not gate.
        ret_code = main(["scan", tmp, "--scanners", "source", "--no-fail-on-violation"])
        assert ret_code == 0


def test_cli_check_policy_subcommand():
    with tempfile.TemporaryDirectory() as tmp:
        _write_policy(tmp, [
            {"id": "no-weak-rsa", "name": "No new RSA < 3072", "algorithm": "RSA", "min_key_size": 3072, "severity": "CRITICAL"},
        ])

        # Phase 1: violating code -> scan gate fails and check-policy later reports FAIL.
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n")
        assert main(["scan", tmp, "--scanners", "source"]) == 1
        assert main(["check-policy", tmp]) == 1

        # Phase 2: compliant code -> scan gate passes and check-policy passes.
        with open(os.path.join(tmp, "crypto_impl.py"), "w") as f:
            f.write("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n")
        assert main(["scan", tmp, "--scanners", "source"]) == 0
        assert main(["check-policy", tmp]) == 0


def test_cli_scan_with_since_flag():
    with tempfile.TemporaryDirectory() as tmp:
        _init_git_repo(tmp)
        _write_policy(tmp, [
            {"id": "no-weak-rsa", "name": "No new RSA < 3072", "algorithm": "RSA", "min_key_size": 3072, "severity": "CRITICAL"},
        ])

        # Commit 1: compliant base file.
        with open(os.path.join(tmp, "base.py"), "w") as f:
            f.write("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n")
        subprocess.run(["git", "add", "."], cwd=tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp, check=True, capture_output=True)

        # Commit 2: new file with weak RSA -> should be caught by diff-native scan.
        with open(os.path.join(tmp, "new_feature.py"), "w") as f:
            f.write("from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n")
        subprocess.run(["git", "add", "."], cwd=tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "add rsa feature"], cwd=tmp, check=True, capture_output=True)

        # Diff-native scan since HEAD~1 should only see the new weak-RSA file and gate.
        ret_code = main(["scan", tmp, "--scanners", "source", "--since", "HEAD~1"])
        assert ret_code == 1

        # Reverting the new file and committing leaves a clean diff -> gate passes.
        os.remove(os.path.join(tmp, "new_feature.py"))
        subprocess.run(["git", "add", "."], cwd=tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "drop rsa feature"], cwd=tmp, check=True, capture_output=True)
        ret_code_clean = main(["scan", tmp, "--scanners", "source", "--since", "HEAD~1"])
        assert ret_code_clean == 0
