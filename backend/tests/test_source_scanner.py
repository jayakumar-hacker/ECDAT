import os
import tempfile
from app.scanners.source.scanner import scan_source


def _write(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def test_detects_rsa_2048():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "auth.py", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
        errors = []
        findings, files_scanned = scan_source(tmp, errors)
        assert files_scanned == 1
        algos = {f["algorithm"] for f in findings}
        assert "RSA-2048" in algos or "RSA" in algos


def test_detects_md5_and_sha1():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "hash.py", "import hashlib\nh1 = hashlib.md5(data)\nh2 = hashlib.sha1(data)\n")
        errors = []
        findings, _ = scan_source(tmp, errors)
        algos = {f["algorithm"] for f in findings}
        assert "MD5" in algos
        assert "SHA-1" in algos


def test_skips_excluded_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "node_modules"))
        _write(tmp, os.path.join("node_modules", "lib.js"), "AES-256\n")
        errors = []
        findings, files_scanned = scan_source(tmp, errors)
        assert files_scanned == 0


def test_comment_lowers_confidence():
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "a.py", "# uses AES-256 for encryption\n")
        _write(tmp, "b.py", "cipher = AES256(key)\n")
        errors = []
        findings, _ = scan_source(tmp, errors)
        comment_finding = next(f for f in findings if f["file"].endswith("a.py"))
        code_finding = next(f for f in findings if f["file"].endswith("b.py"))
        assert comment_finding["confidence"] < code_finding["confidence"]


def test_handles_missing_target_gracefully():
    errors = []
    findings, files_scanned = scan_source("/nonexistent/path/xyz", errors)
    assert findings == []
    assert files_scanned == 0


def test_single_file_scan():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "single.py", "AES-256-GCM\n")
        errors = []
        findings, files_scanned = scan_source(path, errors)
        assert files_scanned == 1
        assert any(f["algorithm"] == "AES-GCM" for f in findings)
