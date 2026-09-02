import os
import tempfile
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.scanners.certificate.scanner import scan_certificates


def _make_cert(path, key_size=2048, days_valid=300, days_offset=0):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days_offset - 10))
        .not_valid_after(now + datetime.timedelta(days=days_offset + days_valid))
        .sign(key, hashes.SHA256())
    )
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key


def test_parses_valid_certificate():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.crt")
        _make_cert(path, key_size=2048)
        errors = []
        results = scan_certificates(tmp, errors)
        assert len(results) == 1
        assert results[0]["public_key_algorithm"] == "RSA"
        assert results[0]["key_size"] == 2048
        assert results[0]["expired"] is False


def test_detects_weak_key():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "weak.crt")
        _make_cert(path, key_size=1024)
        errors = []
        results = scan_certificates(tmp, errors)
        assert results[0]["weak_key"] is True


def test_detects_expired_certificate():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "expired.crt")
        _make_cert(path, days_valid=10, days_offset=-400)
        errors = []
        results = scan_certificates(tmp, errors)
        assert results[0]["expired"] is True


def test_refuses_private_key_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "key.pem")
        with open(path, "w") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n")
        errors = []
        results = scan_certificates(tmp, errors)
        assert len(results) == 1
        assert results[0]["parse_error"] is not None
        assert "Refused" in results[0]["parse_error"]


def test_malformed_certificate_does_not_crash():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bad.crt")
        with open(path, "w") as f:
            f.write("not a real certificate")
        errors = []
        results = scan_certificates(tmp, errors)
        assert results[0]["parse_error"] is not None
