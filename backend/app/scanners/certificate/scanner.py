"""
Certificate scanner.

Parses X.509 certificates (.pem/.crt/.cer/.der) using the `cryptography`
library. Read-only - never extracts or logs private key material, and
explicitly refuses to parse files that look like private keys.
"""
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der"}
PRIVATE_KEY_MARKERS = (b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY")


def _looks_like_private_key(raw: bytes) -> bool:
    return any(marker in raw for marker in PRIVATE_KEY_MARKERS)


def _key_algorithm_and_size(cert: x509.Certificate) -> tuple[str, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", pub.curve.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return pub.__class__.__name__, None


def _parse_one(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()

    if _looks_like_private_key(raw):
        return {"file": path, "parse_error": "Refused to parse: file appears to contain private key material."}

    cert = None
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(raw, default_backend())
            break
        except Exception:
            continue

    if cert is None:
        return {"file": path, "parse_error": "Could not parse as a valid X.509 certificate (PEM or DER)."}

    key_algo, key_size = _key_algorithm_and_size(cert)
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).days
    sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "unknown"

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    weak_key = (key_algo == "RSA" and (key_size or 0) < 2048) or (key_algo == "DSA" and (key_size or 0) < 2048)
    weak_sig = "sha1" in sig_algo.lower() or "md5" in sig_algo.lower()

    return {
        "file": path,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "valid_from": not_before,
        "valid_until": not_after,
        "expired": now > not_after,
        "days_remaining": days_remaining,
        "public_key_algorithm": key_algo,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "san": san,
        "weak_key": weak_key,
        "weak_signature": weak_sig,
        "parse_error": None,
    }


def _matches_filter(path: str, file_filter: set[str] | None) -> bool:
    if file_filter is None:
        return True
    norm_abs = os.path.abspath(path)
    norm_slash = norm_abs.replace("\\", "/")
    basename = os.path.basename(path)
    for f in file_filter:
        f_norm = os.path.abspath(f) if not os.path.isabs(f) else f
        if norm_abs == f_norm or norm_slash.endswith(f.replace("\\", "/")) or basename == f:
            return True
    return False


def scan_certificates(root: str, errors: list, file_filter: set[str] | None = None) -> list[dict]:
    from app.core.config import settings
    results = []
    targets = []
    if os.path.isfile(root):
        if os.path.splitext(root)[1].lower() in CERT_EXTENSIONS and _matches_filter(root, file_filter):
            targets = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in CERT_EXTENSIONS:
                    p = os.path.join(dirpath, fn)
                    if _matches_filter(p, file_filter):
                        targets.append(p)

    for path in targets:
        try:
            results.append(_parse_one(path))
        except Exception as e:
            errors.append({"scanner": "certificate", "level": "error", "message": str(e), "file": path})
    return results
