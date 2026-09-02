"""
Binary scanner (MVP).

Safe static inspection only: reads file bytes, identifies ELF/PE format
via magic numbers, extracts printable ASCII strings, and searches those
strings for crypto library names / algorithm identifiers. This is
evidence of *linkage or reference*, not proof of runtime behavior -
every finding is phrased accordingly (see docs/limitations.md).

Never executes the binary. Never disassembles/executes any code path.
"""
import os
import re

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".bin", ".o", ""}

CRYPTO_STRING_MARKERS = {
    "libcrypto": ("OpenSSL libcrypto", "HIGH"),
    "libssl": ("OpenSSL libssl / TLS", "HIGH"),
    "libsodium": ("libsodium", "HIGH"),
    "mbedtls": ("mbedTLS", "HIGH"),
    "wolfssl": ("wolfSSL", "HIGH"),
    "bcrypt.dll": ("Windows CNG bcrypt", "HIGH"),
    "advapi32": ("Windows CryptoAPI (advapi32)", "MEDIUM"),
    "AES_encrypt": ("AES (OpenSSL symbol)", "HIGH"),
    "RSA_public_encrypt": ("RSA (OpenSSL symbol)", "HIGH"),
    "EVP_EncryptInit": ("OpenSSL EVP cipher API", "MEDIUM"),
    "SHA256_Init": ("SHA-256 (OpenSSL symbol)", "HIGH"),
    "ecdsa": ("ECDSA reference string", "MEDIUM"),
    "chacha20": ("ChaCha20 reference string", "MEDIUM"),
}


def _detect_format(raw: bytes) -> str | None:
    if raw.startswith(ELF_MAGIC):
        return "ELF"
    if raw.startswith(PE_MAGIC):
        return "PE"
    return None


def _extract_strings(raw: bytes, min_len: int = 5) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.decode("ascii", errors="ignore") for m in pattern.findall(raw)]


def _analyze_binary(path: str) -> list[dict]:
    findings = []
    with open(path, "rb") as f:
        raw = f.read(20 * 1024 * 1024)  # cap read at 20MB for safety/performance

    fmt = _detect_format(raw)
    if fmt is None:
        return findings

    strings = _extract_strings(raw)
    joined_sample = "\n".join(strings)

    for marker, (label, confidence_level) in CRYPTO_STRING_MARKERS.items():
        if marker.lower() in joined_sample.lower():
            findings.append({
                "file": path,
                "format": fmt,
                "evidence_type": "linked_symbol_or_string",
                "label": label,
                "confidence_level": confidence_level,
                "note": f"{label} capability detected through linked library/symbol string; runtime usage not confirmed.",
            })
    return findings


def scan_binaries(root: str, errors: list) -> list[dict]:
    from app.core.config import settings
    results = []
    targets = []
    if os.path.isfile(root):
        targets = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in (".so", ".dll", ".exe", ".o"):
                    targets.append(os.path.join(dirpath, fn))

    for path in targets:
        try:
            size = os.path.getsize(path)
            if size > settings.MAX_FILE_SIZE_BYTES * 10:
                errors.append({"scanner": "binary", "level": "warning",
                                "message": "Binary exceeds scan size limit; skipped.", "file": path})
                continue
            results.extend(_analyze_binary(path))
        except Exception as e:
            errors.append({"scanner": "binary", "level": "error", "message": str(e), "file": path})
    return results
