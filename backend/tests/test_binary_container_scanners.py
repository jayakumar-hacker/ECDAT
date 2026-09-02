import os
import tempfile
from app.scanners.binary.scanner import scan_binaries, _detect_format
from app.scanners.container.scanner import scan_containers


def test_detects_elf_format():
    assert _detect_format(b"\x7fELFxxxx") == "ELF"


def test_detects_pe_format():
    assert _detect_format(b"MZxxxx") == "PE"


def test_unrecognized_format_returns_none():
    assert _detect_format(b"not a binary") is None


def test_binary_scan_finds_crypto_symbol_strings():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "libtest.so")
        with open(path, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 20 + b"libcrypto.so.3" + b"\x00" * 20 + b"SHA256_Init")
        errors = []
        results = scan_binaries(tmp, errors)
        labels = {r["label"] for r in results}
        assert any("OpenSSL" in l or "SHA-256" in l for l in labels)
        for r in results:
            assert "runtime usage not confirmed" in r["note"]


def test_container_scan_parses_dockerfile():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11-slim\nRUN apt-get update && apt-get install -y openssl libssl-dev\n")
        errors = []
        result = scan_containers(tmp, errors)
        assert len(result["dockerfiles_found"]) == 1
        assert "python:3.11-slim" in result["base_images"]
        pkg_names = {p["name"] for p in result["crypto_packages"]}
        assert "openssl" in pkg_names
