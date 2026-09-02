import os
import tempfile
from app.scanners.dependency.scanner import scan_dependencies


def test_parses_requirements_txt():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "requirements.txt"), "w") as f:
            f.write("cryptography==42.0.5\nrequests==2.31.0\n# a comment\n")
        errors = []
        deps = scan_dependencies(tmp, errors)
        names = {d["name"] for d in deps}
        assert "cryptography" in names
        assert "requests" in names
        crypto_dep = next(d for d in deps if d["name"] == "cryptography")
        assert crypto_dep["crypto_related"] is True
        assert "RSA" in crypto_dep["known_algorithms"]


def test_parses_package_json():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w") as f:
            f.write('{"dependencies": {"jsonwebtoken": "^9.0.2", "express": "^4.19.2"}}')
        errors = []
        deps = scan_dependencies(tmp, errors)
        names = {d["name"] for d in deps}
        assert "jsonwebtoken" in names
        jwt_dep = next(d for d in deps if d["name"] == "jsonwebtoken")
        assert jwt_dep["crypto_related"] is True


def test_non_crypto_dependency_flagged_correctly():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "requirements.txt"), "w") as f:
            f.write("flask==3.0.0\n")
        errors = []
        deps = scan_dependencies(tmp, errors)
        flask_dep = next(d for d in deps if d["name"] == "flask")
        assert flask_dep["crypto_related"] is False


def test_malformed_package_json_does_not_crash():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w") as f:
            f.write("{not valid json")
        errors = []
        deps = scan_dependencies(tmp, errors)
        assert deps == []
