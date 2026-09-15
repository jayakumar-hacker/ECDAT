import os
import tempfile
from app.scanners.dependency.scanner import scan_dependencies
from app.services.scan_service import run_scan
from app.models import models


def test_parses_poetry_lock_transitive_provenance():
    with tempfile.TemporaryDirectory() as tmp:
        # pyproject.toml declares direct dependency "requests-auth"
        pyproject_content = """
[tool.poetry]
name = "my-app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests-auth = "^1.0.0"
"""
        with open(os.path.join(tmp, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(pyproject_content)

        # poetry.lock has requests-auth -> cryptography (transitive)
        poetry_lock_content = """
[[package]]
name = "requests-auth"
version = "1.0.0"
description = "Auth helper"
optional = false
python-versions = ">=3.8"

[package.dependencies]
cryptography = ">=42.0.0"

[[package]]
name = "cryptography"
version = "42.0.5"
description = "Cryptographic recipes"
optional = false
python-versions = ">=3.8"
"""
        with open(os.path.join(tmp, "poetry.lock"), "w", encoding="utf-8") as f:
            f.write(poetry_lock_content)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        # Look for cryptography
        crypto_dep = next((d for d in deps if d["name"] == "cryptography"), None)
        assert crypto_dep is not None
        assert crypto_dep["crypto_related"] is True
        assert "RSA" in crypto_dep["known_algorithms"]
        assert crypto_dep["is_transitive"] is True
        assert crypto_dep["depth"] == 1
        assert crypto_dep["parent_dependency"] == "requests-auth"
        assert crypto_dep["provenance_chain"] == ["requests-auth", "cryptography"]


def test_parses_package_lock_json_v3_transitive():
    with tempfile.TemporaryDirectory() as tmp:
        lock_json = """{
  "name": "my-node-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-node-app",
      "version": "1.0.0",
      "dependencies": {
        "auth-wrapper": "^1.0.0"
      }
    },
    "node_modules/auth-wrapper": {
      "version": "1.0.0",
      "dependencies": {
        "jsonwebtoken": "^9.0.0"
      }
    },
    "node_modules/jsonwebtoken": {
      "version": "9.0.2",
      "dependencies": {
        "crypto-js": "^4.2.0"
      }
    },
    "node_modules/crypto-js": {
      "version": "4.2.0"
    }
  }
}"""
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as f:
            f.write(lock_json)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        jwt_dep = next((d for d in deps if d["name"] == "jsonwebtoken"), None)
        assert jwt_dep is not None
        assert jwt_dep["crypto_related"] is True
        assert jwt_dep["is_transitive"] is True
        assert jwt_dep["depth"] == 1
        assert jwt_dep["parent_dependency"] == "auth-wrapper"
        assert jwt_dep["provenance_chain"] == ["auth-wrapper", "jsonwebtoken"]

        # crypto-js is at depth 2
        crypto_js = next((d for d in deps if d["name"] == "crypto-js"), None)
        assert crypto_js is not None
        assert crypto_js["crypto_related"] is True
        assert crypto_js["is_transitive"] is True
        assert crypto_js["depth"] == 2
        assert crypto_js["parent_dependency"] == "jsonwebtoken"
        assert crypto_js["provenance_chain"] == ["auth-wrapper", "jsonwebtoken", "crypto-js"]


def test_parses_package_lock_json_v1():
    with tempfile.TemporaryDirectory() as tmp:
        lock_v1 = """{
  "name": "v1-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "web-server": {
      "version": "2.0.0",
      "requires": {
        "node-forge": "^1.3.1"
      },
      "dependencies": {
        "node-forge": {
          "version": "1.3.1"
        }
      }
    }
  }
}"""
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as f:
            f.write(lock_v1)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        forge_dep = next((d for d in deps if d["name"] == "node-forge"), None)
        assert forge_dep is not None
        assert forge_dep["crypto_related"] is True
        assert forge_dep["is_transitive"] is True
        assert forge_dep["depth"] == 1
        assert forge_dep["parent_dependency"] == "web-server"


def test_parses_cargo_lock_transitive():
    with tempfile.TemporaryDirectory() as tmp:
        cargo_lock_content = """
[[package]]
name = "api-server"
version = "0.1.0"
dependencies = [
 "tls-helper 0.1.0",
]

[[package]]
name = "tls-helper"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "openssl-sys 0.9.100",
]

[[package]]
name = "openssl-sys"
version = "0.9.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
        with open(os.path.join(tmp, "Cargo.lock"), "w", encoding="utf-8") as f:
            f.write(cargo_lock_content)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        openssl_sys = next((d for d in deps if d["name"] == "openssl-sys"), None)
        assert openssl_sys is not None
        assert openssl_sys["crypto_related"] is True
        assert "RSA" in openssl_sys["known_algorithms"]
        assert openssl_sys["is_transitive"] is True
        assert openssl_sys["depth"] == 2
        assert openssl_sys["provenance_chain"] == ["api-server", "tls-helper", "openssl-sys"]


def test_parses_go_sum_with_go_mod():
    with tempfile.TemporaryDirectory() as tmp:
        go_mod = """module example.com/payment

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/crypto v0.14.0 // indirect
)
"""
        with open(os.path.join(tmp, "go.mod"), "w", encoding="utf-8") as f:
            f.write(go_mod)

        go_sum = """github.com/gin-gonic/gin v1.9.1 h1:4+DNVrkPnptRz4kW7GkL8w88w/jH9jP7eXy0+Y=
github.com/gin-gonic/gin v1.9.1/go.mod h1:abc=
golang.org/x/crypto v0.14.0 h1:wBqMoZupY4t8px31/==
golang.org/x/crypto v0.14.0/go.mod h1:def=
"""
        with open(os.path.join(tmp, "go.sum"), "w", encoding="utf-8") as f:
            f.write(go_sum)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        crypto_mod = next((d for d in deps if d["name"] == "golang.org/x/crypto"), None)
        assert crypto_mod is not None
        assert crypto_mod["crypto_related"] is True
        assert "Ed25519" in crypto_mod["known_algorithms"]
        assert crypto_mod["is_transitive"] is True
        assert crypto_mod["depth"] == 1
        assert "go.mod" in crypto_mod["parent_dependency"]


def test_parses_pnpm_lock_yaml():
    with tempfile.TemporaryDirectory() as tmp:
        pnpm_yaml = """lockfileVersion: '6.0'

dependencies:
  session-store:
    specifier: ^1.0.0
    version: 1.0.0

packages:
  /session-store@1.0.0:
    dependencies:
      tweetnacl: 1.0.3

  /tweetnacl@1.0.3:
    resolution: {integrity: sha512-xyz}
"""
        with open(os.path.join(tmp, "pnpm-lock.yaml"), "w", encoding="utf-8") as f:
            f.write(pnpm_yaml)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        nacl_dep = next((d for d in deps if d["name"] == "tweetnacl"), None)
        assert nacl_dep is not None
        assert nacl_dep["crypto_related"] is True
        assert "Ed25519" in nacl_dep["known_algorithms"]
        assert nacl_dep["is_transitive"] is True
        assert nacl_dep["depth"] == 1
        assert nacl_dep["parent_dependency"] == "session-store"


def test_parses_gemfile_lock():
    with tempfile.TemporaryDirectory() as tmp:
        gemfile_lock = """GEM
  remote: https://rubygems.org/
  specs:
    oauth2 (2.0.9)
      jwt (>= 1.5, < 3.0)
      rack (>= 1.2, < 4)
    jwt (2.7.1)
    rack (3.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  oauth2

RUBY VERSION
   ruby 3.2.2p53
"""
        with open(os.path.join(tmp, "Gemfile.lock"), "w", encoding="utf-8") as f:
            f.write(gemfile_lock)

        errors = []
        deps = scan_dependencies(tmp, errors)
        assert len(errors) == 0

        jwt_dep = next((d for d in deps if d["name"] == "jwt"), None)
        assert jwt_dep is not None
        assert jwt_dep["crypto_related"] is True
        assert "RSA" in jwt_dep["known_algorithms"]
        assert jwt_dep["is_transitive"] is True
        assert jwt_dep["depth"] == 1
        assert jwt_dep["parent_dependency"] == "oauth2"
        assert jwt_dep["provenance_chain"] == ["oauth2", "jwt"]


def test_scan_service_emits_transitive_artefacts(db_session):
    with tempfile.TemporaryDirectory() as tmp:
        pyproject_content = """
[tool.poetry]
name = "payment-gateway"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
api-client = "^1.0.0"
"""
        with open(os.path.join(tmp, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(pyproject_content)

        poetry_lock = """
[[package]]
name = "api-client"
version = "1.0.0"

[package.dependencies]
cryptography = "^42.0.0"

[[package]]
name = "cryptography"
version = "42.0.5"
"""
        with open(os.path.join(tmp, "poetry.lock"), "w", encoding="utf-8") as f:
            f.write(poetry_lock)

        scan = models.Scan(target=tmp, target_type="directory", scanners_requested=["dependency"])
        db_session.add(scan)
        db_session.commit()
        run_scan(db_session, scan)
        assert scan.status == "completed"

        # Check Dependency record
        deps = db_session.query(models.Dependency).filter(models.Dependency.scan_id == scan.id).all()
        crypto_dep = next((d for d in deps if d.name == "cryptography"), None)
        assert crypto_dep is not None
        assert crypto_dep.is_transitive is True
        assert crypto_dep.depth == 1
        assert crypto_dep.parent_dependency == "api-client"

        # Check CryptographicArtefact records
        artefacts = db_session.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.scan_id == scan.id,
            models.CryptographicArtefact.library == "cryptography",
        ).all()
        assert len(artefacts) > 0
        for art in artefacts:
            assert "Transitive crypto dependency: cryptography" in art.usage
            assert "api-client" in art.usage
            assert "[transitive depth=1 chain=api-client -> cryptography]" in art.evidence
