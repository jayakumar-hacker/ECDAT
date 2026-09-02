"""
Dependency scanner.

Parses common manifest formats (requirements.txt, pyproject.toml,
package.json, pom.xml, go.mod, Cargo.toml, Dockerfile) with lightweight,
format-appropriate parsing (no arbitrary code execution - manifests are
only ever read as text/data, never imported or run).

Cross-references package names against knowledge-base/libraries/crypto_libraries.json
to flag crypto-capable dependencies and their known algorithms. Does not
invent CVEs or version-specific vulnerability data.
"""
import json
import os
import re

_LIB_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
    "knowledge-base", "libraries", "crypto_libraries.json",
)
with open(_LIB_DB_PATH, "r", encoding="utf-8") as f:
    _CRYPTO_LIB_DB = json.load(f)


def _lookup(name: str) -> dict | None:
    key = name.strip().lower()
    return _CRYPTO_LIB_DB.get(key)


def _record(name: str, version: str, ecosystem: str, source_file: str) -> dict:
    info = _lookup(name)
    return {
        "name": name,
        "version": version or "unknown",
        "ecosystem": ecosystem,
        "source_file": source_file,
        "crypto_related": info is not None,
        "known_algorithms": info["known_algorithms"] if info else [],
        "confidence": 0.9 if info else 0.3,
    }


def _parse_requirements_txt(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]*)", line)
            if m:
                deps.append(_record(m.group(1), m.group(3), "pypi", path))
    return deps


def _parse_pyproject_toml(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    for m in re.finditer(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"?([\^~]?[0-9][A-Za-z0-9_.\-]*)?', text, re.MULTILINE):
        name = m.group(1)
        if name.lower() in ("python", "name", "version", "description", "authors", "readme", "license"):
            continue
        deps.append(_record(name, m.group(2) or "", "pypi", path))
    return deps


def _parse_package_json(path: str) -> list[dict]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            deps.append(_record(name, str(version), "npm", path))
    return deps


def _parse_pom_xml(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    for m in re.finditer(r"<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?", text):
        deps.append(_record(m.group(1), m.group(2) or "", "maven", path))
    return deps


def _parse_go_mod(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    for m in re.finditer(r"^\s*([a-zA-Z0-9_./\-]+)\s+(v[0-9][A-Za-z0-9_.\-+]*)", text, re.MULTILINE):
        deps.append(_record(m.group(1), m.group(2), "go", path))
    return deps


def _parse_cargo_toml(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = stripped.startswith("[dependencies")
            continue
        if in_deps and "=" in stripped:
            name = stripped.split("=", 1)[0].strip()
            ver_match = re.search(r'"([^"]+)"', stripped)
            deps.append(_record(name, ver_match.group(1) if ver_match else "", "cargo", path))
    return deps


def _parse_dockerfile(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    for m in re.finditer(r"(?:apt-get install|apk add|yum install)[^\n]*", text, re.IGNORECASE):
        for pkg in re.findall(r"\b(openssl|libssl-dev|libsodium|libsodium-dev|mbedtls|wolfssl|libressl)\b", m.group(0), re.IGNORECASE):
            deps.append(_record(pkg, "", "os", path))
    return deps


_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "package.json": _parse_package_json,
    "pom.xml": _parse_pom_xml,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
}


def scan_dependencies(root: str, errors: list) -> list[dict]:
    """Walk the tree looking for manifest files and parse each with its dedicated parser."""
    from app.core.config import settings
    deps: list[dict] = []
    targets = []
    if os.path.isfile(root):
        targets = [root]
        walk_root = None
    else:
        walk_root = root

    if walk_root:
        for dirpath, dirnames, filenames in os.walk(walk_root):
            dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
            for fn in filenames:
                if fn in _PARSERS or fn in ("Dockerfile",) or fn.endswith(".dockerfile"):
                    targets.append(os.path.join(dirpath, fn))

    for path in targets:
        base = os.path.basename(path)
        try:
            if base in ("Dockerfile",) or base.endswith(".dockerfile"):
                deps.extend(_parse_dockerfile(path))
            elif base in _PARSERS:
                deps.extend(_PARSERS[base](path))
        except (OSError, UnicodeDecodeError, re.error) as e:
            errors.append({"scanner": "dependency", "level": "error", "message": str(e), "file": path})

    return deps
