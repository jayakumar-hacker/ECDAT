"""
Offline lockfile parsers and dependency graph resolution.

Parses lockfiles:
- poetry.lock (TOML)
- package-lock.json (JSON v1/v2/v3)
- Cargo.lock (TOML)
- go.sum (line-based)
- pnpm-lock.yaml (YAML)
- Gemfile.lock (indented text)

Constructs the dependency graph, identifies direct vs transitive dependencies,
and traces provenance chains with depth. No network calls are made.
"""
from collections import deque
import json
import os
import re
import tomllib
import yaml


def resolve_dependency_graph(
    packages: dict[str, dict],
    direct_names: set[str],
) -> dict[str, dict]:
    """
    Given packages (key: lower_name -> {"name": orig, "version": ver, "deps": [child_lower, ...]})
    and direct_names (set of lower_names), performs a BFS to compute:
      - is_transitive: bool
      - depth: int (0 for direct, 1+ for transitive)
      - parent_dependency: str (immediate parent package name)
      - provenance_chain: list[str] (path from direct root to this package)
    """
    results: dict[str, dict] = {}

    # If no direct dependencies were identified from manifest or root, infer roots via in-degree
    if not direct_names:
        in_degree = {k: 0 for k in packages}
        for pkg_info in packages.values():
            for child in pkg_info.get("deps", []):
                child_lower = child.lower()
                if child_lower in in_degree:
                    in_degree[child_lower] += 1
        roots = {k for k, deg in in_degree.items() if deg == 0}
        direct_names = roots if roots else set(packages.keys())

    queue: deque[tuple[str, list[str]]] = deque()
    visited_depth: dict[str, int] = {}

    for d in direct_names:
        orig = packages[d]["name"] if d in packages else d
        visited_depth[d] = 0
        results[d] = {
            "is_transitive": False,
            "depth": 0,
            "parent_dependency": "",
            "provenance_chain": [orig],
        }
        if d in packages:
            queue.append((d, [orig]))

    while queue:
        curr_key, chain = queue.popleft()
        curr_depth = len(chain) - 1
        pkg_data = packages.get(curr_key)
        if not pkg_data:
            continue
        for child in pkg_data.get("deps", []):
            child_key = child.lower()
            next_depth = curr_depth + 1
            if child_key not in visited_depth or next_depth < visited_depth[child_key]:
                visited_depth[child_key] = next_depth
                child_orig = packages[child_key]["name"] if child_key in packages else child
                next_chain = chain + [child_orig]
                parent = chain[-1]
                results[child_key] = {
                    "is_transitive": True,
                    "depth": next_depth,
                    "parent_dependency": parent,
                    "provenance_chain": next_chain,
                }
                queue.append((child_key, next_chain))

    # Any packages in lockfile not reached from roots are recorded at depth 0
    for k, pkg_info in packages.items():
        if k not in results:
            orig = pkg_info["name"]
            results[k] = {
                "is_transitive": False,
                "depth": 0,
                "parent_dependency": "",
                "provenance_chain": [orig],
            }

    return results


def parse_poetry_lock(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    packages: dict[str, dict] = {}
    for p in data.get("package", []):
        name = p.get("name", "").strip()
        if not name:
            continue
        ver = p.get("version", "").strip()
        sub_deps = list((p.get("dependencies") or {}).keys())
        packages[name.lower()] = {
            "name": name,
            "version": ver,
            "deps": sub_deps,
        }

    direct_names: set[str] = set()
    pyproject_path = os.path.join(os.path.dirname(path), "pyproject.toml")
    if os.path.isfile(pyproject_path):
        try:
            with open(pyproject_path, "rb") as f:
                pyproj = tomllib.load(f)
            poetry_deps = pyproj.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for k in poetry_deps:
                if k.lower() != "python":
                    direct_names.add(k.lower())
            for item in pyproj.get("project", {}).get("dependencies", []):
                m = re.match(r"^([A-Za-z0-9_.\-]+)", item)
                if m:
                    direct_names.add(m.group(1).lower())
        except Exception:
            pass

    graph = resolve_dependency_graph(packages, direct_names)
    for pkg in packages.values():
        k = pkg["name"].lower()
        g = graph.get(k, {})
        deps.append(record_fn(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem="pypi",
            source_file=path,
            is_transitive=g.get("is_transitive", False),
            depth=g.get("depth", 0),
            parent_dependency=g.get("parent_dependency", ""),
            provenance_chain=g.get("provenance_chain", [pkg["name"]]),
        ))
    return deps


def parse_package_lock_json(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return deps

    packages: dict[str, dict] = {}
    direct_names: set[str] = set()

    # npm v2 / v3 lockfile with "packages"
    if "packages" in data and isinstance(data["packages"], dict):
        root_pkg = data["packages"].get("", {})
        if isinstance(root_pkg, dict):
            for k in (root_pkg.get("dependencies") or {}).keys():
                direct_names.add(k.lower())
            for k in (root_pkg.get("devDependencies") or {}).keys():
                direct_names.add(k.lower())

        for key, val in data["packages"].items():
            if key == "" or not isinstance(val, dict):
                continue
            if "node_modules/" in key:
                raw_name = key.split("node_modules/")[-1]
            else:
                raw_name = key
            raw_name = raw_name.strip()
            if not raw_name:
                continue
            ver = str(val.get("version", ""))
            sub_deps = list((val.get("dependencies") or {}).keys())
            packages[raw_name.lower()] = {
                "name": raw_name,
                "version": ver,
                "deps": sub_deps,
            }
    # npm v1 lockfile with nested "dependencies"
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        for k in data["dependencies"].keys():
            direct_names.add(k.lower())

        def _walk_v1(d: dict):
            for name, val in d.items():
                if not isinstance(val, dict):
                    continue
                ver = str(val.get("version", ""))
                requires = list((val.get("requires") or {}).keys())
                sub_deps = requires or list((val.get("dependencies") or {}).keys())
                packages[name.lower()] = {
                    "name": name,
                    "version": ver,
                    "deps": sub_deps,
                }
                if "dependencies" in val and isinstance(val["dependencies"], dict):
                    _walk_v1(val["dependencies"])

        _walk_v1(data["dependencies"])

    # Fallback to sibling package.json for direct deps if needed
    pkg_json_path = os.path.join(os.path.dirname(path), "package.json")
    if not direct_names and os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                pj = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for k in (pj.get(section) or {}).keys():
                    direct_names.add(k.lower())
        except Exception:
            pass

    graph = resolve_dependency_graph(packages, direct_names)
    for pkg in packages.values():
        k = pkg["name"].lower()
        g = graph.get(k, {})
        deps.append(record_fn(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem="npm",
            source_file=path,
            is_transitive=g.get("is_transitive", False),
            depth=g.get("depth", 0),
            parent_dependency=g.get("parent_dependency", ""),
            provenance_chain=g.get("provenance_chain", [pkg["name"]]),
        ))
    return deps


def parse_cargo_lock(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    package_list = data.get("package", [])
    packages: dict[str, dict] = {}
    direct_names: set[str] = set()

    # Check sibling Cargo.toml
    cargo_toml_path = os.path.join(os.path.dirname(path), "Cargo.toml")
    if os.path.isfile(cargo_toml_path):
        try:
            with open(cargo_toml_path, "rb") as f:
                ct = tomllib.load(f)
            for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                for k in (ct.get(sec) or {}).keys():
                    direct_names.add(k.lower())
        except Exception:
            pass

    for p in package_list:
        name = p.get("name", "").strip()
        if not name:
            continue
        ver = str(p.get("version", ""))
        raw_deps = p.get("dependencies", [])
        sub_deps = [d.split()[0] for d in raw_deps if isinstance(d, str)]
        packages[name.lower()] = {
            "name": name,
            "version": ver,
            "deps": sub_deps,
        }
        # In Cargo.lock, local workspace crates omit the "source" field
        if not direct_names and "source" not in p:
            direct_names.add(name.lower())

    graph = resolve_dependency_graph(packages, direct_names)
    for pkg in packages.values():
        k = pkg["name"].lower()
        g = graph.get(k, {})
        deps.append(record_fn(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem="cargo",
            source_file=path,
            is_transitive=g.get("is_transitive", False),
            depth=g.get("depth", 0),
            parent_dependency=g.get("parent_dependency", ""),
            provenance_chain=g.get("provenance_chain", [pkg["name"]]),
        ))
    return deps


def parse_go_sum(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    seen: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    mod_path = parts[0]
                    ver = parts[1]
                    if ver.endswith("/go.mod"):
                        continue
                    if mod_path not in seen:
                        seen[mod_path] = ver
    except Exception:
        return deps

    direct_mods: set[str] = set()
    indirect_mods: set[str] = set()
    go_mod_path = os.path.join(os.path.dirname(path), "go.mod")
    if os.path.isfile(go_mod_path):
        try:
            with open(go_mod_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_str = line.strip()
                    m = re.match(r"^([a-zA-Z0-9_./\-]+)\s+(v[0-9][A-Za-z0-9_.\-+]*)", line_str)
                    if m:
                        mod = m.group(1).lower()
                        if "// indirect" in line_str:
                            indirect_mods.add(mod)
                        else:
                            direct_mods.add(mod)
        except Exception:
            pass

    for mod_path, ver in seen.items():
        mod_lower = mod_path.lower()
        if direct_mods or indirect_mods:
            if mod_lower in direct_mods:
                is_transitive = False
                depth = 0
                parent = ""
                chain = [mod_path]
            else:
                is_transitive = True
                depth = 1
                parent = "direct (go.mod indirect)"
                chain = ["go.mod", mod_path]
        else:
            is_transitive = False
            depth = 0
            parent = ""
            chain = [mod_path]

        deps.append(record_fn(
            name=mod_path,
            version=ver,
            ecosystem="go",
            source_file=path,
            is_transitive=is_transitive,
            depth=depth,
            parent_dependency=parent,
            provenance_chain=chain,
        ))
    return deps


def parse_pnpm_lock_yaml(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return deps

    direct_names: set[str] = set()
    packages: dict[str, dict] = {}

    # pnpm lockfile v5 / v6
    for sec in ("dependencies", "devDependencies"):
        for k in (data.get(sec) or {}).keys():
            direct_names.add(k.lower())

    # pnpm lockfile v9
    importers = data.get("importers", {})
    if isinstance(importers, dict) and "." in importers:
        root_imp = importers["."]
        for sec in ("dependencies", "devDependencies"):
            for k in (root_imp.get(sec) or {}).keys():
                direct_names.add(k.lower())

    raw_pkgs = data.get("snapshots") or data.get("packages") or {}
    if isinstance(raw_pkgs, dict):
        for pkg_key, pkg_val in raw_pkgs.items():
            if not isinstance(pkg_val, dict):
                continue
            # Regex extracts package name and version: e.g. /@scope/pkg@1.0.0 or express@4.18.2
            m = re.match(r"^/?(@?[^@/]+(?:/[^@/]+)?)@([^/(]+)", str(pkg_key))
            if m:
                name = m.group(1).strip()
                ver = m.group(2).strip()
            else:
                name = str(pkg_key).lstrip("/").split("@")[0].strip()
                ver = ""
            if not name:
                continue
            sub_deps = list((pkg_val.get("dependencies") or {}).keys())
            packages[name.lower()] = {
                "name": name,
                "version": ver,
                "deps": sub_deps,
            }

    # Fallback to sibling package.json for direct deps
    pkg_json_path = os.path.join(os.path.dirname(path), "package.json")
    if not direct_names and os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                pj = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for k in (pj.get(section) or {}).keys():
                    direct_names.add(k.lower())
        except Exception:
            pass

    graph = resolve_dependency_graph(packages, direct_names)
    for pkg in packages.values():
        k = pkg["name"].lower()
        g = graph.get(k, {})
        deps.append(record_fn(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem="npm",
            source_file=path,
            is_transitive=g.get("is_transitive", False),
            depth=g.get("depth", 0),
            parent_dependency=g.get("parent_dependency", ""),
            provenance_chain=g.get("provenance_chain", [pkg["name"]]),
        ))
    return deps


def parse_gemfile_lock(path: str, record_fn) -> list[dict]:
    deps: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return deps

    direct_names: set[str] = set()
    packages: dict[str, dict] = {}
    section = None
    current_spec = None

    for raw_line in lines:
        stripped = raw_line.rstrip()
        if not stripped:
            continue
        if not raw_line.startswith(" "):
            section = stripped
            current_spec = None
            continue

        if section == "DEPENDENCIES":
            m = re.match(r"^\s{2}([A-Za-z0-9_.\-]+)", raw_line)
            if m:
                direct_names.add(m.group(1).lower())
        elif section == "GEM":
            if stripped == "specs:":
                continue
            # Gem spec at 4 spaces indentation
            m_spec = re.match(r"^\s{4}([A-Za-z0-9_.\-]+)\s*(?:\(([^)]+)\))?", raw_line)
            if m_spec:
                gem_name = m_spec.group(1)
                gem_ver = m_spec.group(2) or ""
                current_spec = gem_name.lower()
                packages[current_spec] = {
                    "name": gem_name,
                    "version": gem_ver,
                    "deps": [],
                }
            elif current_spec:
                # Sub-dependency at 6+ spaces indentation
                m_sub = re.match(r"^\s{6,}([A-Za-z0-9_.\-]+)", raw_line)
                if m_sub:
                    packages[current_spec]["deps"].append(m_sub.group(1))

    graph = resolve_dependency_graph(packages, direct_names)
    for pkg in packages.values():
        k = pkg["name"].lower()
        g = graph.get(k, {})
        deps.append(record_fn(
            name=pkg["name"],
            version=pkg["version"],
            ecosystem="gem",
            source_file=path,
            is_transitive=g.get("is_transitive", False),
            depth=g.get("depth", 0),
            parent_dependency=g.get("parent_dependency", ""),
            provenance_chain=g.get("provenance_chain", [pkg["name"]]),
        ))
    return deps
