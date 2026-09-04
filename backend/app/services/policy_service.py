"""
Policy-as-code evaluation engine for cryptographic governance.

Supports repository-level ecdat-policy.yaml defining rules such as:
- 'no new RSA < 3072'
- 'no MD5 outside **/test/**'
- 'internet-exposed assets must be pqc_ready by <deadline>'
- forbidden algorithms (e.g. TLS 1.0, RC4, 3DES, DES)
- minimum agility scores
- maximum risk thresholds

Read-only, offline, deterministic rule checking.
"""
import fnmatch
import os
import re
from datetime import date, datetime
from typing import Any
import yaml

from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import is_quantum_vulnerable, get_algorithm


PQC_ALGORITHMS = {
    "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "KYBER", "DILITHIUM",
    "SPHINCS+", "XMSS", "LMS", "BIKE", "HQC", "CLASSIC-MCELIECE"
}


def load_policy(target_or_path: str) -> tuple[dict | None, str | None]:
    """
    Finds and loads policy from explicit file path or target directory.
    Returns (policy_dict, loaded_path).
    """
    candidates = []
    if os.path.isfile(target_or_path):
        candidates.append(target_or_path)
    else:
        for name in ("ecdat-policy.yaml", "ecdat-policy.yml", ".ecdat-policy.yaml", ".ecdat-policy.yml"):
            candidates.append(os.path.join(target_or_path, name))

    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict) and "rules" in data:
                    return data, path
            except Exception:
                continue
    return None, None


def match_glob(file_path: str, pattern: str) -> bool:
    """
    Matches file_path against glob pattern, normalizing path separators.
    Supports **/test/**, test_*, *.py, etc.
    """
    norm_path = file_path.replace("\\", "/").strip("/")
    norm_pat = pattern.replace("\\", "/").strip("/")

    # Direct fnmatch match
    if fnmatch.fnmatch(norm_path, norm_pat):
        return True

    # Handle **/dir/** pattern
    if norm_pat.startswith("**/"):
        sub_pat = norm_pat[3:]
        if fnmatch.fnmatch(norm_path, sub_pat):
            return True
        # Match anywhere inside path segments
        segments = norm_path.split("/")
        for i in range(len(segments)):
            sub_path = "/".join(segments[i:])
            if fnmatch.fnmatch(sub_path, sub_pat):
                return True

    if "/**" in norm_pat:
        prefix = norm_pat.split("/**")[0]
        if norm_path.startswith(prefix + "/") or norm_path == prefix:
            return True

    # Check filename specifically
    base = os.path.basename(file_path)
    if fnmatch.fnmatch(base, pattern):
        return True

    return False


def is_pqc_ready(algorithm_name: str | None) -> bool:
    if not algorithm_name:
        return False
    upper = algorithm_name.upper()
    if any(pqc in upper for pqc in PQC_ALGORITHMS):
        return True
    algo_data = get_algorithm(algorithm_name)
    if algo_data:
        cat = algo_data.get("category", "").lower()
        if "pqc" in cat or "post-quantum" in cat:
            return True
    # If not primarily quantum vulnerable (e.g. symmetric AES-256, SHA-256/384/512)
    if not is_quantum_vulnerable(algorithm_name):
        return True
    return False


def _extract_key_size(algorithm_name: str, key_size: int | None) -> int | None:
    if key_size:
        return key_size
    m = re.search(r"\b(?:RSA|DH|EC)-?(\d+)\b", algorithm_name, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def evaluate_policy(policy: dict, scan: models.Scan, db: Session) -> list[dict]:
    """
    Evaluates policy rules against assets and artefacts of a scan.
    Returns list of violation dicts.
    """
    rules: list[dict] = policy.get("rules", [])
    violations: list[dict] = []

    assets = db.query(models.Asset).filter(models.Asset.scan_id == scan.id).all()
    artefacts = db.query(models.CryptographicArtefact).filter(models.CryptographicArtefact.scan_id == scan.id).all()

    for rule in rules:
        rule_id = rule.get("id", "unnamed-rule")
        rule_name = rule.get("name", rule_id)
        severity = rule.get("severity", "ERROR").upper()
        target_algo = (rule.get("algorithm") or "").strip().upper()
        disallowed_algos = [a.strip().upper() for a in rule.get("disallow_algorithms", [])]
        min_key_size = rule.get("min_key_size")
        exclude_paths = rule.get("exclude_paths", [])
        include_paths = rule.get("include_paths", [])
        require_pqc = rule.get("require_pqc_ready", False)
        condition = rule.get("condition")
        deadline_str = rule.get("deadline")

        # Check deadline if applicable
        deadline_passed = True
        if deadline_str:
            try:
                deadline_date = datetime.strptime(deadline_str, "%Y-%m-%d").date()
                if date.today() < deadline_date and not rule.get("enforce_immediately", True):
                    deadline_passed = False
            except Exception:
                deadline_passed = True

        # Rule Type 1: Disallowed algorithms (e.g. "no MD5 outside **/test/**", "no 3DES")
        if target_algo or disallowed_algos:
            algos_to_check = set(disallowed_algos)
            if target_algo:
                algos_to_check.add(target_algo)

            for art in artefacts:
                art_algo_upper = (art.algorithm or "").upper()
                matches_algo = any(
                    chk == art_algo_upper or art_algo_upper.startswith(f"{chk}-") or f"-{chk}" in art_algo_upper
                    for chk in algos_to_check
                )
                if not matches_algo:
                    continue

                file_path = art.file or ""
                # Check path filters
                if include_paths and not any(match_glob(file_path, pat) for pat in include_paths):
                    continue
                if exclude_paths and any(match_glob(file_path, pat) for pat in exclude_paths):
                    continue

                # Key size threshold (e.g. "no new RSA < 3072")
                if min_key_size:
                    ksize = _extract_key_size(art.algorithm, art.key_size)
                    if ksize and ksize >= min_key_size:
                        continue  # Key size meets or exceeds minimum, compliant

                    msg = (
                        f"Rule '{rule_name}' violated: algorithm '{art.algorithm}' "
                        f"key size ({ksize or 'unknown'}) is below required minimum of {min_key_size} bits."
                    )
                else:
                    msg = f"Rule '{rule_name}' violated: disallowed algorithm '{art.algorithm}' found in '{file_path}'."

                violations.append({
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "message": msg,
                    "file": file_path,
                    "line": art.line,
                    "algorithm": art.algorithm,
                    "asset_name": art.usage or art.algorithm,
                    "detail": art.evidence or "",
                })

        # Rule Type 2: Internet-exposed PQC requirement
        if require_pqc or condition == "internet_exposed":
            if deadline_passed:
                for asset in assets:
                    ba = asset.business_asset
                    is_exposed = (ba and ba.internet_exposed) or "internet" in (asset.component or "").lower()
                    if not is_exposed and condition == "internet_exposed":
                        continue

                    if not is_pqc_ready(asset.algorithm_name):
                        violations.append({
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "severity": severity,
                            "message": (
                                f"Rule '{rule_name}' violated: internet-exposed asset '{asset.name}' "
                                f"uses quantum-vulnerable algorithm '{asset.algorithm_name}' and is not PQC-ready."
                            ),
                            "file": asset.location.split(":")[0] if asset.location else "",
                            "line": None,
                            "algorithm": asset.algorithm_name,
                            "asset_name": asset.name,
                            "detail": f"Business asset: {ba.name if ba else 'unlinked'} (internet_exposed=True)",
                        })

        # Rule Type 3: Agility score threshold
        min_agility = rule.get("min_agility_score")
        if min_agility is not None:
            for asset in assets:
                if asset.agility_score is not None and asset.agility_score < min_agility:
                    violations.append({
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "severity": severity,
                        "message": (
                            f"Rule '{rule_name}' violated: asset '{asset.name}' has crypto-agility score "
                            f"{asset.agility_score}, below minimum required {min_agility}."
                        ),
                        "file": asset.location.split(":")[0] if asset.location else "",
                        "line": None,
                        "algorithm": asset.algorithm_name,
                        "asset_name": asset.name,
                        "detail": f"Agility score: {asset.agility_score}/100",
                    })

        # Rule Type 4: Risk score threshold
        max_risk = rule.get("max_risk_score")
        if max_risk is not None:
            for asset in assets:
                rscore = asset.risk_assessment.score if asset.risk_assessment else 0
                if rscore > max_risk:
                    violations.append({
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "severity": severity,
                        "message": (
                            f"Rule '{rule_name}' violated: asset '{asset.name}' has risk score {rscore}, "
                            f"exceeding maximum permitted {max_risk}."
                        ),
                        "file": asset.location.split(":")[0] if asset.location else "",
                        "line": None,
                        "algorithm": asset.algorithm_name,
                        "asset_name": asset.name,
                        "detail": f"Risk score: {rscore}/100 ({asset.risk_assessment.severity if asset.risk_assessment else 'UNKNOWN'})",
                    })

    # Deduplicate violations by (rule_id, file, line, algorithm)
    deduped: list[dict] = []
    seen = set()
    for v in violations:
        key = (v["rule_id"], v["file"], v["line"], v["algorithm"])
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    return deduped


def format_policy_report(violations: list[dict], policy_path: str = "") -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("ECDAT Cryptographic Policy-as-Code Enforcement Report")
    if policy_path:
        lines.append(f"Policy File: {policy_path}")
    lines.append("=" * 70)

    if not violations:
        lines.append("Status: [PASS] - All cryptographic policy rules satisfied.")
        lines.append("=" * 70)
        return "\n".join(lines)

    lines.append(f"Status: [FAIL] - {len(violations)} policy violation(s) detected:")
    lines.append("-" * 70)

    for i, v in enumerate(violations, start=1):
        loc = f"{v['file']}:{v['line']}" if v.get("line") else (v.get("file") or "unspecified")
        lines.append(f"{i}. [{v['severity']}] {v['rule_name']}")
        lines.append(f"   Message : {v['message']}")
        lines.append(f"   Location: {loc}")
        lines.append(f"   Crypto  : {v.get('algorithm', '')}")
        if v.get("detail"):
            lines.append(f"   Detail  : {v['detail']}")
        lines.append("")

    lines.append("-" * 70)
    lines.append("Action required: Remediate the policy violations above before merging.")
    lines.append("=" * 70)
    return "\n".join(lines)
