"""
Turns raw per-line regex matches into structured, deduplicated findings.

Confidence adjustment rules (documented, deterministic - not ML):
  - Matches inside comment lines: confidence reduced (still surfaced, since
    comments/config often *do* reflect real crypto choices, but we cannot
    claim executable evidence).
  - Matches referencing a concrete key-size token get a small boost.
  - Only one finding per (algorithm, file, line) is kept - the strongest match wins.
"""
import re
from app.crypto.algorithms import RULES
from app.crypto.provenance import assess_provenance_risk, PROVENANCE_UNKNOWN

COMMENT_PREFIXES = ("#", "//", "*", "--")


def _looks_like_comment(line: str) -> bool:
    stripped = line.strip()
    return any(stripped.startswith(p) for p in COMMENT_PREFIXES)


def classify_line(line: str, file_path: str, line_no: int, language: str,
                  prev_line: str | None = None) -> list[dict]:
    """Return zero or more findings for a single line of source/config text.

    `prev_line` optionally carries the immediately preceding non-empty line so
    the provenance-risk heuristic can catch tutorial boilerplate where the
    hardcoded literal (e.g. `iv = b"0000..."`) sits on the line before the
    crypto call. Still strictly line-windowed - no AST or data-flow.
    """
    findings = []
    is_comment = _looks_like_comment(line)
    provenance_risk = assess_provenance_risk(line)
    if provenance_risk == PROVENANCE_UNKNOWN and prev_line:
        provenance_risk = assess_provenance_risk(prev_line)
    for rule in RULES:
        m = rule.pattern.search(line)
        if not m:
            continue
        confidence = rule.base_confidence
        if is_comment:
            confidence = max(0.15, confidence - 0.35)
        key_size = rule.key_size
        # try to pull an explicit numeric key size out of the match context
        size_match = re.search(r"\b(512|1024|2048|3072|4096|128|192|256)\b", line)
        if size_match:
            confidence = min(0.98, confidence + 0.05)
            if key_size is None:
                key_size = int(size_match.group(1))

        findings.append({
            "algorithm": rule.algorithm,
            "file": file_path,
            "line": line_no,
            "language": language,
            "usage": f"{rule.algorithm} usage detected via static pattern match",
            "key_size": key_size,
            "purpose": rule.purpose,
            "confidence": round(confidence, 2),
            "evidence": line.strip()[:240],
            "provenance_risk": provenance_risk,
        })
    return findings


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Keep the highest-confidence finding per (algorithm, file, line)."""
    best: dict[tuple, dict] = {}
    for f in findings:
        key = (f["algorithm"], f["file"], f["line"])
        if key not in best or f["confidence"] > best[key]["confidence"]:
            best[key] = f
    return list(best.values())
