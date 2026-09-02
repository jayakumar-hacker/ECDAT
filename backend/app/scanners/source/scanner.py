"""
Source code cryptographic discovery scanner.

Read-only: opens files for reading only, never executes anything.
Walks a directory tree (or scans a single file), applies line-based
pattern detection (app/crypto/classifier.py) across supported languages.

This is static regex/keyword analysis, not a full AST/data-flow engine.
Findings state "usage detected via static pattern match" and never claim
proven runtime behavior - see docs/limitations.md.
"""
import os
from app.crypto.algorithms import SUPPORTED_SOURCE_EXTENSIONS, DOCKERFILE_NAMES
from app.crypto.classifier import classify_line, dedupe_findings
from app.core.config import settings


def _iter_candidate_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def _detect_language(path: str) -> str | None:
    base = os.path.basename(path)
    if base in DOCKERFILE_NAMES or base.endswith(".dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(path)[1].lower()
    return SUPPORTED_SOURCE_EXTENSIONS.get(ext)


def scan_source(root: str, errors: list, max_files: int | None = None) -> tuple[list[dict], int]:
    """Returns (findings, files_scanned_count)."""
    findings: list[dict] = []
    files_scanned = 0
    max_files = max_files or settings.MAX_FILES_PER_SCAN

    for path in _iter_candidate_files(root):
        if files_scanned >= max_files:
            errors.append({"scanner": "source", "level": "warning",
                            "message": f"Reached max_files limit ({max_files}); scan truncated.", "file": path})
            break
        language = _detect_language(path)
        if not language:
            continue
        try:
            size = os.path.getsize(path)
        except OSError as e:
            errors.append({"scanner": "source", "level": "error", "message": str(e), "file": path})
            continue
        if size > settings.MAX_FILE_SIZE_BYTES:
            errors.append({"scanner": "source", "level": "warning",
                            "message": f"File exceeds size limit ({size} bytes); skipped.", "file": path})
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError) as e:
            errors.append({"scanner": "source", "level": "error", "message": f"Could not read file: {e}", "file": path})
            continue

        files_scanned += 1
        rel_path = path
        for i, line in enumerate(lines, start=1):
            line_findings = classify_line(line, rel_path, i, language)
            findings.extend(line_findings)

    return dedupe_findings(findings), files_scanned
