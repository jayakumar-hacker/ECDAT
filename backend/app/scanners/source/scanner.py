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


def _iter_candidate_files(root: str, file_filter: set[str] | None = None):
    if os.path.isfile(root):
        if _matches_filter(root, file_filter):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in getattr(settings, "SCAN_EXCLUDED_FILES", ()) or fn.startswith("ecdat-policy"):
                continue
            full = os.path.join(dirpath, fn)
            if _matches_filter(full, file_filter):
                yield full


def _detect_language(path: str) -> str | None:
    base = os.path.basename(path)
    if base in DOCKERFILE_NAMES or base.endswith(".dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(path)[1].lower()
    return SUPPORTED_SOURCE_EXTENSIONS.get(ext)


def scan_source(root: str, errors: list, max_files: int | None = None, file_filter: set[str] | None = None) -> tuple[list[dict], int]:
    """Returns (findings, files_scanned_count)."""
    findings: list[dict] = []
    files_scanned = 0
    max_files = max_files or settings.MAX_FILES_PER_SCAN

    for path in _iter_candidate_files(root, file_filter=file_filter):
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
        prev_line: str | None = None
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            line_findings = classify_line(line, rel_path, i, language, prev_line=prev_line)
            findings.extend(line_findings)
            if stripped:
                prev_line = line

    return dedupe_findings(findings), files_scanned
