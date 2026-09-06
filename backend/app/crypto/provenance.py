"""
Provenance-risk heuristic for source code findings.

Deterministic, regex/pattern-based signal for crypto code that looks like it
came from an LLM/tutorial rather than a reviewed implementation. It is NOT
an ML model or AI-detection classifier and makes no claim about the true
author of the code - it only flags a small set of precise,
tutorial-boilerplate patterns that are strongly correlated with insecure,
copy-pasted crypto.

False positives are treated as worse than missed detections, so the pattern
list is deliberately small and requires a *literal value binding*
(e.g. `iv = b"0000..."` / `secret_key = "..."`), not merely a variable name.

Design notes / what this does NOT do:
  - It does not run any model, call any network service, or perform AST /
    data-flow analysis.
  - It will not catch AI-authored code written more idiomatically
    (e.g. secrets loaded from a vault), so a "clean" result is NOT proof of
    human authorship or security.
  - It deliberately avoids generic names like `key` to reduce false
    positives; only tutorial-telling bindings are flagged.
"""
import re

# Each entry is (label, compiled pattern). A match sets provenance_risk to
# "ai_suspected". Matching is literal-value bound to keep false positives low.
PROVENANCE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # 1. Hardcoded IV / salt / nonce bound to a literal bytes/str value
    #    (hex-looking or a run of zeros), e.g. iv = b"0000000000000000".
    ("hardcoded_iv_salt_nonce_literal", re.compile(
        r"\b(?:iv|salt|nonce)\s*=\s*(?:[br]{1,2})?['\"](?:[0-9a-fA-F]{8,}|0{8,})['\"]",
        re.IGNORECASE,
    )),
    # 2. Hardcoded key/secret literal binding, e.g. secret_key = b"mykey...".
    ("hardcoded_key_literal", re.compile(
        r"\b(?:secret_key|private_key|encryption_key)\s*=\s*(?:[br]{1,2})?['\"][^'\"]{4,}['\"]",
        re.IGNORECASE,
    )),
    # 3. Explicit ECB block-cipher mode, e.g. AES.MODE_ECB.
    ("ecb_mode", re.compile(
        r"\b[0-9A-Za-z_.]*MODE_ECB\b",
    )),
    # 4. Textbook "plaintext" bound directly to a literal string.
    ("plaintext_literal", re.compile(
        r"\bplaintext\s*=\s*(?:[br]{1,2})?['\"]",
        re.IGNORECASE,
    )),
    # 5. Textbook "ciphertext" bound directly to a literal string.
    ("ciphertext_literal", re.compile(
        r"\bciphertext\s*=\s*(?:[br]{1,2})?['\"]",
        re.IGNORECASE,
    )),
]

# Allowed values for the provenance_risk field on CryptographicArtefact.
PROVENANCE_UNKNOWN = "unknown"
PROVENANCE_AI_SUSPECTED = "ai_suspected"
PROVENANCE_HUMAN_REVIEWED = "human_reviewed"
PROVENANCE_VALUES = (PROVENANCE_UNKNOWN, PROVENANCE_AI_SUSPECTED, PROVENANCE_HUMAN_REVIEWED)


def assess_provenance_risk(line: str) -> str:
    """
    Returns "ai_suspected" if the line matches any tutorial-boilerplate
    pattern, otherwise "unknown". Deterministic and offline.
    """
    if not line:
        return PROVENANCE_UNKNOWN
    for _label, pattern in PROVENANCE_PATTERNS:
        if pattern.search(line):
            return PROVENANCE_AI_SUSPECTED
    return PROVENANCE_UNKNOWN