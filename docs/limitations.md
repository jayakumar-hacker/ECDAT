# Limitations

This MVP makes deliberate, documented tradeoffs. Read this before
treating any ECDAT output as authoritative.

## Detection accuracy

- **Static pattern matching, not full AST/data-flow analysis.** The
  source scanner (`app/crypto/classifier.py`, `app/crypto/algorithms.py`)
  uses regex/keyword matching across source lines. It can produce
  false positives (e.g. a variable named `aes_key_backup` in a
  comment) and false negatives (e.g. crypto usage hidden behind
  significant indirection, reflection, or dynamic code generation).
- Findings are phrased as "usage detected via static pattern match" —
  never as proof of runtime behavior.
- Comment lines lower confidence but are still surfaced, since
  config/comment-adjacent crypto choices are often real signal.

## Binary scanning

- The binary scanner performs string/symbol matching on ELF/PE files.
  A match indicates the binary is *linked against or references* a
  crypto library or symbol — it is explicit evidence of **linkage**,
  not confirmed **runtime usage**. Every finding's `note` field states
  this plainly (e.g. "RSA capability detected through linked library;
  runtime usage not confirmed.").

## Certificate scanning

- Only parses well-formed X.509 PEM/DER certificates. Chain validation
  is not performed (no issuer-chain traversal); only the leaf
  certificate's own fields are analyzed.

## Container scanning

- Static Dockerfile/build-context analysis only. Does not use the
  Docker daemon and cannot see runtime container state, layers not
  represented in the Dockerfile, or multi-stage build artifacts that
  aren't copied into the final visible context.

## Dependency scanning

- Parses manifest files with format-specific lightweight parsers
  (not a full package-manager resolver), so transitive dependencies
  are not resolved — only what's directly declared in the manifest.
- No CVE or vulnerability-database lookups are performed. ECDAT never
  fabricates a CVE number or severity; if you need CVE data, pair
  ECDAT's crypto-capability findings with a dedicated SCA tool.

## Risk scoring

- The 0-100 risk score is the **ECDAT scoring model**
  (`docs/risk-model.md`), not an official NIST or CVSS score.

## Mosca analysis

- The threat horizon `Z` is a configurable assumption, not a
  prediction. ECDAT never states that a quantum computer will exist
  by a specific year.

## Migration simulator

- Never fabricates benchmark numbers. Latency, computational overhead,
  and dependency-impact fields default to `"Not measured"` unless the
  caller explicitly supplies real, measured, or clearly-labelled
  estimated/user-supplied values.

## AI Assistant

- The deterministic fallback mode only answers using structured data
  already in the database — it cannot answer questions outside what a
  scan found.
- If an LLM backend is configured, it is instructed to answer only
  from the structured context it's given, but ECDAT cannot fully
  guarantee an external LLM won't embellish; treat LLM-backed answers
  as a convenience layer over the deterministic mode, not a
  replacement for it.

## Authentication

- Simple admin/user MVP model. Not a hardened multi-tenant identity
  system — no password complexity enforcement, no MFA, no session
  revocation list, no rate limiting on login attempts. Structured so
  full RBAC can be added later without a schema rewrite.

## Scale

- No async/distributed scanning; large repositories (very large
  monorepos, giant binaries) will scan more slowly, bounded by
  `MAX_FILE_SIZE_BYTES` and `MAX_FILES_PER_SCAN` in
  `app/core/config.py`.
