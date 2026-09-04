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

## Config and protocol scanning

- Parses static configuration files (sshd_config, nginx/apache ssl_protocols/ssl_ciphers,
  openssl.cnf, java.security jdk.tls.disabledAlgorithms, Terraform aws_kms_key/ACM/ssl_policy,
  and Kubernetes TLS Secrets / cert-manager CRDs).
- **What is not covered**: Dynamic runtime protocol negotiation (ECDAT does not
  perform live TLS handshakes or network connections), variables and expressions
  in Terraform that are resolved dynamically via remote state or external secret
  stores, non-standard custom ingress controllers, and encrypted configuration
  files.

## Dependency scanning

- Parses manifest files (requirements.txt, pyproject.toml, package.json,
  pom.xml, go.mod, Cargo.toml) and lockfiles (poetry.lock,
  package-lock.json, Cargo.lock, go.sum, pnpm-lock.yaml, Gemfile.lock)
  offline using lightweight parsers and a bundled offline crypto library dataset.
- Transitive dependencies with known cryptographic capabilities are mapped
  with depth and direct-dependency provenance chains (e.g. `direct -> intermediate -> target`).
- **What is not covered**: Dynamic resolution when no lockfile exists (ECDAT
  does not run `pip install`, `npm install`, `cargo build`, or network-based
  package-manager resolvers), vendored/in-tree unmanifested dependencies,
  private/internal registries not in the bundled database, and conditional
  dependencies evaluated at runtime.
- No CVE or vulnerability-database lookups are performed. ECDAT never
  fabricates a CVE number or severity; if you need CVE data, pair
  ECDAT's crypto-capability findings with a dedicated SCA tool.

## Risk scoring

- The 0-100 risk score is the **ECDAT scoring model**
  (`docs/risk-model.md`), not an official NIST or CVSS score.

## Crypto-agility scoring & migration priority view

- Scores crypto-agility on a static 0-100 scale based on:
  1. Abstraction mechanism (config-driven vs interface/provider abstraction vs compile-time constant),
  2. Dependency version pinning (strictly pinned vs range-pinned vs floating/unpinned),
  3. Call-site blast radius (number of direct reference sites across codebase).
- Derives a prioritized migration metric: `migration_priority = risk_score / max(1, agility_score)` so high-risk, low-agility assets surface first.
- **What is not covered**: Dynamic runtime call-graph depth (ECDAT does not execute code or perform whole-program AST flow analysis), dynamic reflection-based provider lookups, and organizational refactoring costs beyond static code/config evidence.

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
