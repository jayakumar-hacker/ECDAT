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

## Diff-native CI mode

- Diff-native scans (`ecdat scan --since <git-ref>`) resolve the changed-file
  set with `git diff --name-only` (including untracked files). Only files
  listed in the diff are fed to the scanners.
- **What is not covered**: The ref must exist and be reachable from the
  working tree; ECDAT does not fetch, rebase, or otherwise mutate the
  repository. Deleted files are reported by git but contain no scannable
  content. Rename-heavy or history-rewritten branches change what the diff
  set contains; treat results as "what changed since this ref", not a
  substitute for a full merge-base analysis. If the git diff fails (e.g. no
  git repo or an invalid ref), the scan falls back to a full scan and logs a
  warning rather than failing the pipeline.

## Policy-as-code engine

- Policies are evaluated deterministically and offline against the scan's
  stored assets and artefacts using package-rule heuristics
  (`app/services/policy_service.py`).
- **What is not covered**: The engine is not a general-purpose policy
  language — it understands the documented rule families (disallowed/lower
  bounded algorithms with path filters, internet-exposed PQC readiness,
  minimum agility score, maximum risk score), not arbitrary expressions.
  `deadline` handling uses the system date and only gates when
  `enforce_immediately` is `false`. Rule matching is keyword-based, so
  ambiguous algorithm names may match more or fewer artefacts than a human
  auditor would report. Findings (and therefore violations) inherit all
  scanner limitations above — a false negative in a scanner is a false
  negative in the gate.

## Harvest-now-decrypt-later (HNDL) lens

- The HNDL view (`app/services/hndl_service.py`, `ecdat hndl`,
  `GET /api/hndl`) is a **derived lens, not a new scanner** — it re-reads
  existing `Asset` + `BusinessAsset` rows and never executes or modifies
  scanned code.
- **What is not covered**:
  - "Captured in transit" is inferred from `BusinessAsset.internet_exposed`
    or small exact transport-crypto hints in the asset's component/location
    (TLS/SSL/SSH/DTLS/QUIC/HTTPS/STARTTLS). Live packet capture, protocol
    inspection, and runtime network state are never performed.
  - "Long shelf-life" uses the existing `data_retention_years` field as a
    proxy against a configurable threshold; ECDAT does not measure real
    data lifetimes.
  - Key-establishment / quantum-vulnerability determination inherits the
    knowledge base's static entries and the source scanner's pattern-match
    limits: an asset is only flagged if it *also* has business context
    (an internet-exposed link or a transport hint) and a long shelf-life.
    Assets with all three factors present but discovered through a
    low-confidence scanner finding are still flagged (exposure/shelf-life
    are not confidence-weighted).

## AI-authored / copy-pasted crypto provenance heuristic

- The `provenance_risk` flag on `CryptographicArtefact` (`app/crypto/provenance.py`)
  is a **deterministic regex-based heuristic, not an ML classifier**. It makes
  no claim about the true author of the code; it only flags a small set of
  precise tutorial-boilerplate patterns (e.g. hardcoded IV/salt/key literals,
  explicit ECB mode, textbook `plaintext`/`ciphertext` string bindings) that are
  strongly correlated with copy-pasted or unreviewed crypto code.
- **False positive risk**: Benign code that uses textbook variable names with
  literal values (for example in unit test fixtures, mock data, or documentation
  examples) will be flagged as `ai_suspected`.
- **False negative risk**: AI-generated code written idiomatically (e.g. fetching
  keys from environment variables or vaults, or using variable names not in the
  small literal pattern list) will **not** be flagged and will remain `unknown`.
  A status of `unknown` must **never** be taken as proof of human authorship or
  security.
- The `human_reviewed` status is strictly a manual triage state and is never
  set automatically.

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
