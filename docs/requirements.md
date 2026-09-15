# Requirements

## Functional requirements (MVP scope actually implemented)

- Scan a directory, a single file, or the bundled demo repository.
- Detect cryptographic usage in source code across Python, JavaScript,
  TypeScript, Java, C, C++, Go, Rust, YAML, JSON, TOML, INI, Dockerfile,
  and shell/config files via pattern-based static analysis.
- Detect crypto-related dependencies in requirements.txt, pyproject.toml,
  package.json, pom.xml, go.mod, Cargo.toml, and Dockerfile package
  installs.
- Parse X.509 certificates (.pem/.crt/.cer/.der) and flag weak keys,
  weak signature algorithms, and expiry status.
- Perform safe static inspection of ELF/PE binaries for linked
  crypto libraries/symbols (evidence-of-linkage only, not proof of use).
- Perform static Dockerfile/container-context inspection (no Docker
  daemon required, no image execution).
- Generate a CBOM (Cryptographic Bill of Materials) with JSON/CSV export.
- Compute a deterministic 0-100 quantum risk score per asset with
  itemized contributing factors.
- Compute Mosca's theorem analysis (X+Y vs Z) per asset, with
  interactively adjustable inputs.
- Recommend PQC replacements (ML-KEM, ML-DSA, SLH-DSA where
  appropriate) distinguishing key-establishment from signature use.
- Prioritize migration (CRITICAL/HIGH/MEDIUM/LOW) with rationale,
  blockers, and affected dependencies.
- Simulate a migration comparison without fabricating benchmark data.
- Generate JSON/CSV/PDF reports.
- Provide a dashboard with real, scan-derived numbers and charts.
- Provide a deterministic AI assistant that answers only from
  structured scan data, with optional LLM backing.
- Provide simple JWT-based authentication (admin/user roles).

## Non-functional requirements

- Runs fully offline; only the optional AI assistant may use a
  network call, and only if explicitly configured.
- No paid services required.
- Read-only scanning: never executes, modifies, or deletes scanned
  files; never extracts private key material.
- SQLite by default for zero-configuration local use; the schema is
  portable to PostgreSQL via `DATABASE_URL`.

## Explicitly out of scope for this MVP

- Full AST/data-flow analysis of source code (see docs/limitations.md).
- CVE lookup or vulnerability database integration (no CVEs are
  fabricated; none are looked up either, to avoid inventing data).
- Full RBAC (a simple admin/user model is implemented, structured so
  RBAC can be layered on later).
- Live Docker-daemon-based container scanning.
- CycloneDX-conformant CBOM output (a simplified, CycloneDX-inspired
  schema is used instead — see docs/cbom.md).
