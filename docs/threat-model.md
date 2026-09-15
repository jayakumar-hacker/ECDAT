# Threat Model

## Assets ECDAT itself must protect

- Scanned source code and file contents (may be proprietary).
- Certificate metadata (public, but subject/SAN data may be sensitive).
- Never: private key material — ECDAT actively refuses to parse files
  that look like private keys (see `app/scanners/certificate/scanner.py`).
- User credentials (bcrypt-hashed, never logged in plaintext).
- Scan results stored in the local SQLite database.

## Threats considered

| Threat | Mitigation |
|---|---|
| Path traversal via a malicious scan target | Targets are resolved with `os.path.abspath`; the demo target is a fixed server-side path, not user-controlled. |
| Arbitrary code execution via a scanned file | Scanners only ever open files for reading (`open(..., "r")` / `"rb"`); nothing scanned is ever executed, imported, or shelled out to. |
| Arbitrary code execution via a scanned binary | The binary scanner performs static byte/string inspection only; it never executes, loads, or disassembles-and-runs the binary. |
| Container image execution | The container scanner never invokes the Docker daemon and never pulls/builds/runs an image; it parses Dockerfiles as text. |
| Private key exposure | The certificate scanner detects PEM private-key markers and refuses to parse those files, returning a `parse_error` instead of any key content. |
| Oversized file / resource exhaustion (DoS) | `MAX_FILE_SIZE_BYTES` and `MAX_FILES_PER_SCAN` in `app/core/config.py` bound per-file and per-scan work; binaries are additionally capped in the reader. |
| Credential theft via weak password storage | Passwords are hashed with bcrypt via passlib; the JWT secret key should be overridden in production via `SECRET_KEY`. |
| Unauthorized API access | All non-health endpoints require a valid JWT bearer token, validated on every request. |
| Source code leaking to an external AI provider | The AI assistant runs in a fully offline deterministic mode by default (`AI_ENABLED=false`); an operator must explicitly opt in and configure a provider, and even then only structured summaries — never raw source — are sent as context. |
| SQL injection | All queries go through SQLAlchemy's ORM/parameterized query builder; no raw string-interpolated SQL is used. |
| Malformed input crashing a scan | Each scanner catches its own exceptions and records them as `ScanEvidence`; one scanner failing does not abort the whole scan (see `app/services/scan_service.py`). |

## Explicit non-goals

- ECDAT is not a runtime/dynamic analysis tool — it cannot prove that
  detected code paths execute in production, only that the pattern is
  present in the source.
- ECDAT is not a general-purpose vulnerability scanner or SAST tool;
  its scope is cryptographic discovery and quantum-risk analysis only.
- ECDAT's own authentication is an MVP-grade admin/user model, not a
  hardened multi-tenant identity system — see docs/limitations.md.
