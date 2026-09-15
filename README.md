# CRYPTORA — Cryptographic Risk & Quantum Readiness Analyzer

CRYPTORA is an implementation of the **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)** problem statement.
It answers: *where is cryptography being used, which of it is vulnerable to future quantum attacks, how serious is that, what should replace it, and what should an organization migrate first?*

CRYPTORA is a **defensive security MVP**. It runs entirely offline, requires no paid services, and never executes, modifies, or deletes anything it scans.

---

## Problem Being Solved

As cryptographically relevant quantum computers (CRQCs) approach practical viability, organizations need to:

1. **Inventory** every cryptographic asset across source code, dependencies, certificates, binaries, and infrastructure.
2. **Assess** which assets are quantum-vulnerable and how urgently they need to be replaced.
3. **Prioritize** migration using formal models (Mosca's inequality) and business context.
4. **Recommend** standards-compliant post-quantum replacements (NIST FIPS 203 / 204 / 205).
5. **Enforce** cryptographic governance policies in CI/CD pipelines.

---

## Current Capabilities (Implemented MVP)

### Cryptographic Discovery (6 Scanner Types)

| Scanner | What It Does | Detection Method |
|---|---|---|
| **Source Code** | Scans 9+ languages for cryptographic API calls, algorithm names, and library imports | Regex/keyword static analysis — **not** AST or data-flow |
| **Dependency** | Parses 6 manifest formats + 6 lockfile formats; flags crypto-capable packages | Offline knowledge-base lookup |
| **X.509 Certificate** | Parses `.pem`/`.crt`/`.cer`/`.der` files for algorithm, key size, expiry, SANs, weak keys/sigs | `cryptography` library X.509 parser |
| **Binary** | Scans ELF/PE binaries for crypto library names and symbol strings | Static string extraction (no execution) |
| **Container** | Analyses Dockerfile base images and installed crypto packages | Static Dockerfile parsing |
| **Config & Protocol** | Parses `sshd_config`, nginx/Apache SSL, `openssl.cnf`, `java.security`, Terraform, K8s TLS Secrets / cert-manager CRDs | Format-specific regex parsers |

All scanners are **read-only**. Nothing is executed, installed, or mutated.

**Supported source languages (static analysis):** Python, JavaScript/TypeScript, Java, Go, Rust, C, C++, Ruby, Dockerfile

**Supported dependency manifests:** `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml`, `go.mod`, `Cargo.toml`

**Supported lockfiles (transitive dependency graph):** `poetry.lock`, `package-lock.json`, `Cargo.lock`, `go.sum`, `pnpm-lock.yaml`, `Gemfile.lock`

---

### Quantum Risk Engine

- Deterministic **0–100 risk score** per cryptographic asset (CRYPTORA scoring model — not NIST/CVSS).
- Additive scoring factors:

| Factor | Impact | Notes |
|---|---|---|
| Quantum vulnerability | +30 / +2 | +30 if vulnerable to Shor's/Grover's; +2 if not |
| Key size (RSA) | +15 | RSA < 2048 bits |
| Cryptographic purpose | +10 / +3 | +10 for key_establishment/digital_signature; +3 for encryption |
| Business criticality | +5 to +20 | LOW/MEDIUM/HIGH/CRITICAL from linked BusinessAsset |
| Data sensitivity | 0 to +18 | PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED |
| Internet exposure | +12 | If BusinessAsset.internet_exposed = true |
| Detection confidence | informational (0) | Low-confidence findings flagged for review only |

- Every score itemizes all factors in `RiskAssessment.factors` — fully explainable, not a black box.
- Severity bands: **0–24 LOW · 25–49 MEDIUM · 50–74 HIGH · 75–100 CRITICAL**
- Thresholds are configurable via `RISK_LOW_MAX` / `RISK_MEDIUM_MAX` / `RISK_HIGH_MAX`.

### Crypto-Agility Scoring

- 0–100 **agility score** based on three dimensions:
  1. **Abstraction mechanism** — config-driven (50 pts) > provider/interface abstraction (35 pts) > certificate-managed (30 pts) > binary/container linkage (20 pts) > compile-time constant (15 pts)
  2. **Version pinning** — strictly pinned (25 pts) > range-pinned (15 pts) > floating/unpinned (5 pts)
  3. **Call-site blast radius** — 1 site (25 pts) > 2–4 sites (18 pts) > 5–10 sites (10 pts) > >10 sites (3 pts)
- Derived **migration priority** = `risk_score / max(1, agility_score)` — surfaces high-risk, hard-to-migrate assets first.

### Mosca Analysis

Implements Michele Mosca's inequality for migration urgency:

```
X = required data/security lifetime (years)
Y = estimated migration time (years)
Z = threat horizon — assumed time to a CRQC (default: 10 years, configurable)

If X + Y > Z → migration should be prioritized now.
```

| Condition | Result |
|---|---|
| Algorithm not quantum-vulnerable | LOW PRIORITY |
| X+Y > Z by more than 3 years | URGENT MIGRATION |
| X+Y > Z by 3 years or less | PLAN MIGRATION |
| X+Y ≤ Z | MONITOR |

> **Important:** CRYPTORA does not predict when a quantum computer will exist. The threat horizon Z is a configurable assumption, not a forecast.

### PQC Recommendations

Purpose-aware recommendations from the offline knowledge base:

| Use Case | Recommended Algorithm | Notes |
|---|---|---|
| Key establishment (RSA/DH/ECDH) | **ML-KEM** (FIPS 203) | Primary NIST standard for key encapsulation |
| Digital signatures (RSA/DSA/ECDSA/Ed25519) | **ML-DSA** (FIPS 204) | Primary NIST standard for signatures |
| Long-lived / high-assurance signatures | **SLH-DSA** (FIPS 205) | Stateless hash-based; conservative alternative |
| Transition period (key establishment) | **X25519 + ML-KEM** hybrid | Retains classical security if PQC is broken |
| Transition period (signatures) | **ECDSA + ML-DSA** composite | Risk-mitigating interim approach |
| Symmetric (AES-256, AES-256-GCM, ChaCha20-Poly1305) | **No PQC swap needed** | Grover's speedup handled by 256-bit key margin |

> Symmetric algorithms such as AES-256 and ChaCha20-Poly1305 are **not** flagged for algorithm replacement. Key size (not algorithm type) is the mitigation lever for Grover's algorithm.

### CBOM (Cryptographic Bill of Materials)

- Exported as JSON or CSV from `GET /api/cbom/export`.
- Schema is **inspired by CycloneDX CBOM concepts** but is a simplified CRYPTORA-specific schema. It is **not** a conformant CycloneDX document. This is stated explicitly in the response:
  - `"bomFormat": "ECDAT-CBOM"`
  - `"specVersion": "0.1-mvp"`
  - `"note": "Simplified schema inspired by CycloneDX CBOM concepts; not a conformant CycloneDX document."`
- Every component traces back to a real scanner finding — nothing is fabricated.

### Reports

Three export formats generated via `POST /api/reports`:

| Format | Contents |
|---|---|
| **JSON** | Executive summary, full cryptographic inventory, critical findings, quantum risk breakdown, PQC recommendations, migration priorities, HNDL lens, certificates, libraries, limitations disclaimer |
| **CSV** | CBOM component table + HNDL exposure section |
| **PDF** | Executive summary, quantum risk table, critical findings list, PQC recommendations, limitations (via ReportLab) |

Reports are saved to `backend/reports_output/` and downloadable via `GET /api/reports/download/{filename}`.

### Harvest-Now-Decrypt-Later (HNDL) Lens

An asset is flagged `hndl_exposed` when **all three** conditions hold simultaneously:

1. **Internet-exposed or captured-in-transit** — via `BusinessAsset.internet_exposed` or transport-crypto hints (TLS/SSL/SSH/DTLS/QUIC/HTTPS/STARTTLS in asset component/location).
2. **Long data shelf-life** — `BusinessAsset.data_retention_years` ≥ threshold (default 10 years, configurable via `HNDL_SHELF_LIFE_THRESHOLD_YEARS`).
3. **Quantum-vulnerable key establishment** — algorithm classified as quantum-vulnerable key exchange in the offline knowledge base.

Exposed via `GET /api/hndl` and `ecdat hndl` CLI; exported as an additional section in JSON/CSV reports (never a replacement for CBOM rows).

### Diff-Native CI Mode + Policy-as-Code Gate

- **`ecdat scan . --since <git-ref>`** — scans only files modified since a git ref (using `git diff --name-only`), ideal for PR merge gates.
- **`ecdat-policy.yaml`** — repository-level policy rules evaluated at scan time:
  - Disallowed algorithms with optional key-size thresholds and path exclusions
  - Internet-exposed PQC readiness requirement with optional deadline
  - Minimum crypto-agility score threshold
  - Maximum risk score ceiling
  - Provenance-risk sign-off requirement (`ai_suspected`)
- **Exit codes:** 0 (pass) · 1 (policy violations) · 2 (no policy/scan found)
- Machine-readable `--json` output for CI parsing.

### Provenance-Risk Heuristic

The source scanner annotates artefacts with `provenance_risk`:
- `unknown` — default (no boilerplate detected); **not proof of human review**
- `ai_suspected` — deterministic regex match of tutorial boilerplate patterns (hardcoded IV/salt/nonce/key literals, explicit ECB mode, `plaintext`/`ciphertext` bound to string literals)
- `human_reviewed` — manual state, **never set automatically**

> This is **not ML detection** — it is a small, precise, regex-based heuristic. False positives (e.g. unit-test fixtures) are expected and documented.

### Crypto-Posture Drift Tracking

`GET /api/dashboard/drift` and `ecdat drift` CLI track chronological trends across historical scans for the same target:
- Vulnerable-artefact count over time
- PQC adoption percentage
- Average migration priority
- Delta summary (improved / regressed)

### Migration Simulator

`POST /api/migration-plans/simulate` — offline, read-only remediation drafts:
- Maps `(language, current_library, algorithm, purpose)` tuples to concrete replacement guidance from `app/crypto/remediation.py`.
- Includes target library, minimum version, replacement API, hybrid construction, and diff template suggestions.
- **Never applies changes to source code** — all drafts are strictly read-only suggestions for manual review.
- Never fabricates benchmark numbers; latency/overhead fields default to `"Not measured"` unless the caller supplies values.

### AI Assistant (Optional)

- **Default (offline deterministic mode):** keyword-routed query engine that answers directly from scan data — no network access, no LLM required.
- **Optional LLM mode:** Ollama or any OpenAI-compatible API. Only structured context (not raw source code) is sent externally, unless `AI_ALLOW_EXTERNAL_CONTEXT=true`.
- LLM mode falls back to deterministic mode automatically if the backend is unavailable.

### Dashboard

All dashboard numbers are derived from actual scan data — nothing is hard-coded. Metrics:
- Total cryptographic assets, quantum-vulnerable count, CRITICAL/HIGH risk counts
- Risk distribution (LOW/MEDIUM/HIGH/CRITICAL)
- Algorithm distribution, asset type distribution
- Migration priority distribution
- Certificate expiry buckets (expired / expiring ≤30d / expiring ≤90d / healthy / unknown)
- Crypto library count, business assets scanned, scans run
- Posture drift summary

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Backend language | Python | 3.11+ |
| Backend framework | FastAPI | 0.115.0 |
| ASGI server | Uvicorn | 0.30.6 |
| ORM | SQLAlchemy | 2.0.35 |
| Database | SQLite | Default, zero-config |
| Data validation | Pydantic v2 | 2.9.2 |
| Authentication | JWT (python-jose) + bcrypt (passlib) | HS256 |
| Crypto library (X.509) | cryptography | 43.0.1 |
| PDF generation | ReportLab | 4.2.5 |
| Frontend language | TypeScript | 5.x |
| Frontend framework | React | 18.x |
| Build tool | Vite | 8.x |
| Styling | Tailwind CSS | 3.x |
| Charts | Recharts | 2.x |
| HTTP client | Axios | 1.x |
| Routing | React Router | 7.x |
| Backend tests | pytest + httpx | 8.x |
| Frontend tests | Vitest + Testing Library | — |
| Containerization | Docker + docker-compose | Optional |
| Frontend server (Docker) | nginx | Serves static build; reverse-proxies `/api/*` |

---

## Architecture Overview

```
Browser (React / TypeScript)
       │
       │  HTTP / REST  (JWT Bearer token)
       ▼
FastAPI Application  (app/main.py)
       │
       ├── API Layer (app/api/)
       │       auth, scans, assets, cbom, risks, mosca,
       │       recommendations, migration, certificates,
       │       libraries, reports, ai, dashboard, hndl
       │
       ├── Services Layer (app/services/)
       │       scan_service.py           Scan orchestrator
       │       risk_service.py           Risk scoring + Mosca + crypto-agility
       │       recommendation_service.py PQC recommendation engine
       │       migration_service.py      Migration plans + simulator
       │       cbom_service.py           CBOM generation
       │       report_service.py         JSON/CSV/PDF reports
       │       hndl_service.py           HNDL exposure lens
       │       policy_service.py         Policy-as-code evaluation
       │       drift_service.py          Posture drift analytics
       │
       ├── Scanners (app/scanners/)
       │       source/     Source code (9+ langs, regex/keyword)
       │       dependency/  Manifests + lockfiles (offline KB lookup)
       │       certificate/ X.509 PEM/DER parsing
       │       binary/      ELF/PE static string analysis
       │       container/   Dockerfile static parsing
       │       config/      SSH/nginx/OpenSSL/Terraform/K8s configs
       │
       ├── Crypto Intelligence (app/crypto/)
       │       knowledge_base.py   Algorithm lookup
       │       classifier.py       Line-level classification
       │       algorithms.py       Pattern definitions + language extensions
       │       provenance.py       AI-boilerplate heuristic
       │       remediation.py      Offline remediation knowledge table
       │
       ├── Models (app/models/models.py)   All SQLAlchemy tables
       ├── Core (app/core/)                Config, DB session, JWT, audit log
       ├── AI Assistant (app/ai/)          Deterministic + optional LLM
       └── CLI (app/cli.py)                ecdat scan/check-policy/hndl/drift
              │
              └── SQLite database (ecdat.db)
```

Full details: [`docs/architecture.md`](docs/architecture.md)

---

## Project Structure

```
ECDAT/                              Repository root
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app entry point
│   │   ├── cli.py                  ecdat CLI (scan/check-policy/hndl/drift)
│   │   ├── api/                    One router module per resource (17 files)
│   │   ├── core/                   Config, database, JWT security, audit logging
│   │   ├── models/models.py        All SQLAlchemy ORM models
│   │   ├── scanners/               source / dependency / certificate / binary / container / config
│   │   ├── crypto/                 Knowledge base, classifier, algorithms, provenance, remediation
│   │   ├── services/               Scan, risk, CBOM, recommendation, migration, report, HNDL, policy, drift
│   │   ├── ai/                     AI assistant (deterministic + optional LLM)
│   │   ├── evaluation/             Demo ground-truth scoring harness
│   │   └── schemas/                Pydantic request/response schemas
│   ├── tests/                      pytest test suite
│   ├── reports_output/             Generated report files
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/                  20 page components
│   │   ├── components/             Shared components (ProtectedRoute, etc.)
│   │   ├── layouts/                AppLayout (sidebar/header)
│   │   ├── services/               Axios API client
│   │   ├── hooks/                  Custom React hooks
│   │   └── types/                  TypeScript type definitions
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── nginx.conf                  nginx config for Docker build
│   └── Dockerfile
├── knowledge-base/
│   ├── algorithms/                 algorithms.json
│   └── libraries/                  crypto_libraries.json
├── demo-data/
│   └── repositories/acme-corp/     6 fictional systems + 4 real X.509 certs
├── docs/                           Architecture, CBOM, limitations, Mosca, PQC, risk model, CI, references
├── scripts/                        setup.sh, seed_demo.py, evaluate_demo.py
├── docker-compose.yml
├── Makefile
└── LICENSE
```

---

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+ (tested with Node 22)

### Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

### Frontend setup

```bash
cd frontend
npm install
```

### One-command setup (both)

```bash
bash scripts/setup.sh
```

---

## Configuration

All backend settings are in [`app/core/config.py`](backend/app/core/config.py) and can be overridden with environment variables or a `.env` file in `backend/`.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./ecdat.db` | SQLAlchemy database URL |
| `SECRET_KEY` | dev default | JWT signing key — **change in production** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | JWT token lifetime |
| `MAX_FILE_SIZE_BYTES` | `5242880` (5 MB) | Per-file scan size limit |
| `MAX_FILES_PER_SCAN` | `20000` | Total file limit per scan |
| `DEFAULT_THREAT_HORIZON_YEARS` | `10` | Default Mosca Z value |
| `HNDL_SHELF_LIFE_THRESHOLD_YEARS` | `10` | Min shelf life to flag HNDL exposure |
| `RISK_LOW_MAX` | `24` | Max score for LOW severity |
| `RISK_MEDIUM_MAX` | `49` | Max score for MEDIUM severity |
| `RISK_HIGH_MAX` | `74` | Max score for HIGH severity (75–100 = CRITICAL) |
| `AI_ENABLED` | `false` | Enable LLM-backed assistant |
| `AI_PROVIDER` | `none` | `none` / `ollama` / `openai_compatible` |
| `AI_API_BASE` | `` | LLM API base URL |
| `AI_MODEL` | `` | LLM model name |
| `FRONTEND_ORIGINS` | `["http://localhost:5173"]` | CORS allowed origins |
| `REPORTS_DIR` | `./reports_output` | Report output directory |

---

## Running Locally

### Backend

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload
```

Backend runs at `http://localhost:8000`. On first startup it auto-seeds two demo users and the algorithm knowledge base:

| Username | Password | Role |
|---|---|---|
| `admin` | `EcdatDemo123!` | admin |
| `analyst` | `EcdatDemo123!` | user |

Optionally seed demo business assets (Payment API, Auth Service, HR Portal, etc.):

```bash
python scripts/seed_demo.py
```

### Frontend

```bash
cd frontend
npm run dev
```

Frontend runs at `http://localhost:5173` and proxies `/api/*` to the backend.

Interactive OpenAPI docs: `http://localhost:8000/docs`

---

## Demo Workflow

1. Log in with `admin` / `EcdatDemo123!`.
2. Open **Scan**, set target to `demo` (or leave as "Demo Repository"), click **Start Scan**.
3. Once complete, explore:
   - **Inventory** — all discovered cryptographic assets
   - **CBOM Explorer** — Cryptographic Bill of Materials
   - **Quantum Risk** — risk scores and severity distribution
   - **Mosca Analysis** — X+Y vs Z threat horizon per asset
   - **PQC Recommendations** — algorithm-specific migration guidance
   - **Migration Simulator** — priority ranking and remediation drafts
   - **Certificates** — X.509 certificate details and expiry
   - **Libraries** — crypto-capable dependency libraries
   - **HNDL Exposure** — harvest-now-decrypt-later lens
   - **Posture Drift** — trends across scans
   - **Reports** — JSON/CSV/PDF export
   - **AI Assistant** — structured query interface (deterministic offline mode by default)
   - **Dashboard** — summary metrics and charts

Or via the API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"EcdatDemo123!"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"demo","target_type":"demo","scanners":["source","dependency","certificate","binary","container","config"]}'
```

---

## CLI Reference

```bash
# Scan a directory (all scanners)
ecdat scan /path/to/repo

# Diff-native CI mode: scan only files changed since `main`
ecdat scan . --since main --policy ecdat-policy.yaml

# Machine-readable JSON output
ecdat scan . --since main --policy ecdat-policy.yaml --json

# Re-check policy on an existing scan without re-scanning
ecdat check-policy . --policy ecdat-policy.yaml

# Report-only mode (no exit-code gate)
ecdat scan . --no-fail-on-violation

# Harvest-now-decrypt-later exposure lens
ecdat hndl .

# Posture drift trend dashboard
ecdat drift .
```

Exit codes: `0` = pass · `1` = policy violations found · `2` = no policy file or scan found

See [`docs/diff-native-ci.md`](docs/diff-native-ci.md) for the full policy rule reference and GitHub Actions copy-paste snippet.

---

## API Overview

Full interactive docs: `http://localhost:8000/docs`. All endpoints except `/health` and `POST /api/auth/login` require `Authorization: Bearer <token>`.

```
POST   /api/auth/login                  POST  /api/auth/logout

POST   /api/scans                       GET   /api/scans
GET    /api/scans/{id}                  POST  /api/scans/{id}/start
GET    /api/scans/{id}/results

GET    /api/assets                      GET   /api/assets/{id}
GET    /api/cbom                        GET   /api/cbom/export
GET    /api/risks                       GET   /api/risks/summary
GET    /api/mosca                       POST  /api/mosca/simulate
GET    /api/recommendations
GET    /api/migration-plans             GET   /api/migration-plans/priority-view
POST   /api/migration-plans/simulate
GET    /api/certificates
GET    /api/libraries
GET    /api/dashboard                   GET   /api/dashboard/drift
GET    /api/hndl
GET    /api/reports                     POST  /api/reports
GET    /api/reports/download/{filename}
POST   /api/ai/chat
GET    /health
```

---

## Docker (Optional)

Docker is **not required**. If you have Docker installed:

```bash
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: **`http://localhost:3000`** (nginx serves the React build and reverse-proxies `/api/*` to the backend)

Log in with `admin` / `EcdatDemo123!` — users and demo business context are seeded automatically.

The SQLite database persists across restarts in a named Docker volume (`ecdat_data`). To reset all data:

```bash
docker compose down -v
```

> **Note:** The backend Docker image is built from the repo root (not `backend/`) because the app resolves `knowledge-base/` and `demo-data/` as sibling directories at runtime.

---

## Testing

```bash
# Backend tests
cd backend && source .venv/bin/activate && python -m pytest tests/ -v

# Frontend component tests
cd frontend && npm test

# Frontend production build (also runs TypeScript compiler)
cd frontend && npm run build

# Demo ground-truth evaluation
python scripts/evaluate_demo.py
```

**Demo self-evaluation results** (on bundled Acme Corp demo repository):

| Scanner | Precision | Recall | F1 |
|---|---|---|---|
| source | 91.7% | 100.0% | 0.957 |
| dependency | 46.4% | 100.0% | 0.634 |
| certificate | 100.0% | 100.0% | 1.000 |
| container | 60.0% | 100.0% | 0.750 |
| **OVERALL** | **70.0%** | **100.0%** | **0.824** |

Recall is 100% on the demo set (zero false negatives). Lower dependency/container precision reflects the design: the knowledge base surfaces all known algorithms a package provides, while ground truth only annotates algorithms exercised by application code.

---

## Current Limitations

- **Static analysis only.** Source scanning is regex/keyword-based — not full AST or data-flow analysis.
- **Binary/container findings indicate linkage, not confirmed runtime use.** Every finding's `note` field states this explicitly.
- **Certificate scanning does not validate chains.** Only the leaf certificate is analyzed.
- **No CVE/CVSS data.** CRYPTORA never fabricates CVE numbers or CVSS scores.
- **Risk score is CRYPTORA's own model**, not an official NIST or CVSS score.
- **Threat horizon Z is a configurable assumption**, not a prediction.
- **Provenance-risk heuristic is not ML.** A small set of deterministic regex rules.
- **No distributed/async scanning.** Bounded by `MAX_FILES_PER_SCAN`.
- **Authentication is MVP-grade.** No MFA, no rate limiting, no session revocation.
- **Policy engine understands documented rule families only**, not arbitrary expressions.

See [`docs/limitations.md`](docs/limitations.md) for the complete, detailed limitations list.

---

## Future Scope

The following are **not implemented** in the current MVP:

- Full AST/data-flow analysis for source code
- Runtime/network traffic analysis and live TLS handshake inspection
- Deeper binary analysis (disassembly, decompilation)
- Container runtime scanning (requires Docker daemon)
- Private/internal registry support in dependency scanning
- CVE/CVSS integration with vulnerability databases
- Certificate chain validation and OCSP/CRL checking
- Full CycloneDX-conformant CBOM output
- Automated migration plan execution
- HSM integration and hardware cryptographic asset discovery
- Cloud cryptographic asset discovery (AWS KMS, Azure Key Vault, GCP KMS)
- Multi-tenant, enterprise-scale distributed scanning
- Password complexity enforcement and MFA

---

## Security Considerations

- **Change `SECRET_KEY` in production.**
- **Authentication:** JWT (HS256) + bcrypt-hashed passwords. Logout is client-side (stateless JWT).
- **No execution of scanned code.** All scanners are read-only.
- **Certificate scanner** explicitly refuses to parse files containing private key markers.
- **File handling:** Respects `MAX_FILE_SIZE_BYTES` and `MAX_FILES_PER_SCAN` limits.
- **Report download:** Filenames sanitized with `os.path.basename`.
- **AI external context:** Source code is never sent to an external LLM unless `AI_ALLOW_EXTERNAL_CONTEXT=true`.
- **Subprocess execution:** Only `git diff --name-only` / `git ls-files` (diff-native mode). No user input is interpolated into shell commands.
- **Not hardened for production.** No MFA, no rate limiting. Suitable for internal/demo use.

---

## Research References

Design choices are based on:

- **NIST FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), **FIPS 205** (SLH-DSA)
- **NIST IR 8547** — Transition to Post-Quantum Cryptographic Standards
- **CycloneDX CBOM** — Bill of Materials for cryptographic assets
- **ETSI TR 103 619** — Quantum-safe considerations
- **IETF hybrid-TLS** drafts
- **Michele Mosca** — Quantum risk prioritization inequality

See [`docs/references.md`](docs/references.md) for full citations.

---

## License

MIT — see [`LICENSE`](LICENSE).
