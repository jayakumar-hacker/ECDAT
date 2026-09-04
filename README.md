# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

ECDAT scans repositories and infrastructure artifacts to answer:
*where is cryptography being used, which of it is vulnerable to future
quantum attacks, how serious is that, what should replace it, and what
should an organization migrate first?*

This is a **defensive security MVP**. It runs entirely offline, requires
no paid services, and never executes, modifies, or deletes anything it
scans.

## Features

- **Scanners**: source code (9+ languages), dependency manifests
  (7 formats), X.509 certificates, ELF/PE binaries (static), and
  Dockerfile/container build contexts — all read-only.
- **CBOM**: a Cryptographic Bill of Materials with JSON/CSV export
  (simplified schema inspired by CycloneDX — see `docs/cbom.md`).
- **Quantum Risk Engine**: deterministic 0–100 scoring with itemized
  factors (`docs/risk-model.md`).
- **Mosca Analysis**: interactive X+Y vs Z threat-horizon modeling
  (`docs/mosca.md`).
- **PQC Recommendations**: ML-KEM / ML-DSA / SLH-DSA / hybrid guidance,
  purpose-aware (key establishment vs signatures) (`docs/pqc-migration.md`).
- **Migration Simulator**: priority ranking + before/after comparison,
  with no fabricated benchmark numbers.
- **Reports**: JSON/CSV/PDF.
- **Dashboard**: real, scan-derived numbers and charts — nothing
  hard-coded.
- **AI Assistant**: works fully offline in deterministic mode by
  default; optional Ollama/OpenAI-compatible backend.
- **Diff-native CI mode + policy gate**: the `ecdat` CLI scans only what
  changed since a git ref and enforces repository-level
  `ecdat-policy.yaml` rules, with machine-readable JSON output and
  merge-gate exit codes — see `docs/diff-native-ci.md`.
- **Harvest-now-decrypt-later (HNDL) lens**: a read-only view flagging
  internet-exposed/captured-in-transit assets that combine quantum-
  vulnerable key establishment with long data shelf-life, exported as an
  additional section of the JSON/CSV reports (`ecdat hndl`,
  `GET /api/hndl`).
- **Demo repository**: 6 fictional systems (Payment API, Auth Service,
  HR Portal, Public Website, Legacy App, IoT Service) across
  Python/JS/Java/Go/C/Rust with intentionally varied crypto usage,
  plus 4 real generated X.509 certificates.

## Architecture

See `docs/architecture.md` for the full pipeline diagram and rationale.

```
Backend:  Python 3.11+, FastAPI, SQLAlchemy, SQLite (zero-config), pytest
Frontend: React, TypeScript, Vite, Tailwind CSS, Recharts, React Router
```

## Installation

### Prerequisites

- Python 3.11+
- Node.js 18+ (tested with Node 22)

### Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
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

## Running

### Backend

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload
```

Backend runs at `http://localhost:8000`. On first startup it
auto-seeds two demo users:

| Username | Password | Role |
|---|---|---|
| `admin` | `EcdatDemo123!` | admin |
| `analyst` | `EcdatDemo123!` | user |

Optionally also run:

```bash
python scripts/seed_demo.py
```

This seeds the six demo `BusinessAsset` rows (Payment API, Auth
Service, HR Portal, Public Website, Legacy App, IoT Service) with
differing criticality/sensitivity/exposure so the risk engine and
Mosca analysis produce varied, realistic results once you scan.

### Frontend

```bash
cd frontend
npm run dev
```

Frontend runs at `http://localhost:5173` and proxies `/api/*` to the
backend at `localhost:8000` (see `frontend/vite.config.ts`).

### Demo scan

1. Log in with `admin` / `EcdatDemo123!`.
2. Open the **Scan** page.
3. Leave the target as "Demo Repository" and click **Start Scan**.
4. Once it completes, explore **Inventory**, **CBOM Explorer**,
   **Quantum Risk**, **Mosca Analysis**, **PQC Recommendations**,
   **Migration Simulator**, **Certificates**, and **Dashboard**.

Or via the API directly:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"EcdatDemo123!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target":"demo","target_type":"demo","scanners":["source","dependency","certificate","binary","container"]}'
```

### CLI: diff-native CI mode + policy gate

The `ecdat` CLI runs scans and enforces policy-as-code rules without the
web UI. It is fully offline and read-only. See `docs/diff-native-ci.md`
for the complete rule reference and a copy-paste CI snippet.

```bash
# One-shot: scan only what changed since `main`, enforcing policy rules.
ecdat scan . --since main --policy ecdat-policy.yaml

# Same, but emit machine-readable JSON (ideal for CI parsing).
ecdat scan . --since main --policy ecdat-policy.yaml --json

# Report violations on an existing scan without closing the gate.
ecdat check-policy . --policy ecdat-policy.yaml

# Scan all files and never fail on policy violations (report only).
ecdat scan . --no-fail-on-violation
```

Exit codes: `0` = pass, `1` = policy violations found, `2` = no policy file
or no scan found.

## API documentation

Interactive OpenAPI docs are available at `http://localhost:8000/docs`
once the backend is running. Key endpoints:

```
POST   /api/scans                 GET /api/scans                 GET /api/scans/{id}
POST   /api/scans/{id}/start      GET /api/scans/{id}/results

GET    /api/assets                GET /api/assets/{id}
GET    /api/cbom                  GET /api/cbom/export
GET    /api/risks                 GET /api/risks/summary
GET    /api/mosca                 POST /api/mosca/simulate
GET    /api/recommendations
GET    /api/migration-plans       POST /api/migration-plans/simulate
GET    /api/certificates          GET /api/libraries        GET /api/containers
GET    /api/dashboard
GET    /api/reports               POST /api/reports          GET /api/reports/download/{filename}
POST   /api/ai/chat
GET    /health
```

## Testing

```bash
# Backend (98 tests: scanners, risk/Mosca math, recommendations,
# migration, CBOM, auth API, scan API, CLI, policy gate)
cd backend && source .venv/bin/activate && python -m pytest tests/ -v

# Frontend (component tests)
cd frontend && npm test

# Frontend production build (also runs the TypeScript compiler)
cd frontend && npm run build
```

## Docker usage (optional, one command)

Docker is **not required** — see "Running" above for the plain
`uvicorn` + `npm run dev` path. If you have Docker installed:

```bash
docker compose up --build
```

That's it. This single command builds and starts both services:

- Backend on `http://localhost:8000` (users and demo business context
  are seeded automatically on startup — no separate seed step needed).
- Frontend on **`http://localhost:3000`** (served via nginx, which
  reverse-proxies `/api/*` server-side to the backend container, so
  there's no CORS configuration to worry about).

Open `http://localhost:3000`, log in with `admin` / `EcdatDemo123!`,
and run the demo scan from the Scan page exactly as described above.

The SQLite database persists across restarts in a named Docker volume
(`ecdat_data`, mounted at `/data` in the backend container). To reset
all data:

```bash
docker compose down -v
```

To stop without deleting data:

```bash
docker compose down
```

Note on how this is wired (in case you're extending it): the backend
image is built from the **repo root** (not `backend/`) because the app
resolves `knowledge-base/` and `demo-data/` as siblings of `backend/`
at runtime — see `backend/Dockerfile` for the exact layout. The
frontend image is a multi-stage build that compiles the React app and
serves the static output via nginx (`frontend/Dockerfile`,
`frontend/nginx.conf`).

## Security limitations

ECDAT is a static-analysis MVP. See `docs/limitations.md` for the
full, honest list — in short: source scanning is pattern-based (not
full AST/data-flow), binary/container findings indicate linkage/
reference (not confirmed runtime use), no CVE data is looked up or
fabricated, and the risk score is ECDAT's own model, not an official
NIST/CVSS score.

## Research references

See `docs/references.md` for the NIST FIPS 203/204/205, NIST IR 8547,
CycloneDX CBOM, ETSI, and IETF hybrid-TLS sources this project's
design choices are based on.

## Screenshots

Not included in this MVP deliverable — run the frontend locally and
use the Scan page to generate live data across all pages instead.

## License

MIT — see `LICENSE`.
