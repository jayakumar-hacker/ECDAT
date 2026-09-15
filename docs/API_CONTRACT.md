# CRYPTORA API Contract

CRYPTORA exposes a RESTful JSON API via FastAPI. Interactive OpenAPI documentation is available at `http://localhost:8000/docs` when the backend is running.

## Authentication

All endpoints except `/health` and `POST /api/auth/login` require:

```
Authorization: Bearer <jwt_token>
```

JWT tokens are HS256-signed. Token lifetime defaults to 480 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`). Logout is stateless — the client discards the token.

---

## Authentication Endpoints

### POST /api/auth/login

Issue a JWT access token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "EcdatDemo123!"
}
```

**Response (200):**
```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "role": "admin"
}
```

**Errors:** `401` — Invalid username or password.

---

### POST /api/auth/logout

Stateless logout — always returns 200. Client must discard the token.

**Response (200):**
```json
{
  "detail": "Logged out. Discard the client-side token."
}
```

---

## Scan Endpoints

### POST /api/scans

Create and start a scan as an async background task.

**Auth:** Required.

**Request Body:**
```json
{
  "target": "/path/to/repo",
  "target_type": "directory",
  "scanners": ["source", "dependency", "certificate", "binary", "container", "config"],
  "since": "main",
  "policy_path": "/path/to/ecdat-policy.yaml"
}
```

- `target` — absolute path on the server, or `"demo"` for the bundled demo repository.
- `target_type` — `"directory"`, `"file"`, or `"demo"`.
- `scanners` — optional list subset of `["source","dependency","certificate","binary","container","config"]`. Defaults to all six if omitted.
- `since` — optional git ref for diff-native scanning (e.g. `"main"`, `"HEAD~1"`).
- `policy_path` — optional explicit path to an `ecdat-policy.yaml` file.

**Response (200):** Serialized `Scan` object. Status will be `"pending"` — scan runs in background.

**Errors:** `400` — Target path does not exist.

---

### GET /api/scans

List all scans, ordered by `created_at` descending.

**Auth:** Required.

**Response (200):** Array of serialized `Scan` objects.

---

### GET /api/scans/{scan_id}

Get a single scan by ID.

**Auth:** Required.

**Response (200):** Serialized `Scan` object.

**Errors:** `404` — Scan not found.

---

### POST /api/scans/{scan_id}/start

Start (or restart) an existing scan.

**Auth:** Required.

**Response (200):**
```json
{"detail": "Scan started", "scan_id": "<id>"}
```

**Errors:** `404` — Scan not found. `409` — Scan already running.

---

### GET /api/scans/{scan_id}/results

Get a scan's results including all assets and scan evidence.

**Auth:** Required.

**Response (200):**
```json
{
  "scan": { ... },
  "assets": [ ... ],
  "evidence": [
    {"scanner": "source", "level": "warning", "message": "...", "file": "..."}
  ]
}
```

**Errors:** `404` — Scan not found.

---

## Asset Endpoints

### GET /api/assets

List cryptographic assets. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional) — filter to a specific scan.

**Response (200):** Array of serialized `Asset` objects, each including risk assessment, Mosca assessment, recommendation, and agility data.

---

### GET /api/assets/{asset_id}

Get a single asset by ID.

**Auth:** Required.

**Response (200):** Serialized `Asset` object with all related assessment data.

**Errors:** `404` — Asset not found.

---

## CBOM Endpoints

### GET /api/cbom

Get the Cryptographic Bill of Materials as a JSON object.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional) — filter to a specific scan.

**Response (200):**
```json
{
  "bomFormat": "ECDAT-CBOM",
  "specVersion": "0.1-mvp",
  "note": "Simplified schema inspired by CycloneDX CBOM concepts; not a conformant CycloneDX document.",
  "componentCount": 12,
  "components": [
    {
      "id": "<uuid>",
      "type": "crypto_usage",
      "algorithm": "RSA-2048",
      "key_size": 2048,
      "purpose": "key_establishment",
      "location": "src/auth.py:12",
      "component": "cryptography",
      "confidence": 0.9,
      "business_asset": "Payment API",
      "classical_security": "See knowledge base",
      "quantum_security": "HIGH",
      "risk_score": 62
    }
  ]
}
```

---

### GET /api/cbom/export

Export the CBOM as a downloadable file.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional) — filter to a specific scan.
- `format` — `"json"` (default) or `"csv"`.

**Response (200):** File download (Content-Disposition: attachment).

---

## Risk Endpoints

### GET /api/risks

List risk assessments. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):** Array of serialized `RiskAssessment` objects.

---

### GET /api/risks/summary

Risk count by severity for a scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):**
```json
{
  "LOW": 5, "MEDIUM": 8, "HIGH": 3, "CRITICAL": 1
}
```

---

## Mosca Endpoints

### GET /api/mosca

List Mosca assessments. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):** Array of Mosca assessment objects, each including `asset_name`, `algorithm`, `x_data_lifetime_years`, `y_migration_time_years`, `z_threat_horizon_years`, `x_plus_y`, `exceeds_horizon`, `result`.

---

### POST /api/mosca/simulate

Re-run Mosca analysis for a specific asset with overridden X, Y, Z values.

**Auth:** Required.

**Request Body:**
```json
{
  "asset_id": "<uuid>",
  "x_data_lifetime_years": 7.0,
  "y_migration_time_years": 2.5,
  "z_threat_horizon_years": 8.0
}
```

**Response (200):** Updated `MoscaAssessment` object.

**Errors:** `404` — Asset not found.

---

## Recommendation Endpoints

### GET /api/recommendations

List PQC recommendations. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):** Array of serialized `Recommendation` objects, each including `current_algorithm`, `recommended_algorithm`, `recommended_type`, `hybrid_option`, `reason`, `compatibility`, `migration_complexity`, `priority`, `confidence`.

---

## Migration Plan Endpoints

### GET /api/migration-plans

List migration plans. Optionally filter by scan or priority.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)
- `priority` (optional) — `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `sort` (optional) — `"migration_priority"` to sort by derived priority score descending.

**Response (200):** Array of migration plan objects, each including `asset_name`, `algorithm`, `priority`, `rationale`, `blockers`, `replacement`, `agility_score`, `migration_priority_score`.

---

### GET /api/migration-plans/priority-view

Derived migration priority view: assets sorted by `risk_score / max(1, agility_score)` descending, surfacing high-risk, hard-to-migrate assets first.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):**
```json
[
  {
    "asset_id": "<uuid>",
    "asset_name": "RSA-2048 in src/auth.py",
    "algorithm": "RSA-2048",
    "purpose": "key_establishment",
    "location": "src/auth.py:12",
    "risk_score": 62,
    "risk_severity": "HIGH",
    "agility_score": 35,
    "agility_factors": [...],
    "migration_priority": 1.77,
    "recommended_algorithm": "ML-KEM"
  }
]
```

---

### POST /api/migration-plans/simulate

Interactive migration simulation — returns offline, read-only remediation guidance. Never applies changes to source code.

**Auth:** Required.

**Request Body:**
```json
{
  "current_algorithm": "RSA-2048",
  "proposed_algorithm": "ML-KEM",
  "language": "python",
  "current_library": "cryptography",
  "purpose": "key_establishment",
  "user_supplied": {}
}
```

**Response (200):** Simulation result with target library, minimum version, replacement API, hybrid construction option, diff template, and explicit notes where values are `"Not measured"`.

---

## Certificate Endpoints

### GET /api/certificates

List discovered X.509 certificates. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):** Array of certificate objects including `file`, `subject`, `issuer`, `serial_number`, `valid_from`, `valid_until`, `expired`, `days_remaining`, `public_key_algorithm`, `key_size`, `signature_algorithm`, `san`, `weak_key`, `weak_signature`, `parse_error`.

---

## Library Endpoints

### GET /api/libraries

List discovered crypto-capable libraries. Optionally filter by scan.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional)

**Response (200):** Array of library objects including `name`, `version`, `ecosystem`, `source_file`, `crypto_capable`, `known_algorithms`, `confidence`.

---

## Dashboard Endpoints

### GET /api/dashboard

Aggregated dashboard metrics derived from scan data.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional) — scope metrics to a specific scan.

**Response (200):**
```json
{
  "total_crypto_assets": 42,
  "quantum_vulnerable_assets": 28,
  "critical_risks": 3,
  "high_risks": 9,
  "certificates_found": 4,
  "crypto_libraries_found": 11,
  "applications_scanned": 6,
  "scans_run": 2,
  "risk_distribution": {"LOW": 5, "MEDIUM": 14, "HIGH": 9, "CRITICAL": 3},
  "algorithm_distribution": {"RSA-2048": 8, "AES-256": 6, ...},
  "asset_type_distribution": {"crypto_usage": 35, "certificate": 4, ...},
  "migration_priority_distribution": {"CRITICAL": 3, "HIGH": 9, "MEDIUM": 14, "LOW": 5},
  "certificate_expiry_distribution": {
    "expired": 1, "expiring_30d": 0, "expiring_90d": 2, "healthy": 1, "unknown": 0
  },
  "posture_drift": { ... }
}
```

---

### GET /api/dashboard/drift

Crypto-posture drift trend across historical completed scans for a target.

**Auth:** Required.

**Query Parameters:**
- `target` (optional) — target directory path. Defaults to the most recent completed scan's target.

**Response (200):**
```json
{
  "target": "/path/to/repo",
  "scans_tracked": 3,
  "history": [
    {
      "scan_id": "<uuid>",
      "target": "/path/to/repo",
      "timestamp": "2026-09-01T10:00:00",
      "total_artefacts": 70,
      "vulnerable_artefacts_count": 45,
      "pqc_artefacts_count": 2,
      "pqc_adoption_percentage": 2.86,
      "average_migration_priority": 1.42,
      "total_assets": 42,
      "critical_risks": 3,
      "high_risks": 9
    }
  ],
  "delta": {
    "vulnerable_artefacts_delta": -5,
    "pqc_adoption_percentage_delta": 1.5,
    "average_migration_priority_delta": -0.2,
    "critical_risks_delta": -1,
    "posture_improved": true
  }
}
```

---

## HNDL Endpoint

### GET /api/hndl

Harvest-now-decrypt-later exposure lens — read-only derived view over existing scan + business context.

**Auth:** Required.

**Query Parameters:**
- `scan_id` (optional) — scope to a specific scan.
- `threshold_years` (optional) — override the shelf-life threshold (default: `HNDL_SHELF_LIFE_THRESHOLD_YEARS` = 10).

**Response (200):**
```json
{
  "threshold_years": 10,
  "count": 2,
  "assets": [
    {
      "asset_id": "<uuid>",
      "name": "RSA-2048 in src/payment.py",
      "algorithm_name": "RSA-2048",
      "purpose": "key_establishment",
      "business_asset": "Payment API",
      "internet_exposed": true,
      "data_sensitivity": "RESTRICTED",
      "data_retention_years": 7,
      "hndl_exposed": true,
      "hndl_reason": "internet-exposed with quantum-vulnerable key exchange (RSA-2048) and long data shelf-life (7 years, RESTRICTED) — remediation deadline is effectively now, not Q-Day.",
      "exposure_factor": "internet-exposed",
      "quantum_kex_factor": "quantum-vulnerable key exchange (RSA-2048)",
      "shelf_life_factor": "long data shelf-life (7 years, RESTRICTED)"
    }
  ]
}
```

---

## Report Endpoints

### GET /api/reports

Get structured report data for a scan (JSON, not a file download).

**Auth:** Required.

**Query Parameters:**
- `scan_id` (required)

**Response (200):** Full report data dict including executive summary, cryptographic inventory, critical findings, quantum risk summary, PQC recommendations, migration priorities, HNDL lens, certificates, libraries, limitations.

**Errors:** `404` — Scan not found.

---

### POST /api/reports

Generate and save a report file.

**Auth:** Required.

**Request Body:**
```json
{
  "scan_id": "<uuid>",
  "format": "pdf"
}
```

- `format` — `"json"`, `"csv"`, or `"pdf"`.

**Response (200):**
```json
{
  "detail": "Report generated",
  "filename": "ecdat-report-<id>-<rand>.pdf",
  "download_url": "/api/reports/download/ecdat-report-<id>-<rand>.pdf"
}
```

**Errors:** `400` — Invalid format. `404` — Scan not found.

---

### GET /api/reports/download/{filename}

Download a previously generated report file.

**Auth:** Required.

**Path Parameters:**
- `filename` — filename returned by `POST /api/reports`. Sanitized server-side with `os.path.basename`.

**Response (200):** File download.

**Errors:** `404` — Report file not found.

---

## AI Assistant Endpoint

### POST /api/ai/chat

Query the AI assistant about scan findings.

**Auth:** Required.

**Request Body:**
```json
{
  "question": "Which RSA assets should migrate first?",
  "scan_id": "<uuid>"
}
```

**Response (200) — deterministic mode (default, `AI_ENABLED=false`):**
```json
{
  "answer": "RSA assets ranked by migration priority...",
  "mode": "deterministic",
  "note": "AI assistant is running in deterministic mode (no LLM configured). This always works offline and never invents findings.",
  "ai_assistant_status": "unavailable_using_deterministic_fallback"
}
```

**Response (200) — LLM mode (`AI_ENABLED=true`):**
```json
{
  "answer": "...",
  "mode": "ollama"
}
```

The `ai_assistant_status` field is added when `AI_ENABLED=false` and the deterministic fallback is used.

---

## Health Endpoint

### GET /health

Application health check. No authentication required.

**Response (200):**
```json
{
  "status": "ok",
  "app": "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
  "version": "0.1.0-mvp"
}
```

---

## Common HTTP Status Codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `400` | Bad request (invalid target, invalid format, validation error) |
| `401` | Missing or invalid JWT token |
| `404` | Resource not found |
| `409` | Conflict (e.g. scan already running) |
| `422` | Pydantic validation error (malformed request body) |

---

## Validation Notes

- **Scan target paths** are resolved with `os.path.abspath`. The server rejects targets that do not exist on the local filesystem.
- **Report filenames** are sanitized with `os.path.basename` before serving, preventing directory traversal.
- **Scanner list** in `POST /api/scans` is filtered against `VALID_SCANNERS = {"source","dependency","certificate","binary","container","config"}` — unknown scanner names are silently dropped.
- All request bodies are validated by Pydantic v2. Validation errors return `422` with field-level detail.
