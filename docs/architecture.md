# ECDAT Architecture

## Overview

ECDAT is a defensive cybersecurity MVP that discovers cryptographic usage
in source code, dependencies, certificates, binaries, and containers, then
evaluates quantum-computing risk and recommends post-quantum (PQC)
migration paths. It runs entirely offline; no paid or external services
are required.

## Pipeline

```
Repository / Files / Container
              |
       Scan Orchestrator (app/services/scan_service.py)
              |
 -----------------------------
 | Source Code Scanner        |  app/scanners/source
 | Dependency Scanner         |  app/scanners/dependency
 | Certificate Scanner        |  app/scanners/certificate
 | Binary Scanner              |  app/scanners/binary
 | Container Scanner           |  app/scanners/container
 -----------------------------
              |
     Crypto Intelligence        app/crypto (knowledge_base, classifier, algorithms)
              |
          CBOM Engine           app/services/cbom_service.py
              |
     Dependency Graph           derived at query time from Asset/Library rows
              |
      Quantum Risk Engine       app/services/risk_service.py
              |
        Mosca Analysis          app/services/risk_service.py (compute_mosca_for_asset)
              |
    Migration Prioritization    app/services/migration_service.py
              |
       PQC Recommendation       app/services/recommendation_service.py
              |
      Migration Simulator       app/services/migration_service.py (simulate_migration)
              |
        Reports + Dashboard     app/services/report_service.py, app/api/dashboard.py
              |
          AI Assistant          app/ai/assistant.py
```

## Backend layout

- `app/main.py` — FastAPI app, router registration, startup seeding.
- `app/api/` — one module per resource; thin, delegates to `app/services/`.
- `app/core/` — config, database session, security (JWT/bcrypt), logging/audit.
- `app/models/models.py` — all SQLAlchemy models in one module for clarity.
- `app/scanners/` — one scanner per artefact type, each read-only. Includes
  manifest and lockfile parsers (poetry.lock, package-lock.json, Cargo.lock,
  go.sum, pnpm-lock.yaml, Gemfile.lock) that construct offline dependency graphs
  and resolve transitive cryptographic provenance.
- `app/crypto/` — the offline knowledge base, detection patterns, classifier.
- `app/services/` — orchestration and business logic (scan, risk, CBOM,
  recommendations, migration, reports).
- `app/ai/` — deterministic + optional LLM-backed assistant.

## Data model

A scan produces `CryptographicArtefact` rows (raw per-file/per-line
findings). These are grouped into `Asset` rows (one per distinct
algorithm+location), which is the unit that `RiskAssessment`,
`MoscaAssessment`, `Recommendation`, and `MigrationPlan` attach to
one-to-one. `BusinessAsset` rows (Payment API, HR Portal, ...) can be
linked to `Asset` rows to bring in business context (criticality,
sensitivity, exposure) that the risk engine and Mosca analysis use.

## Frontend layout

React + TypeScript + Vite + Tailwind, talking to the backend over
`/api/*` (proxied to `localhost:8000` in dev via `vite.config.ts`).
One page component per required navigation item under `src/pages/`,
a shared `AppLayout` sidebar/header, and a small `services/api.ts`
axios client that attaches the JWT and redirects to `/login` on 401.

## Why these tradeoffs

- **Regex/keyword source scanning, not full AST/data-flow analysis.**
  This is far cheaper to build and reason about, and is transparent
  about its limits (see `docs/limitations.md`) rather than pretending
  to prove runtime behavior it cannot prove.
- **SQLite by default.** Zero configuration, matches the "runnable
  locally without paid services" requirement. The schema uses only
  portable SQLAlchemy types, so moving to PostgreSQL is a
  `DATABASE_URL` change, not a rewrite.
- **Deterministic AI fallback.** The AI Assistant page and API always
  work, even with zero internet access and zero LLM configured,
  because the "must work without AI" requirement is treated as a hard
  constraint, not a stretch goal.
