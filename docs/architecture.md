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
 | Config & Protocol Scanner  |  app/scanners/config
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
              |
      Diff-native CI mode        app/services/scan_service.py (git diff file_filter)
              |
      Policy-as-Code Gate        app/services/policy_service.py + app/cli.py
              |
     HNDL Exposure Lens          app/services/hndl_service.py + app/api/hndl.py
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
  recommendations, migration, reports). Includes crypto-agility scoring
  (0-100 score based on abstraction mechanism, version pinning, and call-site
  blast radius), derived migration priority views, and the policy-as-code
  evaluation engine (`policy_service.py`).
- `app/cli.py` — the `ecdat` command-line interface, including diff-native
  CI mode (`ecdat scan --since <git-ref>`) and the policy gate
  (`ecdat check-policy`). See `docs/diff-native-ci.md`.
- `app/services/hndl_service.py` — the Harvest-now-decrypt-later (HNDL)
  lens: a deterministic, read-only projection over Asset + BusinessAsset
  rows that flags internet-exposed/captured-in-transit assets with
  quantum-vulnerable key establishment and long data shelf-life.
- `app/ai/` — deterministic + optional LLM-backed assistant.

## Data model

A scan produces `CryptographicArtefact` rows (raw per-file/per-line
findings). These are grouped into `Asset` rows (one per distinct
algorithm+location), which is the unit that `RiskAssessment`,
`MoscaAssessment`, `Recommendation`, and `MigrationPlan` attach to
one-to-one. Each `Asset` and `RiskAssessment` records an `agility_score`
and derived `migration_priority` (`risk_score / max(1, agility_score)`).
`BusinessAsset` rows (Payment API, HR Portal, ...) can be
linked to `Asset` rows to bring in business context (criticality,
sensitivity, exposure) that the risk engine and Mosca analysis use.

Each `Scan` also records `since_git_ref` (when run in diff-native mode),
`policy_status` (`NOT_RUN` / `PASS` / `FAIL`) and `policy_violations`
(the resolved list of violated rules), so CI gates and the dashboard can
surface policy results without re-running the scan.

## Diff-native CI mode and policy gate

The `ecdat` CLI adds a gate-friendly layer on top of the scan pipeline:

- **Diff-native scans** (`ecdat scan <target> --since <git-ref>`) resolve
  the set of files changed since a git ref via `git diff --name-only` and
  pass that set as a `file_filter` to every scanner. Only files in the diff
  are examined, so a PR gate sees only what the PR introduced.
- **Policy-as-code gating** (`ecdat scan <target> --policy ecdat-policy.yaml`
  or `ecdat check-policy`) evaluates repository-level YAML rules against the
  scan's assets and artefacts. Exit codes are `0` (pass), `1` (violations /
  gate closed) and `2` (no policy or no scan found). `--json` emits a
  machine-readable report and `--no-fail-on-violation` reports without
  closing the gate.

See `docs/diff-native-ci.md` for the rule reference and a copy-paste CI
snippet.

## Harvest-now-decrypt-later (HNDL) exposure lens

The HNDL lens (`app/services/hndl_service.py`, `app/api/hndl.py`,
`ecdat hndl`) is a read-only projection over existing data that flags
assets matching all three of:

1. internet-exposed **or** captured-in-transit (transport-crypto
   protocol/library hints),
2. long data shelf-life — using the existing
   `BusinessAsset.data_retention_years` as the shelf-life proxy against a
   configurable threshold (`HNDL_SHELF_LIFE_THRESHOLD_YEARS`, default 10),
   with `data_sensitivity` / `business_criticality` carried as context,
3. quantum-vulnerable key establishment (via the offline knowledge base and
   the `Asset.purpose`/algorithm category).

Each matched asset is tagged `hndl_exposed: true` with a human-readable
`hndl_reason` (e.g. *"internet-exposed with quantum-vulnerable key exchange
(RSA-2048) and long data shelf-life (7 years, RESTRICTED) — remediation
deadline is effectively now, not Q-Day."*). The two fields are additive
columns on `Asset`; no scanner output or risk-model shape changes. The view
is exposed as an **additional section** in the existing JSON/CSV report
exports (never a replacement).

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
