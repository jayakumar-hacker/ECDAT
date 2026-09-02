#!/usr/bin/env bash
# Starts the ECDAT FastAPI backend on http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")/../backend"
# shellcheck disable=SC1091
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
