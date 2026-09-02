#!/usr/bin/env bash
# ECDAT one-time setup: creates the backend virtualenv, installs Python
# and Node dependencies, and seeds demo users/business context.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Setting up backend virtualenv"
cd backend
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cd ..

echo "==> Installing frontend dependencies"
cd frontend
npm install
cd ..

echo "==> Seeding demo users and business context"
cd backend && source .venv/bin/activate && cd ..
python scripts/seed_demo.py

echo ""
echo "Setup complete."
echo "Run the backend:  scripts/run_backend.sh"
echo "Run the frontend: scripts/run_frontend.sh"
