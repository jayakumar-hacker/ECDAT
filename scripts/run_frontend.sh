#!/usr/bin/env bash
# Starts the ECDAT frontend dev server on http://localhost:5173
set -euo pipefail
cd "$(dirname "$0")/../frontend"
npm run dev
