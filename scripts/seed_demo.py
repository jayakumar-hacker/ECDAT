"""
CLI wrapper around the shared seed logic in app/core/seed.py (the same
logic FastAPI's startup event runs automatically). Useful if you want to
seed without starting the server, e.g.:

    python scripts/seed_demo.py

This does NOT run a scan by itself - use the API (POST /api/scans with
target_type "demo") or the frontend "Scan" page to run the actual scan
against demo-data/repositories/acme-corp.
"""
import os
import sys

BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND_DIR)

from app.core.database import init_db, SessionLocal  # noqa: E402
from app.core.seed import seed_all  # noqa: E402


def main():
    init_db()
    db = SessionLocal()
    try:
        seed_all(db)
        print("Seed complete. Demo users: admin/EcdatDemo123!, analyst/EcdatDemo123!")
        print("Run a demo scan via the API or frontend to populate crypto findings:")
        print('  POST /api/scans  {"target": "demo", "target_type": "demo"}')
    finally:
        db.close()


if __name__ == "__main__":
    main()
