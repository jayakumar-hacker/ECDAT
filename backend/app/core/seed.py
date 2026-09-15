"""
Shared seed data/logic, used by both the FastAPI startup event (so a bare
`docker compose up` or `uvicorn app.main:app` gives a ready-to-use demo
with zero extra steps) and scripts/seed_demo.py (for manual/CLI use).
"""
from sqlalchemy.orm import Session
from app.models import models
from app.core.security import hash_password
from app.core.logging import logger

BUSINESS_ASSETS = [
    dict(name="Payment API", description="Handles card payment processing and settlement.",
         owner="payments-team", environment="production", business_criticality="CRITICAL",
         data_sensitivity="RESTRICTED", internet_exposed=True, data_retention_years=7,
         estimated_migration_years=1.5),
    dict(name="Authentication Service", description="Issues and validates user session/refresh tokens.",
         owner="platform-team", environment="production", business_criticality="CRITICAL",
         data_sensitivity="CONFIDENTIAL", internet_exposed=True, data_retention_years=2,
         estimated_migration_years=1.0),
    dict(name="HR Portal", description="Internal employee records and document management.",
         owner="it-team", environment="production", business_criticality="MEDIUM",
         data_sensitivity="CONFIDENTIAL", internet_exposed=False, data_retention_years=10,
         estimated_migration_years=2.0),
    dict(name="Public Website", description="Marketing site and contact forms.",
         owner="marketing-team", environment="production", business_criticality="LOW",
         data_sensitivity="PUBLIC", internet_exposed=True, data_retention_years=1,
         estimated_migration_years=0.5),
    dict(name="Legacy Application", description="15-year-old internal inventory system.",
         owner="it-team", environment="production", business_criticality="MEDIUM",
         data_sensitivity="INTERNAL", internet_exposed=False, data_retention_years=15,
         estimated_migration_years=3.0),
    dict(name="IoT Service", description="Telemetry ingestion from field devices.",
         owner="iot-team", environment="production", business_criticality="HIGH",
         data_sensitivity="INTERNAL", internet_exposed=True, data_retention_years=5,
         estimated_migration_years=2.5),
]


def seed_users(db: Session) -> int:
    if db.query(models.User).count() > 0:
        return 0
    db.add_all([
        models.User(username="admin", email="admin@ecdat.local",
                    hashed_password=hash_password("EcdatDemo123!"), role="admin"),
        models.User(username="analyst", email="analyst@ecdat.local",
                    hashed_password=hash_password("EcdatDemo123!"), role="user"),
    ])
    db.commit()
    return 2


def seed_business_assets(db: Session) -> int:
    existing_names = {b.name for b in db.query(models.BusinessAsset).all()}
    added = 0
    for ba in BUSINESS_ASSETS:
        if ba["name"] not in existing_names:
            db.add(models.BusinessAsset(**ba))
            added += 1
    if added:
        db.commit()
    return added


def seed_all(db: Session):
    users_added = seed_users(db)
    if users_added:
        logger.info("Seeded default users: admin/EcdatDemo123!, analyst/EcdatDemo123!")
    ba_added = seed_business_assets(db)
    if ba_added:
        logger.info("Seeded %d business asset(s).", ba_added)
