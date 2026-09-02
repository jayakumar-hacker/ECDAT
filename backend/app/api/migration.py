from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_migration_plan
from app.models import models
from app.schemas.schemas import MigrationSimulateRequest
from app.services.migration_service import simulate_migration

router = APIRouter(prefix="/api/migration-plans", tags=["migration"])


@router.get("")
def list_plans(scan_id: str | None = None, priority: str | None = None,
               db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.MigrationPlan).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    plans = q.all()
    if priority:
        plans = [p for p in plans if p.priority == priority.upper()]
    plans = sorted(plans, key=lambda p: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(p.priority, 4))
    return [{**serialize_migration_plan(p), "asset_name": p.asset.name, "algorithm": p.asset.algorithm_name} for p in plans]


@router.post("/simulate")
def simulate(req: MigrationSimulateRequest, user: models.User = Depends(get_current_user)):
    return simulate_migration(req.current_algorithm, req.proposed_algorithm, req.user_supplied)
