from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_migration_plan
from app.models import models
from app.scanners.schemas.schemas import MigrationSimulateRequest
from app.services.migration_service import simulate_migration

router = APIRouter(prefix="/api/migration-plans", tags=["migration"])


@router.get("")
def list_plans(scan_id: str | None = None, priority: str | None = None, sort: str | None = None,
               db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.MigrationPlan).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    plans = q.all()
    if priority:
        plans = [p for p in plans if p.priority == priority.upper()]
    if sort in ("migration_priority", "priority_score"):
        plans = sorted(plans, key=lambda p: p.migration_priority_score or 0.0, reverse=True)
    else:
        plans = sorted(plans, key=lambda p: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(p.priority, 4))
    return [{**serialize_migration_plan(p), "asset_name": p.asset.name, "algorithm": p.asset.algorithm_name} for p in plans]


@router.get("/priority-view")
def migration_priority_view(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Derived migration priority view: surfaces high-risk + low-agility assets first."""
    q = db.query(models.Asset).join(models.RiskAssessment)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    assets = q.all()
    sorted_assets = sorted(assets, key=lambda a: a.migration_priority or 0.0, reverse=True)
    return [
        {
            "asset_id": a.id,
            "asset_name": a.name,
            "algorithm": a.algorithm_name,
            "purpose": a.purpose,
            "location": a.location,
            "risk_score": a.risk_assessment.score if a.risk_assessment else 0,
            "risk_severity": a.risk_assessment.severity if a.risk_assessment else "LOW",
            "agility_score": a.agility_score,
            "agility_factors": a.agility_factors,
            "migration_priority": a.migration_priority,
            "recommended_algorithm": a.recommendation.recommended_algorithm if a.recommendation else None,
        }
        for a in sorted_assets
    ]


@router.post("/simulate")
def simulate(req: MigrationSimulateRequest, user: models.User = Depends(get_current_user)):
    return simulate_migration(req.current_algorithm, req.proposed_algorithm, req.user_supplied)
