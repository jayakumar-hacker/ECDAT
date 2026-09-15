from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_risk
from app.models import models

router = APIRouter(prefix="/api/risks", tags=["risks"])


@router.get("")
def list_risks(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.RiskAssessment).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    risks = q.all()
    return [{**serialize_risk(r), "asset_name": r.asset.name, "algorithm": r.asset.algorithm_name} for r in risks]


@router.get("/summary")
def risk_summary(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.RiskAssessment).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    risks = q.all()
    summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in risks:
        summary[r.severity] = summary.get(r.severity, 0) + 1
    algo_dist: dict[str, int] = {}
    for r in risks:
        algo = r.asset.algorithm_name or "unknown"
        algo_dist[algo] = algo_dist.get(algo, 0) + 1
    return {"total": len(risks), "by_severity": summary, "by_algorithm": algo_dist}
