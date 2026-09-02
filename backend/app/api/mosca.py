from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_mosca
from app.models import models
from app.schemas.schemas import MoscaSimulateRequest
from app.services.risk_service import compute_mosca_for_asset

router = APIRouter(prefix="/api/mosca", tags=["mosca"])


@router.get("")
def list_mosca(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.MoscaAssessment).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    results = q.all()
    return [{**serialize_mosca(m), "asset_name": m.asset.name, "algorithm": m.asset.algorithm_name} for m in results]


@router.post("/simulate")
def simulate(req: MoscaSimulateRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    asset = db.query(models.Asset).filter(models.Asset.id == req.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    mosca = compute_mosca_for_asset(
        db, asset,
        x_override=req.x_data_lifetime_years,
        y_override=req.y_migration_time_years,
        z_override=req.z_threat_horizon_years,
    )
    db.commit()
    return serialize_mosca(mosca)
