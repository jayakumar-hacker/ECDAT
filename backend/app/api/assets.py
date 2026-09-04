from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_asset
from app.models import models

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("")
def list_assets(scan_id: str | None = None, severity: str | None = None, sort: str | None = None,
                 db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    assets = q.all()
    if severity:
        assets = [a for a in assets if a.risk_assessment and a.risk_assessment.severity == severity.upper()]
    if sort in ("migration_priority", "priority"):
        assets = sorted(assets, key=lambda a: a.migration_priority or 0.0, reverse=True)
    return [serialize_asset(a) for a in assets]


@router.get("/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return serialize_asset(asset)
