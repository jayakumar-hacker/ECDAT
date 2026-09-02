from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_recommendation
from app.models import models

router = APIRouter(prefix="/api/recommendations", tags=["recommendations"])


@router.get("")
def list_recommendations(scan_id: str | None = None, priority: str | None = None,
                          db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.Recommendation).join(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    recs = q.all()
    if priority:
        recs = [r for r in recs if r.priority == priority.upper()]
    return [{**serialize_recommendation(r), "asset_name": r.asset.name} for r in recs]
