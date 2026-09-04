"""
HNDL (Harvest-now-decrypt-later) lens API.

Read-only endpoint exposing the derived HNDL exposure view over existing
scan/business context (see app/services/hndl_service.py).
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import models
from app.services.hndl_service import evaluate_hndl, resolve_threshold

router = APIRouter(prefix="/api/hndl", tags=["hndl"])


@router.get("")
def get_hndl_lens(scan_id: str | None = None, threshold_years: int | None = None,
                  db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """
    Returns assets matching the harvest-now-decrypt-later profile:
    internet-exposed/captured-in-transit + long data shelf-life +
    quantum-vulnerable key establishment.
    """
    matched = evaluate_hndl(db, scan_id=scan_id, shelf_life_threshold_years=threshold_years)
    return {
        "threshold_years": resolve_threshold(threshold_years),
        "count": len(matched),
        "assets": matched,
    }