from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_library
from app.models import models

router = APIRouter(tags=["libraries"])


@router.get("/api/libraries")
def list_libraries(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.Library)
    if scan_id:
        q = q.filter(models.Library.scan_id == scan_id)
    return [serialize_library(l) for l in q.all()]


@router.get("/api/containers")
def list_containers(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Container findings are folded into artefacts/libraries with artefact_type='container';
    this endpoint surfaces a filtered view for the Containers page."""
    q = db.query(models.CryptographicArtefact).filter(models.CryptographicArtefact.artefact_type == "container")
    if scan_id:
        q = q.filter(models.CryptographicArtefact.scan_id == scan_id)
    artefacts = q.all()
    return [
        {"id": a.id, "algorithm": a.algorithm, "file": a.file, "usage": a.usage,
         "library": a.library, "confidence": a.confidence}
        for a in artefacts
    ]
