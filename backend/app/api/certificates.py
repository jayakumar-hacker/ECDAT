from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_certificate
from app.models import models

router = APIRouter(prefix="/api/certificates", tags=["certificates"])


@router.get("")
def list_certificates(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    q = db.query(models.Certificate)
    if scan_id:
        q = q.filter(models.Certificate.scan_id == scan_id)
    return [serialize_certificate(c) for c in q.all()]
