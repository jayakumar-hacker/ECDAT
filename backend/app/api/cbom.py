from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import models
from app.services.cbom_service import generate_cbom, cbom_to_csv

router = APIRouter(prefix="/api/cbom", tags=["cbom"])


@router.get("")
def get_cbom(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return generate_cbom(db, scan_id)


@router.get("/export")
def export_cbom(scan_id: str | None = None, format: str = "json",
                 db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    cbom = generate_cbom(db, scan_id)
    if format == "csv":
        csv_text = cbom_to_csv(cbom)
        return Response(content=csv_text, media_type="text/csv",
                         headers={"Content-Disposition": "attachment; filename=cbom.csv"})
    import json
    return Response(content=json.dumps(cbom, indent=2, default=str), media_type="application/json",
                     headers={"Content-Disposition": "attachment; filename=cbom.json"})
