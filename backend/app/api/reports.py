import os
import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import models
from app.scanners.schemas.schemas import ReportRequest
from app.services.report_service import build_report_data, export_json, export_csv, export_pdf
from app.core.config import settings

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
def get_report(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    try:
        return build_report_data(db, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("")
def generate_report(req: ReportRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    try:
        data = build_report_data(db, req.scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    filename = f"ecdat-report-{req.scan_id[:8]}-{uuid.uuid4().hex[:6]}.{req.format}"
    path = os.path.join(settings.REPORTS_DIR, filename)

    if req.format == "json":
        export_json(data, path)
    elif req.format == "csv":
        export_csv(db, req.scan_id, path)
    elif req.format == "pdf":
        export_pdf(data, path)
    else:
        raise HTTPException(status_code=400, detail="format must be json, csv, or pdf")

    return {"detail": "Report generated", "filename": filename, "download_url": f"/api/reports/download/{filename}"}


@router.get("/download/{filename}")
def download_report(filename: str, user: models.User = Depends(get_current_user)):
    safe_name = os.path.basename(filename)
    path = os.path.join(settings.REPORTS_DIR, safe_name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=safe_name)
