import os
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.api.serializers import serialize_scan, serialize_asset
from app.models import models
from app.scanners.schemas.schemas import ScanCreateRequest
from app.services.scan_service import run_scan, VALID_SCANNERS
from app.services.recommendation_service import build_recommendations_for_scan
from app.services.migration_service import build_migration_plans_for_scan
from app.core.config import BASE_DIR

router = APIRouter(prefix="/api/scans", tags=["scans"])

DEMO_REPO_PATH = os.path.join(BASE_DIR, "..", "demo-data", "repositories", "acme-corp")
DEMO_REPO_PATH = os.path.normpath(DEMO_REPO_PATH)


def _resolve_target(req: ScanCreateRequest) -> str:
    if req.target_type == "demo" or req.target.strip().lower() == "demo":
        return DEMO_REPO_PATH
    target = os.path.abspath(req.target)
    return target


@router.post("")
def create_scan(req: ScanCreateRequest, background_tasks: BackgroundTasks,
                 db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scanners = [s for s in req.scanners if s in VALID_SCANNERS] or list(VALID_SCANNERS)
    target = _resolve_target(req)

    if not os.path.exists(target):
        raise HTTPException(status_code=400, detail=f"Target path does not exist on the server: {target}")

    scan = models.Scan(
        target=target, target_type=req.target_type, scanners_requested=scanners,
        status="pending", created_by=user.username,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    def _do_scan(scan_id: str):
        from app.core.database import SessionLocal
        session = SessionLocal()
        try:
            s = session.query(models.Scan).filter(models.Scan.id == scan_id).first()
            run_scan(session, s, since_ref=req.since, policy_path=req.policy_path)
            build_recommendations_for_scan(session, scan_id)
            build_migration_plans_for_scan(session, scan_id)
        finally:
            session.close()

    background_tasks.add_task(_do_scan, scan.id)
    return serialize_scan(scan)


@router.get("")
def list_scans(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scans = db.query(models.Scan).order_by(models.Scan.created_at.desc()).all()
    return [serialize_scan(s) for s in scans]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialize_scan(scan)


@router.post("/{scan_id}/start")
def start_scan(scan_id: str, background_tasks: BackgroundTasks,
                db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=409, detail="Scan already running")

    def _do_scan(sid: str):
        from app.core.database import SessionLocal
        session = SessionLocal()
        try:
            s = session.query(models.Scan).filter(models.Scan.id == sid).first()
            run_scan(session, s)
            build_recommendations_for_scan(session, sid)
            build_migration_plans_for_scan(session, sid)
        finally:
            session.close()

    background_tasks.add_task(_do_scan, scan.id)
    return {"detail": "Scan started", "scan_id": scan.id}


@router.get("/{scan_id}/results")
def scan_results(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assets = db.query(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    return {
        "scan": serialize_scan(scan),
        "assets": [serialize_asset(a) for a in assets],
        "evidence": [
            {"scanner": e.scanner, "level": e.level, "message": e.message, "file": e.file}
            for e in scan.evidence
        ],
    }
