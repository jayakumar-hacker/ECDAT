from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import models
from app.services.drift_service import compute_posture_drift

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])



@router.get("")
def dashboard(scan_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    asset_q = db.query(models.Asset)
    if scan_id:
        asset_q = asset_q.filter(models.Asset.scan_id == scan_id)
    assets = asset_q.all()

    risks = [a.risk_assessment for a in assets if a.risk_assessment]
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in risks:
        severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1

    quantum_vulnerable_count = 0
    algo_dist: dict[str, int] = {}
    asset_type_dist: dict[str, int] = {}
    for a in assets:
        algo = a.algorithm_name or "unknown"
        algo_dist[algo] = algo_dist.get(algo, 0) + 1
        asset_type_dist[a.asset_type] = asset_type_dist.get(a.asset_type, 0) + 1
        if a.risk_assessment and any(f["name"] == "quantum_vulnerability" and f["impact"] >= 20 for f in (a.risk_assessment.factors or [])):
            quantum_vulnerable_count += 1

    cert_q = db.query(models.Certificate)
    lib_q = db.query(models.Library)
    scan_q = db.query(models.Scan)
    migration_q = db.query(models.MigrationPlan).join(models.Asset)
    if scan_id:
        cert_q = cert_q.filter(models.Certificate.scan_id == scan_id)
        lib_q = lib_q.filter(models.Library.scan_id == scan_id)
        migration_q = migration_q.filter(models.Asset.scan_id == scan_id)

    certificates = cert_q.all()
    libraries = lib_q.all()
    migration_plans = migration_q.all()
    scans = scan_q.all()

    migration_priority_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for p in migration_plans:
        migration_priority_dist[p.priority] = migration_priority_dist.get(p.priority, 0) + 1

    cert_expiry_buckets = {"expired": 0, "expiring_30d": 0, "expiring_90d": 0, "healthy": 0, "unknown": 0}
    for c in certificates:
        if c.parse_error:
            cert_expiry_buckets["unknown"] += 1
        elif c.expired:
            cert_expiry_buckets["expired"] += 1
        elif c.days_remaining is not None and c.days_remaining <= 30:
            cert_expiry_buckets["expiring_30d"] += 1
        elif c.days_remaining is not None and c.days_remaining <= 90:
            cert_expiry_buckets["expiring_90d"] += 1
        else:
            cert_expiry_buckets["healthy"] += 1

    return {
        "total_crypto_assets": len(assets),
        "quantum_vulnerable_assets": quantum_vulnerable_count,
        "critical_risks": severity_counts["CRITICAL"],
        "high_risks": severity_counts["HIGH"],
        "certificates_found": len(certificates),
        "crypto_libraries_found": len(libraries),
        "applications_scanned": len({a.business_asset_id for a in assets if a.business_asset_id}),
        "scans_run": len(scans),
        "risk_distribution": severity_counts,
        "algorithm_distribution": algo_dist,
        "asset_type_distribution": asset_type_dist,
        "migration_priority_distribution": migration_priority_dist,
        "certificate_expiry_distribution": cert_expiry_buckets,
        "posture_drift": compute_posture_drift(db),
    }


@router.get("/drift")
def posture_drift_endpoint(
    target: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Trend view: vulnerable-artefact count over time, PQC-adoption %, average migration priority."""
    return compute_posture_drift(db, target=target)

