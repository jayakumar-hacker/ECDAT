"""
Crypto-posture drift service.

Calculates chronological trends across historical scans for the same target:
  - Vulnerable-artefact count over time
  - PQC-adoption % (Post-Quantum Cryptography / hybrid share of artefacts)
  - Average migration_priority across assets
"""
from typing import Any
from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import is_quantum_vulnerable, get_algorithm

PQC_KEYWORDS = (
    "ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA",
    "KYBER", "DILITHIUM", "SPHINCS",
    "FALCON", "BIKE", "HQC", "MCELIECE", "LMS", "XMSS", "HYBRID",
)


def is_pqc_algorithm(name: str) -> bool:
    """Return True if algorithm is a standardized or hybrid PQC construction."""
    if not name:
        return False
    upper = name.upper().strip()
    if any(k in upper for k in PQC_KEYWORDS):
        return True
    kb = get_algorithm(name)
    if kb and kb.get("category") == "pqc":
        return True
    return False


def compute_posture_drift(db: Session, target: str | None = None) -> dict[str, Any]:
    """
    Compute cryptographic posture drift across historical scans for a target.
    
    If target is None, defaults to the target of the most recent completed scan,
    or evaluates across all scans.
    """
    q = db.query(models.Scan).filter(models.Scan.status == "completed")

    if target:
        # Match exact or normalized path
        target_norm = target.strip()
        scans = q.filter(models.Scan.target == target_norm).order_by(models.Scan.created_at.asc()).all()
        if not scans:
            # Try fuzzy match if path separator difference
            all_scans = q.order_by(models.Scan.created_at.asc()).all()
            scans = [s for s in all_scans if s.target.replace("\\", "/").rstrip("/") == target_norm.replace("\\", "/").rstrip("/")]
    else:
        # Find the target with the most recent scan
        latest = q.order_by(models.Scan.created_at.desc()).first()
        if latest:
            target = latest.target
            scans = q.filter(models.Scan.target == target).order_by(models.Scan.created_at.asc()).all()
        else:
            scans = []

    history: list[dict[str, Any]] = []

    for scan in scans:
        artefacts = db.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.scan_id == scan.id
        ).all()
        total_artefacts = len(artefacts)

        vulnerable_count = 0
        pqc_count = 0
        for a in artefacts:
            algo_name = a.algorithm or ""
            if is_pqc_algorithm(algo_name):
                pqc_count += 1
            elif is_quantum_vulnerable(algo_name) or algo_name.upper() in ("MD5", "SHA-1", "DES", "3DES"):
                vulnerable_count += 1

        pqc_pct = round((pqc_count / max(1, total_artefacts)) * 100.0, 2)

        assets = db.query(models.Asset).filter(models.Asset.scan_id == scan.id).all()
        if assets:
            avg_priority = round(sum(float(a.migration_priority or 1.0) for a in assets) / len(assets), 2)
            crit_count = sum(1 for a in assets if a.risk_assessment and a.risk_assessment.severity == "CRITICAL")
            high_count = sum(1 for a in assets if a.risk_assessment and a.risk_assessment.severity == "HIGH")
        else:
            avg_priority = 0.0
            crit_count = 0
            high_count = 0

        ts = (scan.end_time or scan.start_time or scan.created_at)
        history.append({
            "scan_id": scan.id,
            "target": scan.target,
            "timestamp": ts.isoformat() if ts else None,
            "total_artefacts": total_artefacts,
            "vulnerable_artefacts_count": vulnerable_count,
            "pqc_artefacts_count": pqc_count,
            "pqc_adoption_percentage": pqc_pct,
            "average_migration_priority": avg_priority,
            "total_assets": len(assets),
            "critical_risks": crit_count,
            "high_risks": high_count,
        })

    delta: dict[str, Any] | None = None
    if len(history) >= 2:
        first = history[0]
        last = history[-1]
        delta = {
            "vulnerable_artefacts_delta": last["vulnerable_artefacts_count"] - first["vulnerable_artefacts_count"],
            "pqc_adoption_percentage_delta": round(last["pqc_adoption_percentage"] - first["pqc_adoption_percentage"], 2),
            "average_migration_priority_delta": round(last["average_migration_priority"] - first["average_migration_priority"], 2),
            "critical_risks_delta": last["critical_risks"] - first["critical_risks"],
            "posture_improved": (
                last["vulnerable_artefacts_count"] <= first["vulnerable_artefacts_count"]
                and last["pqc_adoption_percentage"] >= first["pqc_adoption_percentage"]
                and last["average_migration_priority"] <= first["average_migration_priority"]
            ),
        }

    return {
        "target": target or "none",
        "scans_tracked": len(history),
        "history": history,
        "delta": delta,
    }
