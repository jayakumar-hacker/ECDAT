"""
PQC recommendation engine.

Maps each asset's current algorithm to a standards-aware recommendation
using the offline knowledge base. Distinguishes PQC standards (ML-KEM,
ML-DSA, SLH-DSA) from hybrid constructions and legacy algorithms, and
never claims one PQC algorithm is a universal drop-in replacement for
a different cryptographic purpose (e.g. ML-KEM does not replace RSA
*signatures* - only RSA *key establishment*).
"""
from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import get_algorithm

CATEGORY_MAP = {
    "key_establishment": "key_establishment",
    "digital_signature": "signature",
    "encryption": "symmetric",
    "hashing": "hash",
    "mac": "mac",
    "protocol": "protocol",
}


def _recommendation_type(algo_kb: dict) -> str:
    if not algo_kb["quantum_vulnerable"]:
        return "legacy" if algo_kb["name"] in ("MD5", "SHA-1", "DES") else "not_applicable"
    if algo_kb.get("recommended_pqc") and "N/A" not in algo_kb["recommended_pqc"]:
        return "pqc_standard"
    return "legacy"


def build_recommendation_for_asset(db: Session, asset: models.Asset) -> models.Recommendation | None:
    if not asset.algorithm_name:
        return None
    algo_kb = get_algorithm(asset.algorithm_name)
    if not algo_kb:
        return None

    category = CATEGORY_MAP.get(asset.purpose, algo_kb["category"])
    rec_type = _recommendation_type(algo_kb)

    if algo_kb["quantum_vulnerable"]:
        priority = "HIGH" if category in ("key_establishment", "signature") else "MEDIUM"
    else:
        priority = "LOW"

    reason_parts = [algo_kb["quantum_impact"]]
    if category == "key_establishment":
        reason_parts.append("ML-KEM (FIPS 203) is the NIST-standardized replacement for classical key establishment.")
    elif category == "signature":
        reason_parts.append("ML-DSA (FIPS 204) is the primary NIST-standardized replacement for classical signatures; SLH-DSA (FIPS 205) is a stateless hash-based alternative for conservative/long-lived use cases.")
    elif category == "symmetric":
        reason_parts.append("Symmetric algorithms are addressed via key size (Grover's algorithm margin), not a PQC algorithm swap.")
    elif category == "hash":
        reason_parts.append("Hash algorithm strength is addressed via output size/algorithm choice, not PQC migration.")

    existing = db.query(models.Recommendation).filter(models.Recommendation.asset_id == asset.id).first()
    values = dict(
        current_algorithm=asset.algorithm_name,
        category=category,
        recommended_algorithm=algo_kb.get("recommended_pqc", ""),
        recommended_type=rec_type,
        hybrid_option=algo_kb.get("recommended_hybrid", ""),
        reason=" ".join(reason_parts),
        compatibility=algo_kb.get("compatibility_notes", ""),
        migration_complexity=algo_kb.get("migration_complexity", "MEDIUM"),
        priority=priority,
        confidence=min(0.95, (asset.confidence or 0.5) + 0.1),
    )
    if existing:
        for k, v in values.items():
            setattr(existing, k, v)
        return existing
    rec = models.Recommendation(asset_id=asset.id, **values)
    db.add(rec)
    return rec


def build_recommendations_for_scan(db: Session, scan_id: str):
    assets = db.query(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    for asset in assets:
        build_recommendation_for_asset(db, asset)
    db.commit()
