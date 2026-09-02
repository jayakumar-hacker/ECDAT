"""
Risk engine.

build_assets_from_artefacts(): groups raw CryptographicArtefact rows into
Asset rows (one asset per distinct algorithm+location combination), which
is the unit that risk/Mosca/recommendations/migration all attach to.

compute_risk_for_asset(): deterministic 0-100 scoring model. This is
explicitly documented as the "ECDAT scoring model" - not an official
NIST/CVSS score - see docs/risk-model.md.
"""
from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import get_algorithm, is_quantum_vulnerable
from app.core.config import settings

CRITICALITY_WEIGHT = {"LOW": 5, "MEDIUM": 10, "HIGH": 15, "CRITICAL": 20}
SENSITIVITY_WEIGHT = {"PUBLIC": 0, "INTERNAL": 5, "CONFIDENTIAL": 12, "RESTRICTED": 18}
COMPLEXITY_WEIGHT = {"LOW": 3, "MEDIUM": 8, "HIGH": 14}


def _slugify(name: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")


def _match_business_asset(db: Session, file_path: str, cache: dict) -> str | None:
    """Deterministic path-based linking: matches the top-level directory of a
    finding's file path against a slugified BusinessAsset name (e.g. a file
    under '.../payment-api/...' links to the 'Payment API' business asset,
    since slugify('Payment API') == 'payment-api'). Returns None if no
    business assets exist or none match - this is not fabricated linkage,
    only applied when the directory name deterministically matches."""
    if not file_path:
        return None
    if "business_assets" not in cache:
        cache["business_assets"] = {_slugify(b.name): b.id for b in db.query(models.BusinessAsset).all()}
    ba_map = cache["business_assets"]
    if not ba_map:
        return None
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    for part in parts:
        slug = _slugify(part)
        if slug in ba_map:
            return ba_map[slug]
    return None


def build_assets_from_artefacts(db: Session, scan_id: str):
    artefacts = db.query(models.CryptographicArtefact).filter(
        models.CryptographicArtefact.scan_id == scan_id,
        models.CryptographicArtefact.asset_id.is_(None),
    ).all()

    groups: dict[tuple, list[models.CryptographicArtefact]] = {}
    for a in artefacts:
        key = (a.algorithm, a.file, a.purpose or "")
        groups.setdefault(key, []).append(a)

    cache: dict = {}
    for (algorithm, file, purpose), items in groups.items():
        best = max(items, key=lambda x: x.confidence or 0)
        business_asset_id = _match_business_asset(db, file, cache)
        asset = models.Asset(
            scan_id=scan_id,
            business_asset_id=business_asset_id,
            name=f"{algorithm} in {file or 'dependency manifest'}",
            asset_type="crypto_usage",
            algorithm_name=algorithm,
            key_size=best.key_size,
            purpose=purpose,
            component=best.library or best.protocol or "",
            location=f"{file}:{best.line}" if best.line else (file or ""),
            confidence=best.confidence or 0.5,
        )
        db.add(asset)
        db.flush()
        for item in items:
            item.asset_id = asset.id

        compute_risk_for_asset(db, asset)
        compute_mosca_for_asset(db, asset)

    db.commit()


def _severity_for_score(score: int) -> str:
    if score <= settings.RISK_LOW_MAX:
        return "LOW"
    if score <= settings.RISK_MEDIUM_MAX:
        return "MEDIUM"
    if score <= settings.RISK_HIGH_MAX:
        return "HIGH"
    return "CRITICAL"


def compute_risk_for_asset(db: Session, asset: models.Asset) -> models.RiskAssessment:
    factors = []
    score = 0

    algo_kb = get_algorithm(asset.algorithm_name or "") if asset.algorithm_name else None
    vulnerable = is_quantum_vulnerable(asset.algorithm_name or "") if asset.algorithm_name else True

    if vulnerable:
        impact = 30
        factors.append({"name": "quantum_vulnerability", "impact": impact,
                         "detail": f"{asset.algorithm_name} is vulnerable to a cryptographically relevant quantum computer."})
        score += impact
    else:
        factors.append({"name": "quantum_vulnerability", "impact": 2,
                         "detail": f"{asset.algorithm_name} is not primarily quantum-vulnerable (symmetric/hash, adequate margin)."})
        score += 2

    # key size factor
    if asset.key_size:
        if asset.algorithm_name and asset.algorithm_name.upper().startswith("RSA") and asset.key_size < 2048:
            factors.append({"name": "key_size", "impact": 15, "detail": f"Key size {asset.key_size} is below the modern 2048-bit RSA minimum."})
            score += 15
        elif asset.algorithm_name and "SHA-1" in (asset.algorithm_name or "").upper():
            pass

    # purpose factor
    if asset.purpose in ("key_establishment", "digital_signature"):
        factors.append({"name": "purpose", "impact": 10, "detail": f"Purpose '{asset.purpose}' carries higher migration priority than symmetric encryption/hashing."})
        score += 10
    elif asset.purpose == "encryption":
        factors.append({"name": "purpose", "impact": 3, "detail": "Symmetric encryption purpose."})
        score += 3

    # business context (if linked)
    ba = asset.business_asset
    if ba:
        c_impact = CRITICALITY_WEIGHT.get(ba.business_criticality, 8)
        factors.append({"name": "business_criticality", "impact": c_impact, "detail": f"Business criticality: {ba.business_criticality}"})
        score += c_impact

        s_impact = SENSITIVITY_WEIGHT.get(ba.data_sensitivity, 5)
        factors.append({"name": "data_sensitivity", "impact": s_impact, "detail": f"Data sensitivity: {ba.data_sensitivity}"})
        score += s_impact

        if ba.internet_exposed:
            factors.append({"name": "internet_exposure", "impact": 12, "detail": "Asset's business system is internet-exposed."})
            score += 12
    else:
        factors.append({"name": "business_criticality", "impact": 6, "detail": "No business context supplied; default weight applied."})
        score += 6

    # confidence dampener - low-confidence findings contribute less certainty-adjusted risk display,
    # but we do not hide them; we simply note it.
    if (asset.confidence or 0) < 0.5:
        factors.append({"name": "detection_confidence", "impact": 0, "detail": f"Detection confidence is {asset.confidence:.2f}; recommend manual verification."})

    score = max(0, min(100, score))
    severity = _severity_for_score(score)

    existing = db.query(models.RiskAssessment).filter(models.RiskAssessment.asset_id == asset.id).first()
    if existing:
        existing.score = score
        existing.severity = severity
        existing.factors = factors
        risk = existing
    else:
        risk = models.RiskAssessment(asset_id=asset.id, score=score, severity=severity, factors=factors)
        db.add(risk)
    return risk


def compute_mosca_for_asset(db: Session, asset: models.Asset, x_override=None, y_override=None, z_override=None) -> models.MoscaAssessment:
    ba = asset.business_asset
    x = x_override if x_override is not None else (ba.data_retention_years if ba else 5)
    y = y_override if y_override is not None else (ba.estimated_migration_years if ba else 1.5)
    z = z_override if z_override is not None else settings.DEFAULT_THREAT_HORIZON_YEARS

    vulnerable = is_quantum_vulnerable(asset.algorithm_name or "") if asset.algorithm_name else True
    x_plus_y = x + y
    exceeds = x_plus_y > z

    if not vulnerable:
        result = "LOW PRIORITY"
    elif exceeds and x_plus_y - z > 3:
        result = "URGENT MIGRATION"
    elif exceeds:
        result = "PLAN MIGRATION"
    else:
        result = "MONITOR"

    existing = db.query(models.MoscaAssessment).filter(models.MoscaAssessment.asset_id == asset.id).first()
    if existing:
        existing.x_data_lifetime_years = x
        existing.y_migration_time_years = y
        existing.z_threat_horizon_years = z
        existing.x_plus_y = x_plus_y
        existing.exceeds_horizon = exceeds
        existing.result = result
        mosca = existing
    else:
        mosca = models.MoscaAssessment(
            asset_id=asset.id, x_data_lifetime_years=x, y_migration_time_years=y,
            z_threat_horizon_years=z, x_plus_y=x_plus_y, exceeds_horizon=exceeds, result=result,
        )
        db.add(mosca)
    return mosca
