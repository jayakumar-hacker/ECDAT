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

        compute_risk_for_asset(db, asset, artefacts=items)
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


def compute_agility_for_asset(
    db: Session,
    asset: models.Asset,
    artefacts: list[models.CryptographicArtefact] | None = None,
    risk_score: int | None = None,
) -> tuple[int, list[dict], float]:
    """
    Computes a deterministic static 0-100 crypto-agility score based on:
    1. Abstraction / Mechanism (15 - 50 pts):
       - Config-driven (sshd_config, nginx/apache, openssl.cnf, java.security, terraform, k8s/cert-manager) -> 50
       - Provider / Interface abstraction (factory, getInstance, wrapper, dependency) -> 35
       - Certificate leaf -> 30
       - Binary/container linkage -> 20
       - Compile-time constant / direct source instantiation -> 15
    2. Version Pinning (5 - 25 pts):
       - Strictly pinned version -> 25
       - Range-pinned / semver floating -> 15
       - Floating / unpinned / unknown -> 5
       - Non-dependency with lockfiles present -> 25 (otherwise 15)
    3. Call-site Blast Radius (3 - 25 pts):
       - 1 call site -> 25
       - 2-4 call sites -> 18
       - 5-10 call sites -> 10
       - >10 call sites -> 3

    Returns (agility_score, agility_factors, migration_priority).
    migration_priority = round(risk_score / max(1.0, float(agility_score)), 2)
    so high-risk + low-agility assets surface first.
    """
    import re
    if artefacts is None:
        artefacts = db.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.asset_id == asset.id
        ).all()

    # 1. Abstraction / Mechanism
    is_config = (
        asset.asset_type == "config"
        or any(a.artefact_type == "config" for a in artefacts)
        or any(
            (a.file or "").endswith((".conf", ".cnf", ".yaml", ".yml", ".tf", ".tfvars", "sshd_config", "java.security"))
            for a in artefacts
        )
        or (asset.location or "").endswith((".conf", ".cnf", ".yaml", ".yml", ".tf", ".tfvars", "sshd_config", "java.security"))
    )

    has_abstraction = any(
        re.search(r"\b(getInstance|Provider|Factory|KeyManager|AlgorithmParameters|KeyAgreement|CipherSuite)\b", a.evidence or "", re.IGNORECASE)
        or a.artefact_type == "dependency"
        for a in artefacts
    )

    is_cert = asset.asset_type == "certificate" or any(a.artefact_type == "certificate" for a in artefacts)
    is_binary_container = any(a.artefact_type in ("binary", "container") for a in artefacts)

    if is_config:
        abs_val = "config_driven"
        abs_score = 50
        abs_detail = "Config-driven: Algorithm is externally configured via configuration file or infrastructure policy (highest agility, no code recompile required)."
    elif has_abstraction:
        abs_val = "interface_provider_abstraction"
        abs_score = 35
        abs_detail = "Provider/Interface abstraction: Algorithm accessed via security provider, factory, or library interface."
    elif is_cert:
        abs_val = "certificate_authority_managed"
        abs_score = 30
        abs_detail = "Certificate-managed: Key and algorithm governed by X.509 certificate renewal lifecycle."
    elif is_binary_container:
        abs_val = "binary_or_container_linkage"
        abs_score = 20
        abs_detail = "Static linkage: Cryptographic capability linked into binary or container base image."
    else:
        abs_val = "compile_time_constant"
        abs_score = 15
        abs_detail = "Compile-time constant: Algorithm is hardcoded or directly instantiated in source code (lowest agility, code change required)."

    # 2. Version Pinning
    dep = None
    if asset.scan_id:
        if asset.component:
            dep = db.query(models.Dependency).filter(
                models.Dependency.scan_id == asset.scan_id,
                models.Dependency.name.ilike(asset.component),
            ).first()
        if not dep and asset.location:
            loc_file = asset.location.split(":")[0]
            dep = db.query(models.Dependency).filter(
                models.Dependency.scan_id == asset.scan_id,
                models.Dependency.source_file == loc_file,
            ).first()

    if dep:
        ver = (dep.version or "").strip()
        ver_lower = ver.lower()
        if ver_lower in ("unknown", "", "*", "latest"):
            pin_val = "floating_unpinned"
            pin_score = 5
            pin_detail = f"Floating version: Dependency {dep.name} is unpinned or unknown ({ver or 'unversioned'})."
        elif any(sym in ver for sym in ("^", "~", ">", "<")) and not ver.startswith("==") and not ver.startswith("="):
            pin_val = "range_pinned"
            pin_score = 15
            pin_detail = f"Range-pinned: Dependency {dep.name} uses floating range specifier ({ver})."
        else:
            pin_val = "strictly_pinned"
            pin_score = 25
            pin_detail = f"Strictly pinned: Dependency {dep.name} has fixed pinned version ({ver})."
    else:
        has_lockfiles = False
        if asset.scan_id:
            has_lockfiles = db.query(models.Dependency).filter(
                models.Dependency.scan_id == asset.scan_id,
                models.Dependency.is_transitive.is_(True),
            ).first() is not None
        if has_lockfiles:
            pin_val = "repo_lockfile_managed"
            pin_score = 25
            pin_detail = "Environment dependencies are managed and locked via repository lockfile."
        else:
            pin_val = "untracked_version"
            pin_score = 15
            pin_detail = "Non-dependency asset without explicit repository-wide dependency lockfile."

    # 3. Call-site Blast Radius
    call_sites = len(artefacts) if artefacts else 1
    if call_sites <= 1:
        site_val = "single_site"
        site_score = 25
        site_detail = "1 direct call site (isolated, single point of migration)."
    elif call_sites <= 4:
        site_val = "few_sites"
        site_score = 18
        site_detail = f"{call_sites} direct call sites (moderate localization)."
    elif call_sites <= 10:
        site_val = "multiple_sites"
        site_score = 10
        site_detail = f"{call_sites} direct call sites (multiple touch points across codebase)."
    else:
        site_val = "widespread_sites"
        site_score = 3
        site_detail = f"{call_sites} direct call sites (high blast radius across codebase)."

    total_agility = min(100, max(0, abs_score + pin_score + site_score))
    agility_factors = [
        {"dimension": "abstraction", "value": abs_val, "score": abs_score, "detail": abs_detail},
        {"dimension": "version_pinning", "value": pin_val, "score": pin_score, "detail": pin_detail},
        {"dimension": "call_sites", "value": site_val, "count": call_sites, "score": site_score, "detail": site_detail},
    ]

    effective_risk_score = risk_score if risk_score is not None else (asset.risk_assessment.score if asset.risk_assessment else 0)
    migration_priority = round(float(effective_risk_score) / max(1.0, float(total_agility)), 2)

    return total_agility, agility_factors, migration_priority


def compute_risk_for_asset(
    db: Session,
    asset: models.Asset,
    artefacts: list[models.CryptographicArtefact] | None = None,
) -> models.RiskAssessment:
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

    # Compute crypto-agility score and derived migration priority
    agility_score, agility_factors, migration_priority = compute_agility_for_asset(
        db, asset, artefacts=artefacts, risk_score=score
    )
    risk.agility_score = agility_score
    risk.migration_priority = migration_priority
    asset.agility_score = agility_score
    asset.agility_factors = agility_factors
    asset.migration_priority = migration_priority

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
