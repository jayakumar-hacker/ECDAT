"""
Migration prioritization and simulation.

build_migration_plan_for_asset(): derives a CRITICAL/HIGH/MEDIUM/LOW
priority from the already-computed risk score + Mosca result + business
context, and records rationale, blockers, and affected dependencies.

simulate_migration(): a comparison table between current and proposed
state. Never fabricates benchmark numbers - fields default to
"Not measured" unless the caller supplies "user_supplied" values.
"""
from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import get_algorithm


def _priority_from_score_and_mosca(score: int, mosca_result: str) -> str:
    if mosca_result == "URGENT MIGRATION" or score >= 75:
        return "CRITICAL"
    if mosca_result == "PLAN MIGRATION" or score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_migration_plan_for_asset(db: Session, asset: models.Asset) -> models.MigrationPlan | None:
    risk = asset.risk_assessment
    mosca = asset.mosca_assessment
    rec = asset.recommendation
    if not risk:
        return None

    priority = _priority_from_score_and_mosca(risk.score, mosca.result if mosca else "MONITOR")

    blockers = []
    algo_kb = get_algorithm(asset.algorithm_name or "") if asset.algorithm_name else None
    if algo_kb and algo_kb.get("migration_complexity") == "HIGH":
        blockers.append("High migration complexity per knowledge base (protocol/ecosystem support still maturing).")
    if asset.business_asset and asset.business_asset.internet_exposed:
        blockers.append("Internet-exposed system requires coordinated rollout to avoid interoperability breaks.")
    if not blockers:
        blockers.append("No major blockers identified beyond standard testing/rollout.")

    # affected dependencies: libraries in the same scan referencing this algorithm
    affected = []
    if asset.scan_id and asset.algorithm_name:
        libs = db.query(models.Library).filter(models.Library.scan_id == asset.scan_id).all()
        for lib in libs:
            if asset.algorithm_name in (lib.known_algorithms or []):
                affected.append(lib.name)

    rationale = f"Risk score {risk.score} ({risk.severity})."
    if mosca:
        rationale += f" Mosca: X(data lifetime)+Y(migration time) = {mosca.x_plus_y:.1f}y vs Z(threat horizon) = {mosca.z_threat_horizon_years:.1f}y -> {mosca.result}."

    existing = db.query(models.MigrationPlan).filter(models.MigrationPlan.asset_id == asset.id).first()
    values = dict(
        priority=priority,
        rationale=rationale,
        blockers=blockers,
        replacement=rec.recommended_algorithm if rec else "Not yet analyzed",
        affected_dependencies=affected,
        risk_before=risk.score,
        risk_after_estimate="Estimated",
    )
    if existing:
        for k, v in values.items():
            setattr(existing, k, v)
        return existing
    plan = models.MigrationPlan(asset_id=asset.id, **values)
    db.add(plan)
    return plan


def build_migration_plans_for_scan(db: Session, scan_id: str):
    assets = db.query(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    for asset in assets:
        build_migration_plan_for_asset(db, asset)
    db.commit()


def simulate_migration(current_algorithm: str, proposed_algorithm: str, user_supplied: dict | None = None) -> dict:
    user_supplied = user_supplied or {}
    current_kb = get_algorithm(current_algorithm) or {}
    proposed_kb = get_algorithm(proposed_algorithm) or {}

    def field(name, default="Not measured"):
        return user_supplied.get(name, default)

    return {
        "current": {
            "algorithm": current_algorithm,
            "quantum_vulnerable": current_kb.get("quantum_vulnerable", True),
            "classical_security_bits": current_kb.get("classical_security_bits"),
        },
        "proposed": {
            "algorithm": proposed_algorithm,
            "quantum_vulnerable": proposed_kb.get("quantum_vulnerable", False) if proposed_kb else "Unknown - not in knowledge base",
        },
        "comparison": {
            "security": "Proposed algorithm is not classically broken by Shor's algorithm" if not proposed_kb.get("quantum_vulnerable", True) else "Not measured",
            "quantum_resistance": "Improved (PQC/hybrid)" if proposed_algorithm != current_algorithm else "Unchanged",
            "compatibility": field("compatibility"),
            "latency": field("latency"),
            "computational_overhead": field("computational_overhead"),
            "migration_complexity": current_kb.get("migration_complexity", "Estimated"),
            "dependency_impact": field("dependency_impact"),
        },
    }
