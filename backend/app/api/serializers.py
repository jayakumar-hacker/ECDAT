from app.models import models


def dt(value):
    return value.isoformat() if value else None


def serialize_scan(s: models.Scan) -> dict:
    return {
        "id": s.id, "target": s.target, "target_type": s.target_type,
        "scanners_requested": s.scanners_requested, "status": s.status,
        "start_time": dt(s.start_time), "end_time": dt(s.end_time),
        "files_scanned": s.files_scanned, "artefacts_found": s.artefacts_found,
        "since_git_ref": s.since_git_ref,
        "policy_status": s.policy_status,
        "policy_violations": s.policy_violations,
        "errors": s.errors, "created_at": dt(s.created_at),
    }


def serialize_asset(a: models.Asset) -> dict:
    return {
        "id": a.id, "scan_id": a.scan_id, "name": a.name, "asset_type": a.asset_type,
        "algorithm_name": a.algorithm_name, "key_size": a.key_size, "purpose": a.purpose,
        "component": a.component, "location": a.location, "confidence": a.confidence,
        "agility_score": a.agility_score,
        "agility_factors": a.agility_factors,
        "migration_priority": a.migration_priority,
        "hndl_exposed": bool(a.hndl_exposed),
        "hndl_reason": a.hndl_reason or "",
        "business_asset": a.business_asset.name if a.business_asset else None,
        "risk": serialize_risk(a.risk_assessment) if a.risk_assessment else None,
        "mosca": serialize_mosca(a.mosca_assessment) if a.mosca_assessment else None,
        "recommendation": serialize_recommendation(a.recommendation) if a.recommendation else None,
    }


def serialize_risk(r: models.RiskAssessment) -> dict:
    return {
        "id": r.id, "asset_id": r.asset_id, "score": r.score, "severity": r.severity, "factors": r.factors,
        "agility_score": r.agility_score, "migration_priority": r.migration_priority,
    }


def serialize_mosca(m: models.MoscaAssessment) -> dict:
    return {
        "id": m.id, "asset_id": m.asset_id,
        "x_data_lifetime_years": m.x_data_lifetime_years,
        "y_migration_time_years": m.y_migration_time_years,
        "z_threat_horizon_years": m.z_threat_horizon_years,
        "x_plus_y": m.x_plus_y, "exceeds_horizon": m.exceeds_horizon, "result": m.result,
    }


def serialize_recommendation(r: models.Recommendation) -> dict:
    return {
        "id": r.id, "asset_id": r.asset_id, "current_algorithm": r.current_algorithm,
        "category": r.category, "recommended_algorithm": r.recommended_algorithm,
        "recommended_type": r.recommended_type, "hybrid_option": r.hybrid_option,
        "reason": r.reason, "compatibility": r.compatibility,
        "migration_complexity": r.migration_complexity, "priority": r.priority, "confidence": r.confidence,
    }


def serialize_migration_plan(p: models.MigrationPlan) -> dict:
    return {
        "id": p.id, "asset_id": p.asset_id, "priority": p.priority, "rationale": p.rationale,
        "blockers": p.blockers, "replacement": p.replacement,
        "affected_dependencies": p.affected_dependencies,
        "risk_before": p.risk_before, "risk_after_estimate": p.risk_after_estimate,
        "agility_score": p.agility_score,
        "migration_priority": p.migration_priority_score,
    }


def serialize_certificate(c: models.Certificate) -> dict:
    return {
        "id": c.id, "file": c.file, "subject": c.subject, "issuer": c.issuer,
        "serial_number": c.serial_number, "valid_from": dt(c.valid_from), "valid_until": dt(c.valid_until),
        "expired": c.expired, "days_remaining": c.days_remaining,
        "public_key_algorithm": c.public_key_algorithm, "key_size": c.key_size,
        "signature_algorithm": c.signature_algorithm, "san": c.san,
        "weak_key": c.weak_key, "weak_signature": c.weak_signature, "parse_error": c.parse_error,
    }


def serialize_library(l: models.Library) -> dict:
    return {
        "id": l.id, "name": l.name, "version": l.version, "ecosystem": l.ecosystem,
        "source_file": l.source_file, "crypto_capable": l.crypto_capable,
        "known_algorithms": l.known_algorithms, "confidence": l.confidence,
    }
