from app.models import models
from app.services.risk_service import compute_risk_for_asset, compute_mosca_for_asset
from app.services.recommendation_service import build_recommendation_for_asset
from app.services.migration_service import build_migration_plan_for_asset, simulate_migration, _priority_from_score_and_mosca


def test_priority_mapping():
    assert _priority_from_score_and_mosca(80, "MONITOR") == "CRITICAL"
    assert _priority_from_score_and_mosca(60, "MONITOR") == "HIGH"
    assert _priority_from_score_and_mosca(30, "MONITOR") == "MEDIUM"
    assert _priority_from_score_and_mosca(10, "MONITOR") == "LOW"
    assert _priority_from_score_and_mosca(10, "URGENT MIGRATION") == "CRITICAL"


def test_migration_plan_built_from_asset(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.flush()
    asset = models.Asset(scan_id=scan.id, algorithm_name="RSA-1024", key_size=1024,
                          purpose="key_establishment", name="RSA-1024 test", confidence=0.9)
    db_session.add(asset)
    db_session.flush()

    compute_risk_for_asset(db_session, asset)
    compute_mosca_for_asset(db_session, asset, x_override=15, y_override=3, z_override=10)
    build_recommendation_for_asset(db_session, asset)
    db_session.commit()

    plan = build_migration_plan_for_asset(db_session, asset)
    db_session.commit()
    assert plan is not None
    assert plan.priority in ("CRITICAL", "HIGH")
    assert plan.replacement != ""
    assert len(plan.blockers) > 0


def test_migration_plan_none_without_risk(db_session):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db_session.add(scan)
    db_session.flush()
    asset = models.Asset(scan_id=scan.id, algorithm_name="RSA-2048", name="no risk yet", confidence=0.9)
    db_session.add(asset)
    db_session.flush()
    plan = build_migration_plan_for_asset(db_session, asset)
    assert plan is None


def test_simulate_migration_no_fabricated_benchmarks():
    result = simulate_migration("RSA-2048", "ML-KEM")
    assert result["comparison"]["latency"] == "Not measured"
    assert result["comparison"]["computational_overhead"] == "Not measured"


def test_simulate_migration_user_supplied_values_respected():
    result = simulate_migration("RSA-2048", "ML-KEM", user_supplied={"latency": "12ms (user supplied benchmark)"})
    assert result["comparison"]["latency"] == "12ms (user supplied benchmark)"
