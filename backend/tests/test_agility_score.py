import tempfile
import os
from app.models import models
from app.services.risk_service import compute_risk_for_asset, compute_agility_for_asset, build_assets_from_artefacts
from app.services.migration_service import build_migration_plan_for_asset
from app.services.scan_service import run_scan


def test_agility_score_config_vs_constant(db_session):
    # Create scan
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Asset 1: Config-driven algorithm (nginx.conf TLS 1.2)
    asset_config = models.Asset(
        scan_id=scan.id,
        name="TLS 1.2 in nginx.conf",
        asset_type="config",
        algorithm_name="TLS 1.2",
        location="/etc/nginx/nginx.conf:10",
        purpose="protocol",
    )
    db_session.add(asset_config)
    db_session.flush()

    art_config = models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_config.id,
        artefact_type="config", algorithm="TLS 1.2",
        file="/etc/nginx/nginx.conf", line=10,
        purpose="protocol", evidence="ssl_protocols TLSv1.2",
    )
    db_session.add(art_config)

    # Asset 2: Compile-time constant in source code (direct RSA-1024 instantiation)
    asset_source = models.Asset(
        scan_id=scan.id,
        name="RSA-1024 in payment.py",
        asset_type="crypto_usage",
        algorithm_name="RSA",
        key_size=1024,
        location="payment.py:42",
        purpose="key_establishment",
    )
    db_session.add(asset_source)
    db_session.flush()

    art_source = models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_source.id,
        artefact_type="source", algorithm="RSA",
        file="payment.py", line=42, key_size=1024,
        purpose="key_establishment", evidence="key = RSA.generate(1024)",
    )
    db_session.add(art_source)
    db_session.commit()

    # Compute risk and agility
    compute_risk_for_asset(db_session, asset_config)
    compute_risk_for_asset(db_session, asset_source)

    # Config-driven asset should have significantly higher agility than hardcoded source constant
    assert asset_config.agility_score > asset_source.agility_score
    assert asset_config.agility_score >= 80  # config (50) + lockfile/clean (25) + single site (25)
    assert asset_source.agility_score <= 60  # constant (15) + ...


def test_agility_score_version_pinning_impact(db_session):
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Pinned dependency
    dep_pinned = models.Dependency(
        scan_id=scan.id, name="cryptography", version="42.0.5",
        ecosystem="pypi", source_file="poetry.lock", crypto_related=True,
    )
    # Floating dependency
    dep_floating = models.Dependency(
        scan_id=scan.id, name="pycrypto", version="unknown",
        ecosystem="pypi", source_file="requirements.txt", crypto_related=True,
    )
    db_session.add_all([dep_pinned, dep_floating])
    db_session.flush()

    asset_pinned = models.Asset(
        scan_id=scan.id, name="AES-256 in cryptography",
        asset_type="library", algorithm_name="AES-256", component="cryptography",
    )
    asset_floating = models.Asset(
        scan_id=scan.id, name="AES-128 in pycrypto",
        asset_type="library", algorithm_name="AES-128", component="pycrypto",
    )
    db_session.add_all([asset_pinned, asset_floating])
    db_session.flush()

    art_pinned = models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_pinned.id,
        artefact_type="dependency", algorithm="AES-256", library="cryptography",
    )
    art_floating = models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_floating.id,
        artefact_type="dependency", algorithm="AES-128", library="pycrypto",
    )
    db_session.add_all([art_pinned, art_floating])
    db_session.commit()

    compute_risk_for_asset(db_session, asset_pinned)
    compute_risk_for_asset(db_session, asset_floating)

    assert asset_pinned.agility_score > asset_floating.agility_score


def test_agility_score_call_sites_blast_radius(db_session):
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Asset with 1 call site
    asset_single = models.Asset(
        scan_id=scan.id, name="SHA-256 in auth.py",
        asset_type="crypto_usage", algorithm_name="SHA-256", location="auth.py:10",
    )
    db_session.add(asset_single)
    db_session.flush()
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_single.id,
        artefact_type="source", algorithm="SHA-256", file="auth.py", line=10,
    ))

    # Asset with 12 call sites (broad blast radius)
    asset_widespread = models.Asset(
        scan_id=scan.id, name="SHA-256 in legacy.py",
        asset_type="crypto_usage", algorithm_name="SHA-256", location="legacy.py:1",
    )
    db_session.add(asset_widespread)
    db_session.flush()
    for i in range(1, 13):
        db_session.add(models.CryptographicArtefact(
            scan_id=scan.id, asset_id=asset_widespread.id,
            artefact_type="source", algorithm="SHA-256", file="legacy.py", line=i * 5,
        ))
    db_session.commit()

    compute_risk_for_asset(db_session, asset_single)
    compute_risk_for_asset(db_session, asset_widespread)

    assert asset_single.agility_score > asset_widespread.agility_score


def test_migration_priority_surfaces_high_risk_low_agility(db_session):
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # Asset A: High Risk + Low Agility (e.g. hardcoded RSA-1024, multiple call sites)
    asset_a = models.Asset(
        scan_id=scan.id, name="RSA-1024 in core.py",
        asset_type="crypto_usage", algorithm_name="RSA", key_size=1024,
        purpose="key_establishment", location="core.py:5",
    )
    db_session.add(asset_a)
    db_session.flush()
    for i in range(5):
        db_session.add(models.CryptographicArtefact(
            scan_id=scan.id, asset_id=asset_a.id,
            artefact_type="source", algorithm="RSA", file="core.py", line=i + 1, key_size=1024,
        ))

    # Asset B: High Risk + High Agility (e.g. RSA-2048 in config or single provider site)
    asset_b = models.Asset(
        scan_id=scan.id, name="RSA-2048 in gateway.conf",
        asset_type="config", algorithm_name="RSA", key_size=2048,
        purpose="key_establishment", location="gateway.conf:1",
    )
    db_session.add(asset_b)
    db_session.flush()
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=asset_b.id,
        artefact_type="config", algorithm="RSA", file="gateway.conf", line=1, key_size=2048,
    ))
    db_session.commit()

    compute_risk_for_asset(db_session, asset_a)
    compute_risk_for_asset(db_session, asset_b)

    # Asset A should have lower agility than Asset B
    assert asset_a.agility_score < asset_b.agility_score

    # Derived migration priority = risk_score / agility_score
    # Asset A has both higher risk (weak key 1024) AND lower agility, so its migration priority must be higher
    assert asset_a.migration_priority > asset_b.migration_priority


def test_api_priority_view(client, admin_token, db_session):
    scan = models.Scan(target="/tmp/test", status="completed")
    db_session.add(scan)
    db_session.flush()

    # High-risk, low-agility asset
    a1 = models.Asset(
        scan_id=scan.id, name="Hardcoded RSA-1024",
        asset_type="crypto_usage", algorithm_name="RSA", key_size=1024,
        purpose="key_establishment", location="auth.py:1",
    )
    # Low-risk, high-agility asset
    a2 = models.Asset(
        scan_id=scan.id, name="Configured AES-256",
        asset_type="config", algorithm_name="AES-256", key_size=256,
        purpose="encryption", location="app.conf:1",
    )
    db_session.add_all([a1, a2])
    db_session.flush()

    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a1.id, artefact_type="source", algorithm="RSA", file="auth.py", key_size=1024,
    ))
    db_session.add(models.CryptographicArtefact(
        scan_id=scan.id, asset_id=a2.id, artefact_type="config", algorithm="AES-256", file="app.conf",
    ))
    db_session.commit()

    compute_risk_for_asset(db_session, a1)
    compute_risk_for_asset(db_session, a2)
    db_session.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get(f"/api/migration-plans/priority-view?scan_id={scan.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # First item must be the highest migration priority
    assert data[0]["asset_name"] == "Hardcoded RSA-1024"
    assert data[0]["migration_priority"] >= data[1]["migration_priority"]

    # Also check /api/assets?sort=migration_priority
    resp_assets = client.get(f"/api/assets?scan_id={scan.id}&sort=migration_priority", headers=headers)
    assert resp_assets.status_code == 200
    assets_data = resp_assets.json()
    assert assets_data[0]["name"] == "Hardcoded RSA-1024"
    assert "agility_score" in assets_data[0]
    assert "migration_priority" in assets_data[0]
