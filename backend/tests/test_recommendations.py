from app.models import models
from app.services.recommendation_service import build_recommendation_for_asset


def _asset(db, algorithm, purpose):
    scan = models.Scan(target="/tmp/fake", status="completed")
    db.add(scan)
    db.flush()
    asset = models.Asset(scan_id=scan.id, algorithm_name=algorithm, purpose=purpose,
                          name=f"{algorithm} test", confidence=0.8)
    db.add(asset)
    db.flush()
    return asset


def test_rsa_key_establishment_recommends_ml_kem(db_session):
    asset = _asset(db_session, "RSA-2048", "key_establishment")
    rec = build_recommendation_for_asset(db_session, asset)
    db_session.commit()
    assert rec is not None
    assert "ML-KEM" in rec.recommended_algorithm
    assert rec.category == "key_establishment"
    assert rec.priority == "HIGH"


def test_ecdsa_signature_recommends_ml_dsa(db_session):
    asset = _asset(db_session, "ECDSA", "digital_signature")
    rec = build_recommendation_for_asset(db_session, asset)
    db_session.commit()
    assert "ML-DSA" in rec.recommended_algorithm
    assert rec.category == "signature"


def test_aes256_recommendation_is_low_priority(db_session):
    asset = _asset(db_session, "AES-256", "encryption")
    rec = build_recommendation_for_asset(db_session, asset)
    db_session.commit()
    assert rec.priority == "LOW"
    assert "N/A" in rec.recommended_algorithm


def test_recommendation_distinguishes_signature_from_key_establishment(db_session):
    """RSA used for signatures should not be told to migrate to a key-establishment-only
    algorithm without qualification - the category must be correctly tagged."""
    sig_asset = _asset(db_session, "RSA-2048", "digital_signature")
    ke_asset = _asset(db_session, "RSA-2048", "key_establishment")
    sig_rec = build_recommendation_for_asset(db_session, sig_asset)
    ke_rec = build_recommendation_for_asset(db_session, ke_asset)
    db_session.commit()
    assert sig_rec.category == "signature"
    assert ke_rec.category == "key_establishment"


def test_unknown_algorithm_returns_none(db_session):
    asset = _asset(db_session, "SomeMadeUpCipher", "encryption")
    rec = build_recommendation_for_asset(db_session, asset)
    assert rec is None
