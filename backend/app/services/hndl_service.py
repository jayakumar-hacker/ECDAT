"""
Harvest-now-decrypt-later (HNDL) lens.

A read-only, derived view over existing Asset + BusinessAsset rows that
flags assets at risk of "harvest now, decrypt later": an attacker captures
encrypted data in transit today, stores it, and decrypts it offline once a
cryptographically-relevant quantum computer (or any future key-recovery
capability) makes the key exchange breakable.

An asset is flagged `hndl_exposed` when ALL of the following hold:

  (a) the asset's traffic is internet-exposed OR captured-in-transit
      (deterministic heuristics over BusinessAsset.internet_exposed and
      transport-crypto protocol/library hints),
  (b) the associated data has a long shelf-life, using the existing
      BusinessAsset.data_retention_years field as the shelf-life proxy
      (configurable threshold, default 10 years), and
  (c) the asset uses quantum-vulnerable key establishment.

This is purely additive and deterministic: it reads existing scan/business
context, writes only the derived `hndl_exposed` / `hndl_reason` columns on
the Asset row, and never executes or modifies scanned code.
"""
from typing import Any

from sqlalchemy.orm import Session
from app.models import models
from app.crypto.knowledge_base import get_algorithm, is_quantum_vulnerable
from app.core.config import settings

# Transport-crypto hints used to recognise "captured in transit" usage when
# the asset is not directly linked to an internet-exposed BusinessAsset.
# Kept small and exact to avoid false positives (a protocol/library name is
# only treated as transit evidence when it literally names a transport layer).
TRANSIT_HINTS = ("tls", "ssl", "ssh", "dtls", "quic", "https", "starttls")

# Key-establishment category fragment used in the ECDAT knowledge base
# (e.g. "key_establishment_or_signature" for RSA/ECDH).
KEY_ESTABLISHMENT_CATEGORY = "key_establishment"


def resolve_threshold(shelf_life_threshold_years: int | None) -> int:
    """Resolves the effective shelf-life threshold (config default when None)."""
    if shelf_life_threshold_years is None:
        return settings.HNDL_SHELF_LIFE_THRESHOLD_YEARS
    return shelf_life_threshold_years
def _exposure_factor(asset: models.Asset) -> tuple[bool, str]:
    """(a) internet-exposed OR captured-in-transit. Returns (matched, description)."""
    ba = asset.business_asset
    if ba and ba.internet_exposed:
        return True, "internet-exposed"

    # Search transport-crypto hints across the asset's component / location
    # (the component captures a library or protocol name from the raw artefact).
    haystacks = [asset.component or "", asset.location or ""]
    for hint in TRANSIT_HINTS:
        for text in haystacks:
            if hint in text.lower():
                return True, f"captured-in-transit ({hint.upper()} transport detected)"
    return False, "not internet-exposed / no transit evidence detected"


def _shelf_life_factor(asset: models.Asset, threshold: int) -> tuple[bool, str]:
    """(b) long data shelf-life, using existing data_retention_years as the proxy."""
    ba = asset.business_asset
    if not ba:
        return False, "no shelf-life context (asset not linked to a business asset)"
    years = ba.data_retention_years or 0
    sensitivity = ba.data_sensitivity or "UNKNOWN"
    if years >= threshold:
        return True, f"long data shelf-life ({years} years, {sensitivity})"
    return False, f"data shelf-life ({years}y) below the {threshold}y HNDL threshold"


def _quantum_kex_factor(asset: models.Asset) -> tuple[bool, str]:
    """(c) quantum-vulnerable key establishment."""
    name = asset.algorithm_name or ""
    algo = get_algorithm(name) if name else None
    category = (algo or {}).get("category", "") or ""
    is_key_establishment = (
        KEY_ESTABLISHMENT_CATEGORY in category.lower()
        or (asset.purpose or "") == "key_establishment"
    )
    if not is_key_establishment:
        return False, f"{name or 'unknown'} is not key establishment"
    if is_quantum_vulnerable(name):
        return True, f"quantum-vulnerable key exchange ({name})"
    return False, f"{name} key exchange is not primarily quantum-vulnerable"


def _build_reason(exposure: str, qv: str, shelf: str) -> str:
    return (
        f"{exposure} with {qv} and {shelf} "
        "\u2014 remediation deadline is effectively now, not Q-Day."
    )


def _to_record(asset: models.Asset, threshold: int,
               exposure: str, qv: str, shelf: str, reason: str) -> dict[str, Any]:
    ba = asset.business_asset
    return {
        "asset_id": asset.id,
        "scan_id": asset.scan_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "algorithm_name": asset.algorithm_name,
        "purpose": asset.purpose,
        "key_size": asset.key_size,
        "component": asset.component,
        "location": asset.location,
        "business_asset": ba.name if ba else None,
        "internet_exposed": bool(ba and ba.internet_exposed),
        "business_criticality": (ba.business_criticality if ba else None),
        "data_sensitivity": (ba.data_sensitivity if ba else None),
        "data_retention_years": (ba.data_retention_years if ba else None),
        "hndl_exposed": True,
        "hndl_reason": reason,
        "exposure_factor": exposure,
        "quantum_kex_factor": qv,
        "shelf_life_factor": shelf,
    }


def evaluate_hndl(
    db: Session,
    scan_id: str | None = None,
    shelf_life_threshold_years: int | None = None,
) -> list[dict]:
    """
    Evaluates the HNDL lens over assets (optionally for one scan).

    Deterministic and read-only over scan data. For each asset it computes the
    three factors, persists the derived `hndl_exposed` / `hndl_reason` columns
    (additive), and returns the matching records with a human-readable reason.
    """
    threshold = resolve_threshold(shelf_life_threshold_years)
    q = db.query(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    assets = q.all()

    matched: list[dict] = []
    for asset in assets:
        exposed, exp_desc = _exposure_factor(asset)
        shelf, shelf_desc = _shelf_life_factor(asset, threshold)
        qv, qv_desc = _quantum_kex_factor(asset)

        if exposed and shelf and qv:
            reason = _build_reason(exp_desc, qv_desc, shelf_desc)
            asset.hndl_exposed = True
            asset.hndl_reason = reason
            matched.append(_to_record(asset, threshold, exp_desc, qv_desc, shelf_desc, reason))
        else:
            asset.hndl_exposed = False
            asset.hndl_reason = ""

    db.commit()
    return matched
    category = (algo or {}).get("category", "") or ""
    is_key_establishment = (
        KEY_ESTABLISHMENT_CATEGORY in category.lower()
        or (asset.purpose or "") == "key_establishment"
    )
    if not is_key_establishment:
        return False, f"{name or 'unknown'} is not key establishment"
    if is_quantum_vulnerable(name):
        return True, f"quantum-vulnerable key exchange ({name})"
    return False, f"{name} key exchange is not primarily quantum-vulnerable"