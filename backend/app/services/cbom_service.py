"""
CBOM (Cryptographic Bill of Materials) generation.

Schema is inspired by CycloneDX's CBOM concepts (see docs/cbom.md and
docs/references.md) but implemented as a simplified, documented ECDAT
schema for the MVP rather than a full CycloneDX-conformant document.
"""
import csv
import io
from sqlalchemy.orm import Session
from app.models import models


def generate_cbom(db: Session, scan_id: str | None = None) -> dict:
    q = db.query(models.Asset)
    if scan_id:
        q = q.filter(models.Asset.scan_id == scan_id)
    assets = q.all()

    components = []
    for asset in assets:
        risk = asset.risk_assessment
        components.append({
            "id": asset.id,
            "type": asset.asset_type,
            "algorithm": asset.algorithm_name,
            "key_size": asset.key_size,
            "purpose": asset.purpose,
            "location": asset.location,
            "component": asset.component,
            "confidence": asset.confidence,
            "business_asset": asset.business_asset.name if asset.business_asset else None,
            "classical_security": "See knowledge base",
            "quantum_security": risk.severity if risk else "not_assessed",
            "risk_score": risk.score if risk else None,
        })

    return {
        "bomFormat": "ECDAT-CBOM",
        "specVersion": "0.1-mvp",
        "note": "Simplified schema inspired by CycloneDX CBOM concepts; not a conformant CycloneDX document.",
        "componentCount": len(components),
        "components": components,
    }


def cbom_to_csv(cbom: dict) -> str:
    output = io.StringIO()
    fieldnames = ["id", "type", "algorithm", "key_size", "purpose", "location", "component",
                  "confidence", "business_asset", "quantum_security", "risk_score"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for c in cbom["components"]:
        writer.writerow({k: c.get(k, "") for k in fieldnames})
    return output.getvalue()
