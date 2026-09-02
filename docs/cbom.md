# CBOM (Cryptographic Bill of Materials)

## Schema

ECDAT's CBOM is **inspired by** CycloneDX's CBOM concepts (component,
algorithm, purpose, key size, confidence) but is implemented as a
**simplified, ECDAT-specific schema**, not a CycloneDX-conformant
document. The response is explicitly labelled as such:

```json
{
  "bomFormat": "ECDAT-CBOM",
  "specVersion": "0.1-mvp",
  "note": "Simplified schema inspired by CycloneDX CBOM concepts; not a conformant CycloneDX document.",
  "componentCount": 12,
  "components": [
    {
      "id": "...",
      "type": "crypto_usage",
      "algorithm": "RSA-2048",
      "key_size": 2048,
      "purpose": "key_establishment",
      "location": "src/auth.py:12",
      "component": "cryptography",
      "confidence": 0.9,
      "business_asset": "Payment API",
      "quantum_security": "HIGH",
      "risk_score": 62
    }
  ]
}
```

## Why not full CycloneDX

A conformant CycloneDX CBOM document requires a broader set of fields
(component hierarchies, external references, full crypto-asset typing
per the CycloneDX 1.6 crypto extension) than an MVP can responsibly
implement and validate in this timeframe. Rather than emit a document
that *claims* CycloneDX conformance without passing CycloneDX
validation, ECDAT emits a simpler, honestly-labelled schema and
documents the relationship to CycloneDX here. A production follow-up
should map this schema onto the official CycloneDX CBOM JSON schema
and validate against it.

## Export formats

- **JSON** — `GET /api/cbom/export?format=json` — the schema above.
- **CSV** — `GET /api/cbom/export?format=csv` — flattened, one row per
  component, columns: id, type, algorithm, key_size, purpose,
  location, component, confidence, business_asset, quantum_security,
  risk_score.

## Provenance

Every CBOM component is derived from an `Asset` row, which is itself
built from one or more `CryptographicArtefact` rows produced by a
scanner (see docs/architecture.md). Nothing in the CBOM is
hand-entered or fabricated — an empty scan produces an empty CBOM.
