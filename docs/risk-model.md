# Risk Model

**This is the ECDAT scoring model. It is not an official NIST or CVSS
score**, and ECDAT does not claim it is. It is a deterministic,
documented, additive scoring function implemented in
`app/services/risk_service.py:compute_risk_for_asset`.

## Score range and severity bands

| Score | Severity |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Thresholds are configurable via `RISK_LOW_MAX` / `RISK_MEDIUM_MAX` /
`RISK_HIGH_MAX` in `app/core/config.py`.

## Contributing factors (additive, capped at 100)

| Factor | Typical impact | Rationale |
|---|---|---|
| `quantum_vulnerability` | +30 (vulnerable) / +2 (not) | Whether the algorithm is broken by Shor's/Grover's algorithm per the offline knowledge base. |
| `key_size` | +15 | RSA keys below 2048 bits are flagged as additionally weak regardless of quantum considerations. |
| `purpose` | +10 (key establishment / signature) / +3 (encryption) | Key establishment and signatures are the primary Shor's-algorithm targets and the priority for PQC migration. |
| `business_criticality` | +5 to +20 | From the linked `BusinessAsset` (LOW/MEDIUM/HIGH/CRITICAL); defaults to +6 if no business context is linked. |
| `data_sensitivity` | +0 to +18 | PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED from the linked `BusinessAsset`. |
| `internet_exposure` | +12 | If the linked `BusinessAsset.internet_exposed` is true. |
| `detection_confidence` | informational only (+0) | Surfaces low-confidence findings for manual review without silently inflating or deflating the numeric score. |

Every `RiskAssessment.factors` array itemizes exactly which factors
fired and their impact, so a score is always explainable, not a black
box.

## Known limitations of this model

- It is additive rather than probabilistic; it does not model
  interactions between factors (e.g. a CRITICAL system with a
  low-confidence finding is not down-weighted beyond the flat
  `detection_confidence` note).
- It does not incorporate any external threat intelligence or
  CVE data (none is fabricated either — see docs/limitations.md).
- Business context factors default to a fixed value when no
  `BusinessAsset` is linked, which under-scores unlinked assets
  relative to their true organizational risk. Linking scan findings
  to business assets (via the demo path-based matching in
  `scripts/seed_demo.py` and `risk_service._match_business_asset`, or
  manually) improves accuracy.
