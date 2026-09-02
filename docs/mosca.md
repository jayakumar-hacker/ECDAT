# Mosca Analysis

Implements Michele Mosca's "theorem" framing for prioritizing
post-quantum migration, per `app/services/risk_service.py:compute_mosca_for_asset`.

## The inequality

```
X = required confidentiality/security lifetime of the data (years)
Y = time required to migrate the system to quantum-safe crypto (years)
Z = threat horizon — assumed time until a cryptographically relevant
    quantum computer (CRQC) exists (years)

If X + Y > Z, migration should be prioritized now, because the data
will still need protecting after the migration completes, and a CRQC
may exist before that protection is in place.
```

## Result classification

| Condition | Result |
|---|---|
| Algorithm not quantum-vulnerable | `LOW PRIORITY` |
| X+Y > Z by more than 3 years | `URGENT MIGRATION` |
| X+Y > Z (by 3 years or less) | `PLAN MIGRATION` |
| X+Y <= Z | `MONITOR` |

## Configurability

- `Z` (threat horizon) defaults to `DEFAULT_THREAT_HORIZON_YEARS = 10`
  in `app/core/config.py`, but is fully configurable per-asset via
  `POST /api/mosca/simulate` (and the Mosca Analysis page in the
  frontend, which recalculates live).
- `X` (data lifetime) defaults to the linked `BusinessAsset.data_retention_years`.
- `Y` (migration time) defaults to the linked `BusinessAsset.estimated_migration_years`.

## What ECDAT does NOT claim

ECDAT does not predict when a cryptographically relevant quantum
computer will exist. The threat horizon `Z` is an explicit,
user-adjustable assumption, not a forecast. See
`docs/pqc-migration.md` and `docs/references.md` for the NIST/ETSI
guidance this framing is based on.
