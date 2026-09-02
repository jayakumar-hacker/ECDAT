# PQC Migration Guidance

## Standards used by ECDAT's recommendation engine

- **ML-KEM** (FIPS 203) — the NIST-standardized key-encapsulation
  mechanism, recommended as the replacement for classical
  key-establishment algorithms (RSA encryption/key transport, DH,
  ECDH).
- **ML-DSA** (FIPS 204) — the NIST-standardized signature scheme,
  recommended as the primary replacement for classical signature
  algorithms (RSA signatures, DSA, ECDSA, Ed25519, Ed448).
- **SLH-DSA** (FIPS 205) — a stateless hash-based signature scheme,
  offered as a conservative alternative for long-lived / high-assurance
  signature use cases.
- **Hybrid constructions** — e.g. X25519+ML-KEM for key exchange,
  ECDSA+ML-DSA composite signatures — recommended as an interim/
  risk-mitigating step, since they preserve classical security even
  if a PQC algorithm is later found to have a weakness.

## Why ECDAT distinguishes purpose

A single algorithm family is often used for more than one purpose.
RSA, for example, can be used for **encryption/key transport** or for
**digital signatures** — these require different PQC replacements
(ML-KEM vs ML-DSA respectively) and ECDAT's knowledge base and
recommendation engine (`app/services/recommendation_service.py`)
tag and recommend accordingly. ECDAT never states that "ML-KEM
replaces every RSA use" — see `app/crypto/algorithms.py` and
`app/services/recommendation_service.py` for the purpose-aware
mapping, and docs/limitations.md for the accuracy rules this
follows.

## Symmetric algorithms are not the primary PQC driver

AES-256, AES-256-GCM, and ChaCha20-Poly1305 are **not** flagged for
PQC algorithm replacement. Grover's algorithm gives at most a
quadratic speedup against symmetric ciphers, which AES-256's 256-bit
key size already accommodates with a comfortable margin. ECDAT's
knowledge base explicitly marks these as `quantum_vulnerable: false`
and recommends key-size review (not an algorithm swap) where
applicable — see `knowledge-base/algorithms/algorithms.json`.

## Migration sequencing

1. Inventory (this tool's CBOM output).
2. Prioritize by risk score + Mosca result + business criticality
   (Migration Priorities / Migration Simulator pages).
3. Start with key-establishment and signature algorithms in
   internet-exposed, high-criticality systems (see the demo Payment
   API / Authentication Service scores).
4. Prefer hybrid constructions during the transition period.
5. Re-scan after each migration step to confirm the finding is gone
   and track residual risk.
