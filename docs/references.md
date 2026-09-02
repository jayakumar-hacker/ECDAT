# Research References

ECDAT's design decisions are informed by the following authoritative
sources. This list is not exhaustive of all PQC literature, and no
reference below is invented — each maps directly to a design choice
described elsewhere in `docs/`.

- **NIST FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism
  Standard (ML-KEM). Basis for ECDAT's key-establishment PQC
  recommendations.
- **NIST FIPS 204** — Module-Lattice-Based Digital Signature Standard
  (ML-DSA). Basis for ECDAT's signature PQC recommendations.
- **NIST FIPS 205** — Stateless Hash-Based Digital Signature Standard
  (SLH-DSA). Basis for ECDAT's conservative/long-lived signature
  recommendation.
- **NIST IR 8547** — Transition to Post-Quantum Cryptography Standards
  (initial public draft and successors). Basis for ECDAT's general
  migration-sequencing guidance in `docs/pqc-migration.md`.
- **NIST SP 800-208** — Recommendation for Stateful Hash-Based
  Signature Schemes (background for hash-based signature discussion).
- **CycloneDX CBOM** (OWASP CycloneDX project's Cryptographic Bill of
  Materials extension) — conceptual basis for ECDAT's simplified CBOM
  schema; see `docs/cbom.md` for the explicit divergence from full
  conformance.
- **ETSI TR 103 619** — Migration strategies and recommendations to
  Quantum Safe schemes. Referenced for general migration-strategy
  framing.
- **IETF drafts on hybrid key exchange in TLS 1.3** (e.g.
  draft-ietf-tls-hybrid-design and related work defining groups such
  as X25519MLKEM768) — basis for the hybrid TLS/SSH recommendations
  in `knowledge-base/algorithms/algorithms.json`.
- **Mosca, M. (2018), "Cybersecurity in an Era with Quantum
  Computers: Will We Be Ready?"**, IEEE Security & Privacy — origin
  of the X+Y>Z framing implemented in `docs/mosca.md`.
- **Shor, P. (1997), "Polynomial-Time Algorithms for Prime
  Factorization and Discrete Logarithms on a Quantum Computer"** —
  the algorithm underlying why RSA/DSA/ECDSA/ECDH/DH are classified
  as quantum-vulnerable.
- **Grover, L. (1996), "A Fast Quantum Mechanical Algorithm for
  Database Search"** — the algorithm underlying the quadratic
  security-margin reduction applied to symmetric ciphers and hash
  functions (not treated as "broken") in the knowledge base.

For anything not covered above, treat ECDAT's output as a starting
point for further research, not a substitute for consulting current
NIST/ETSI/IETF publications directly — see `docs/limitations.md`.
