# Expected Demo Scan Results (reference, not enforced)

Running a full scan (`target: "demo"`, all 5 scanners) against
`demo-data/repositories/acme-corp` should surface, among other things:

- **RSA** at multiple key sizes: 1024 (legacy-app), 2048 (payment-api,
  hr-portal), 4096 (auth-service).
- **ECDSA** (auth-service, public-website), **ECDH** (auth-service),
  **Ed25519** (auth-service).
- **AES-128** (auth-service, legacy scope), **AES-256/AES-GCM**
  (payment-api, hr-portal).
- **ChaCha20-Poly1305** (iot-service).
- **MD5** and **3DES** and **RSA-1024** (legacy-app — intentionally
  weak/legacy).
- **SHA-1** and **DES** (hr-portal — intentionally weak/legacy).
- **SHA-256** (public-website, iot-service, payment-api).
- **TLS 1.3** references (payment-api, public-website).
- 4 certificates: a healthy RSA-2048/SHA-256 cert, a weak
  RSA-1024/SHA-1 near-expiry cert, a healthy ECDSA P-256/SHA-256 cert,
  and an already-expired RSA-2048 cert.
- Crypto-capable dependencies: `cryptography`, `pycryptodome`,
  `jsonwebtoken`, `node-forge`, `bcprov-jdk18on`,
  `spring-security-crypto`, `golang.org/x/crypto`, `ring`.
- Container findings: `openssl`/`libssl-dev` packages referenced in
  the payment-api and legacy-app Dockerfiles.

Exact counts will vary slightly as the pattern-matching rules evolve
(see `docs/limitations.md`) — this file is a sanity-check reference
for manual review, not an automated golden-file test. Automated
coverage of the underlying detection logic lives in
`backend/tests/test_source_scanner.py`,
`backend/tests/test_dependency_scanner.py`,
`backend/tests/test_certificate_scanner.py`, and
`backend/tests/test_binary_container_scanners.py`.
