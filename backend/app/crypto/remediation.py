"""
Offline knowledge table and diff generator for library-and-version-aware remediation drafts.

Provides concrete, read-only diff suggestions mapping:
  (language, current library, algorithm, purpose) ->
  (target library, minimum version, replacement API, hybrid construction, diff suggestion)

Suggestions are NEVER applied automatically; they are strictly read-only reference
drafts for human review and manual application.
"""
from typing import NamedTuple


class RemediationEntry(NamedTuple):
    language: str
    current_library: str
    algorithm: str
    purpose: str
    target_library: str
    minimum_version: str
    replacement_api: str
    hybrid_construction: str
    diff_template: str


# Knowledge table mapping (language, current_library, algorithm_family, purpose)
REMEDIATION_TABLE: list[RemediationEntry] = [
    # Python - cryptography
    RemediationEntry(
        language="python",
        current_library="cryptography",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="cryptography",
        minimum_version=">=42.0.0",
        replacement_api="cryptography.hazmat.primitives.asymmetric.x25519 / ML-KEM-768 (FIPS 203)",
        hybrid_construction="X25519 + ML-KEM-768 hybrid KEM",
        diff_template=(
            "--- a/crypto_handler.py\n"
            "+++ b/crypto_handler.py\n"
            "@@ -1,6 +1,8 @@\n"
            "-from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "-private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "+from cryptography.hazmat.primitives.asymmetric import x25519\n"
            "+# Hybrid migration: pair classical ECDH with post-quantum ML-KEM-768\n"
            "+classical_priv = x25519.X25519PrivateKey.generate()\n"
            "+# When library >= 42.0.0 is upgraded to PQC standard:\n"
            "+# kem_shared = mlkem.encapsulate(peer_pqc_pubkey)\n"
            "+# combined_key = hkdf(classical_shared + kem_shared)\n"
        ),
    ),
    RemediationEntry(
        language="python",
        current_library="cryptography",
        algorithm="RSA",
        purpose="digital_signature",
        target_library="cryptography",
        minimum_version=">=43.0.0",
        replacement_api="ML-DSA-65 (FIPS 204) / SLH-DSA (FIPS 205)",
        hybrid_construction="RSA-3072 + ML-DSA-65 dual composite signature",
        diff_template=(
            "--- a/signer.py\n"
            "+++ b/signer.py\n"
            "@@ -1,6 +1,7 @@\n"
            "-from cryptography.hazmat.primitives.asymmetric import padding, rsa\n"
            "-signature = private_key.sign(data, padding.PSS(...), hashes.SHA256())\n"
            "+# Migration to FIPS 204 ML-DSA-65 (Composite / Dual Signature)\n"
            "+classic_sig = private_key.sign(data, padding.PSS(...), hashes.SHA256())\n"
            "+pqc_sig = mldsa65_private_key.sign(data)\n"
            "+composite_signature = classic_sig + pqc_sig\n"
        ),
    ),
    RemediationEntry(
        language="python",
        current_library="cryptography",
        algorithm="ECDSA",
        purpose="digital_signature",
        target_library="cryptography",
        minimum_version=">=43.0.0",
        replacement_api="ML-DSA-65 (FIPS 204)",
        hybrid_construction="ECDSA P-256 + ML-DSA-65 composite signature",
        diff_template=(
            "--- a/auth_signer.py\n"
            "+++ b/auth_signer.py\n"
            "@@ -1,5 +1,7 @@\n"
            "-from cryptography.hazmat.primitives.asymmetric import ec\n"
            "-sig = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))\n"
            "+# Composite signature: ECDSA P-256 with ML-DSA-65\n"
            "+classic_sig = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))\n"
            "+pqc_sig = mldsa_priv_key.sign(data)\n"
            "+composite_sig = {'ecdsa': classic_sig, 'ml_dsa': pqc_sig}\n"
        ),
    ),
    RemediationEntry(
        language="python",
        current_library="pycryptodome",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="liboqs-python",
        minimum_version=">=0.10.0",
        replacement_api="oqs.KeyEncapsulation('ML-KEM-768')",
        hybrid_construction="X25519 + ML-KEM-768 hybrid KEM",
        diff_template=(
            "--- a/key_exchange.py\n"
            "+++ b/key_exchange.py\n"
            "@@ -1,4 +1,6 @@\n"
            "-from Crypto.PublicKey import RSA\n"
            "-key = RSA.generate(2048)\n"
            "+import oqs\n"
            "+# Post-Quantum KEM encapsulation via liboqs\n"
            "+kem = oqs.KeyEncapsulation('ML-KEM-768')\n"
            "+public_key = kem.generate_keypair()\n"
        ),
    ),
    # Java - BouncyCastle
    RemediationEntry(
        language="java",
        current_library="bcprov-jdk15on",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="org.bouncycastle:bcprov-jdk18on",
        minimum_version=">=1.78",
        replacement_api="org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator (ML-KEM)",
        hybrid_construction="X25519withMLKEM hybrid key agreement",
        diff_template=(
            "--- a/pom.xml\n"
            "+++ b/pom.xml\n"
            "@@ -10,3 +10,3 @@\n"
            "-    <artifactId>bcprov-jdk15on</artifactId>\n"
            "-    <version>1.70</version>\n"
            "+    <artifactId>bcprov-jdk18on</artifactId>\n"
            "+    <version>1.78</version>\n"
            "--- a/CryptoService.java\n"
            "+++ b/CryptoService.java\n"
            "@@ -1,3 +1,5 @@\n"
            "-KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n"
            "+// Upgrade to ML-KEM (Kyber-768) PQC Key Agreement\n"
            "+KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"ML-KEM-768\", \"BC\");\n"
        ),
    ),
    RemediationEntry(
        language="java",
        current_library="bcprov-jdk18on",
        algorithm="ECDSA",
        purpose="digital_signature",
        target_library="org.bouncycastle:bcprov-jdk18on",
        minimum_version=">=1.78",
        replacement_api="org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator",
        hybrid_construction="SHA384withECDSAandMLDSA composite signature",
        diff_template=(
            "--- a/SignatureService.java\n"
            "+++ b/SignatureService.java\n"
            "@@ -1,3 +1,4 @@\n"
            "-Signature sig = Signature.getInstance(\"SHA256withECDSA\");\n"
            "+// Dual composite signature with ML-DSA-65\n"
            "+Signature sig = Signature.getInstance(\"SHA384withECDSAandMLDSA\", \"BC\");\n"
        ),
    ),
    # JavaScript / Node.js
    RemediationEntry(
        language="javascript",
        current_library="crypto",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="node",
        minimum_version=">=22.0.0",
        replacement_api="crypto.generateKeyPairSync('ml-kem-768')",
        hybrid_construction="X25519 + ML-KEM-768 hybrid KEM",
        diff_template=(
            "--- a/tokenAuth.js\n"
            "+++ b/tokenAuth.js\n"
            "@@ -1,4 +1,6 @@\n"
            "-const { generateKeyPairSync } = require('crypto');\n"
            "-const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });\n"
            "+const { generateKeyPairSync } = require('crypto');\n"
            "+// Node.js >= 22 PQC / hybrid KEM interface\n"
            "+const { publicKey, privateKey } = generateKeyPairSync('ml-kem-768');\n"
        ),
    ),
    RemediationEntry(
        language="javascript",
        current_library="crypto",
        algorithm="RSA",
        purpose="digital_signature",
        target_library="node",
        minimum_version=">=22.0.0",
        replacement_api="crypto.sign('ml-dsa-65')",
        hybrid_construction="RSA-PSS + ML-DSA-65 composite signature",
        diff_template=(
            "--- a/signer.js\n"
            "+++ b/signer.js\n"
            "@@ -1,4 +1,6 @@\n"
            "-const sign = crypto.createSign('SHA256');\n"
            "-sign.update(data); const signature = sign.sign(privateKey);\n"
            "+// Composite signature: sign with classical RSA-PSS and ML-DSA-65\n"
            "+const classicSig = crypto.sign('sha256', data, privateKey);\n"
            "+const pqcSig = crypto.sign('ml-dsa-65', data, mldsaPrivateKey);\n"
        ),
    ),
    # Go
    RemediationEntry(
        language="go",
        current_library="crypto/rsa",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="golang.org/x/crypto",
        minimum_version=">=0.25.0",
        replacement_api="crypto/mlkem.NewDecapsulationKey768()",
        hybrid_construction="X25519 + ML-KEM-768 hybrid KEM",
        diff_template=(
            "--- a/crypto.go\n"
            "+++ b/crypto.go\n"
            "@@ -1,4 +1,6 @@\n"
            "-import \"crypto/rsa\"\n"
            "-key, err := rsa.GenerateKey(rand.Reader, 2048)\n"
            "+import \"crypto/mlkem\"\n"
            "+// FIPS 203 ML-KEM-768 key encapsulation in Go 1.24+\n"
            "+dk, err := mlkem.NewDecapsulationKey768()\n"
        ),
    ),
    RemediationEntry(
        language="go",
        current_library="crypto/ecdsa",
        algorithm="ECDSA",
        purpose="digital_signature",
        target_library="golang.org/x/crypto",
        minimum_version=">=0.25.0",
        replacement_api="mldsa.GenerateKey()",
        hybrid_construction="ECDSA P-256 + ML-DSA-65 composite signature",
        diff_template=(
            "--- a/signer.go\n"
            "+++ b/signer.go\n"
            "@@ -1,4 +1,6 @@\n"
            "-import \"crypto/ecdsa\"\n"
            "-sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash)\n"
            "+// Composite signing with ECDSA + ML-DSA-65\n"
            "+sigClassical, _ := ecdsa.SignASN1(rand.Reader, privKey, hash)\n"
            "+sigPQC, _ := mldsa.Sign(mldsaPrivKey, hash)\n"
        ),
    ),
    # C / C++ / OpenSSL
    RemediationEntry(
        language="c",
        current_library="openssl",
        algorithm="RSA",
        purpose="key_establishment",
        target_library="openssl",
        minimum_version=">=3.2.0 (with oqsprovider)",
        replacement_api="EVP_PKEY_Q_keygen(ctx, \"ML-KEM-768\")",
        hybrid_construction="p256_mlkem768 hybrid KEM",
        diff_template=(
            "--- a/tls_setup.c\n"
            "+++ b/tls_setup.c\n"
            "@@ -1,4 +1,6 @@\n"
            "-EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);\n"
            "+// OpenSSL 3.2+ with oqsprovider hybrid key agreement\n"
            "+SSL_CTX_set1_groups_list(ctx, \"p256_mlkem768:X25519MLKEM768:x25519\");\n"
        ),
    ),
]


def _normalize_algo(algo: str) -> str:
    norm = algo.upper()
    if norm.startswith("RSA"):
        return "RSA"
    if norm.startswith("ECDSA") or "ECDSA" in norm:
        return "ECDSA"
    if norm.startswith("ECDH") or "ECDH" in norm:
        return "ECDH"
    if "ED25519" in norm:
        return "ED25519"
    if "AES" in norm:
        return "AES"
    if norm in ("DES", "3DES"):
        return "DES"
    return norm


def _normalize_purpose(purpose: str) -> str:
    p = purpose.lower().replace("-", "_").replace(" ", "_")
    if "sig" in p:
        return "digital_signature"
    if "key" in p or "kem" in p or "exchange" in p or "establish" in p:
        return "key_establishment"
    if "encrypt" in p or "symmetric" in p:
        return "encryption"
    return p


def get_remediation_draft(
    language: str | None = None,
    current_library: str | None = None,
    algorithm: str = "RSA",
    purpose: str = "key_establishment",
    proposed_algorithm: str | None = None,
) -> dict:
    """
    Look up the offline remediation knowledge table and return a concrete diff-style
    suggestion draft.

    The returned suggestion is strictly read-only and never applied automatically.
    """
    lang_norm = (language or "python").strip().lower()
    lib_norm = (current_library or "").strip().lower()
    algo_norm = _normalize_algo(algorithm)
    purp_norm = _normalize_purpose(purpose or "key_establishment")

    matched_entry: RemediationEntry | None = None

    # Pass 1: exact match on (language, current_library, algorithm, purpose)
    if lib_norm:
        for entry in REMEDIATION_TABLE:
            if (
                entry.language == lang_norm
                and lib_norm in entry.current_library.lower()
                and entry.algorithm == algo_norm
                and entry.purpose == purp_norm
            ):
                matched_entry = entry
                break

    # Pass 2: match (language, algorithm, purpose) ignoring library
    if not matched_entry:
        for entry in REMEDIATION_TABLE:
            if (
                entry.language == lang_norm
                and entry.algorithm == algo_norm
                and entry.purpose == purp_norm
            ):
                matched_entry = entry
                break

    # Pass 3: match (algorithm, purpose) across any language
    if not matched_entry:
        for entry in REMEDIATION_TABLE:
            if entry.algorithm == algo_norm and entry.purpose == purp_norm:
                matched_entry = entry
                break

    # Pass 4: match algorithm only
    if not matched_entry:
        for entry in REMEDIATION_TABLE:
            if entry.algorithm == algo_norm:
                matched_entry = entry
                break

    if matched_entry:
        target_library = matched_entry.target_library
        minimum_version = matched_entry.minimum_version
        replacement_api = proposed_algorithm or matched_entry.replacement_api
        hybrid_construction = matched_entry.hybrid_construction
        diff_suggestion = matched_entry.diff_template
        resolved_language = matched_entry.language
        resolved_library = matched_entry.current_library if not lib_norm else current_library
    else:
        # Fallback default for unrecognized combination
        resolved_language = language or "unknown"
        resolved_library = current_library or "standard-library"
        target_library = "NIST FIPS 203 / 204 compliant library"
        minimum_version = "latest"
        replacement_api = proposed_algorithm or "ML-KEM-768 / ML-DSA-65"
        hybrid_construction = f"Classical ({algorithm}) + Post-Quantum ({replacement_api}) hybrid"
        diff_suggestion = (
            f"--- a/crypto_module\n"
            f"+++ b/crypto_module\n"
            f"@@ -1,4 +1,5 @@\n"
            f"-// Legacy: {algorithm} ({purp_norm})\n"
            f"+// Remediated: {hybrid_construction}\n"
            f"+// Target: {target_library} (min version {minimum_version})\n"
        )

    return {
        "language": resolved_language,
        "current_library": resolved_library,
        "target_library": target_library,
        "minimum_version": minimum_version,
        "replacement_api": replacement_api,
        "hybrid_construction": hybrid_construction,
        "diff_suggestion": diff_suggestion,
        "read_only": True,
        "note": (
            "Remediation draft is an offline concrete diff suggestion for manual "
            "human review only — never applied automatically."
        ),
    }
