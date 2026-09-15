"""
Detection patterns used by the source/dependency/config scanners.

This is intentionally a *reduced, documented* static-analysis approach:
regex + keyword matching over source text, not a full AST/type-flow
analysis. It cannot prove runtime usage - see classifier.py and
docs/limitations.md for the accuracy caveats that must accompany
every finding.

Each entry:
  pattern: compiled regex (case-insensitive) matched against a single line
  algorithm: canonical algorithm name (must match knowledge-base/algorithms.json where applicable)
  purpose: key_establishment | digital_signature | encryption | hashing | mac | protocol
  key_size: optional int, or None if not determinable from the pattern alone
  base_confidence: float 0-1, starting confidence before context adjustments
"""
import re
from dataclasses import dataclass


@dataclass
class DetectionRule:
    pattern: re.Pattern
    algorithm: str
    purpose: str
    key_size: int | None = None
    base_confidence: float = 0.7


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


RULES: list[DetectionRule] = [
    # ---- RSA ----
    DetectionRule(_rx(r"rsa[._-]?generate_private_key"), "RSA", "key_establishment", None, 0.95),
    DetectionRule(_rx(r"RSA\.generate\s*\(\s*(\d+)"), "RSA", "key_establishment", None, 0.95),
    DetectionRule(_rx(r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']"), "RSA", "key_establishment", None, 0.9),
    DetectionRule(_rx(r"RSA_generate_key"), "RSA", "key_establishment", None, 0.9),
    DetectionRule(_rx(r"rsa\.newkeys\s*\("), "RSA", "key_establishment", None, 0.85),
    DetectionRule(_rx(r"\bRSA-4096\b|\bRSA4096\b"), "RSA-4096", "key_establishment", 4096, 0.9),
    DetectionRule(_rx(r"\bRSA-3072\b|\bRSA3072\b"), "RSA-3072", "key_establishment", 3072, 0.9),
    DetectionRule(_rx(r"\bRSA-2048\b|\bRSA2048\b"), "RSA-2048", "key_establishment", 2048, 0.9),
    DetectionRule(_rx(r"\bRSA-1024\b|\bRSA1024\b"), "RSA-1024", "key_establishment", 1024, 0.9),
    DetectionRule(_rx(r"\bRSA\b"), "RSA", "key_establishment", None, 0.55),

    # ---- DSA ----
    DetectionRule(_rx(r"DSA\.generate|dsa_generate|KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']"), "DSA", "digital_signature", None, 0.85),
    DetectionRule(_rx(r"\bDSA\b"), "DSA", "digital_signature", None, 0.5),

    # ---- ECDSA / ECDH / EC ----
    DetectionRule(_rx(r"ECDSA|ec\.generate_private_key.*SECP|SigningKey\.generate\(curve"), "ECDSA", "digital_signature", None, 0.8),
    DetectionRule(_rx(r"ECDH|ec\.ECDH|X25519.*exchange"), "ECDH", "key_establishment", None, 0.75),
    DetectionRule(_rx(r"\bEd25519\b"), "Ed25519", "digital_signature", None, 0.85),
    DetectionRule(_rx(r"\bEd448\b"), "Ed448", "digital_signature", None, 0.85),

    # ---- Diffie-Hellman ----
    DetectionRule(_rx(r"diffie[\s_-]?hellman|DHParameterSpec|dh\.generate_parameters"), "Diffie-Hellman", "key_establishment", None, 0.7),

    # ---- AES ----
    DetectionRule(_rx(r"AES[_-]?256[_-]?GCM|AES/GCM/NoPadding.*256"), "AES-GCM", "encryption", 256, 0.85),
    DetectionRule(_rx(r"AES[_-]?128[_-]?GCM"), "AES-GCM", "encryption", 128, 0.85),
    DetectionRule(_rx(r"AES.*GCM|GCM.*AES"), "AES-GCM", "encryption", None, 0.7),
    DetectionRule(_rx(r"\bAES-?256\b|\bAES_256\b"), "AES-256", "encryption", 256, 0.8),
    DetectionRule(_rx(r"\bAES-?192\b|\bAES_192\b"), "AES-192", "encryption", 192, 0.8),
    DetectionRule(_rx(r"\bAES-?128\b|\bAES_128\b"), "AES-128", "encryption", 128, 0.8),
    DetectionRule(_rx(r"\bAES\b"), "AES-128", "encryption", None, 0.4),

    # ---- ChaCha ----
    DetectionRule(_rx(r"ChaCha20[-_]?Poly1305"), "ChaCha20-Poly1305", "encryption", None, 0.85),
    DetectionRule(_rx(r"\bChaCha20\b"), "ChaCha20", "encryption", None, 0.8),

    # ---- DES / 3DES ----
    DetectionRule(_rx(r"3DES|TripleDES|DESede"), "3DES", "encryption", 112, 0.85),
    DetectionRule(_rx(r"\bDES\b(?!ede)"), "DES", "encryption", 56, 0.6),

    # ---- Hashes ----
    DetectionRule(_rx(r"\bMD5\b|hashlib\.md5|MessageDigest\.getInstance\(\s*[\"']MD5[\"']"), "MD5", "hashing", 0, 0.85),
    DetectionRule(_rx(r"\bSHA-?1\b(?!\d)|hashlib\.sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']"), "SHA-1", "hashing", 0, 0.85),
    DetectionRule(_rx(r"\bSHA-?224\b|hashlib\.sha224"), "SHA-224", "hashing", 0, 0.8),
    DetectionRule(_rx(r"\bSHA-?256\b|hashlib\.sha256|MessageDigest\.getInstance\(\s*[\"']SHA-?256[\"']"), "SHA-256", "hashing", 0, 0.85),
    DetectionRule(_rx(r"\bSHA-?384\b|hashlib\.sha384"), "SHA-384", "hashing", 0, 0.8),
    DetectionRule(_rx(r"\bSHA-?512\b|hashlib\.sha512"), "SHA-512", "hashing", 0, 0.8),
    DetectionRule(_rx(r"\bHMAC\b|hmac\.new|Mac\.getInstance"), "HMAC", "mac", None, 0.75),

    # ---- Protocols ----
    DetectionRule(_rx(r"TLSv?1\.3|TLS_1_3|ssl\.TLSVersion\.TLSv1_3"), "TLS 1.3", "protocol", None, 0.8),
    DetectionRule(_rx(r"TLSv?1\.2|TLS_1_2|ssl\.TLSVersion\.TLSv1_2"), "TLS 1.2", "protocol", None, 0.8),
    DetectionRule(_rx(r"\bmTLS\b|mutual[\s_-]?tls"), "mTLS", "protocol", None, 0.7),
    DetectionRule(_rx(r"\bHTTPS\b"), "HTTPS", "protocol", None, 0.4),
    DetectionRule(_rx(r"\bIPsec\b|IPSEC"), "IPsec", "protocol", None, 0.7),
    DetectionRule(_rx(r"\bssh2?[-_]?(rsa|ed25519|ecdsa)|paramiko|OpenSSH"), "SSH", "protocol", None, 0.6),
    DetectionRule(_rx(r"\bTLS\b"), "TLS 1.2", "protocol", None, 0.35),
]

# Purpose display labels
PURPOSE_LABELS = {
    "key_establishment": "Key Establishment / Key Exchange",
    "digital_signature": "Digital Signature",
    "encryption": "Symmetric/Asymmetric Encryption",
    "hashing": "Hashing",
    "mac": "Message Authentication Code",
    "protocol": "Transport/Network Protocol",
}

SUPPORTED_SOURCE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".go": "go", ".rs": "rust", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".conf": "config", ".sh": "shell",
}

DOCKERFILE_NAMES = {"Dockerfile", "dockerfile"}
