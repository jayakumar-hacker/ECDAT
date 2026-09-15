"""
Payment API - authentication and transaction signing module.
Fictional demo code for ECDAT scanning purposes.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import ssl

# Generate RSA-2048 key pair for legacy transaction signing (candidate for PQC migration)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Symmetric encryption for card data at rest - AES-256-GCM
def encrypt_card_data(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12
    return aesgcm.encrypt(nonce, plaintext, None)

# TLS configuration for the payment gateway - enforce TLS 1.3
def build_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx

# Legacy checksum used in an old reconciliation job - SHA-256 is fine here
def transaction_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
