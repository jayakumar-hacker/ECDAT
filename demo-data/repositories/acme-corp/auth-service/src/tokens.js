/**
 * Authentication Service - JWT signing and session key exchange.
 * Fictional demo code for ECDAT scanning purposes.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// RSA-4096 used to sign long-lived refresh tokens
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
});

// ECDSA P-256 used for short-lived session tokens
function signSessionToken(payload) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Ed25519 used for service-to-service signing
const ed25519Keys = crypto.generateKeyPairSync('ed25519');

// ECDH for establishing shared session keys with the mobile app
function deriveSharedSecret(ecdh, otherPublicKey) {
  return ecdh.computeSecret(otherPublicKey);
}

// AES-128-GCM for encrypting session tokens at rest (legacy, should move to 256)
function encryptSessionBlob(plaintext, key) {
  const cipher = crypto.createCipheriv('aes-128-gcm', key, crypto.randomBytes(12));
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { signSessionToken, deriveSharedSecret, encryptSessionBlob };
