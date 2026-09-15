// Public marketing website - TLS termination and contact-form signing.
// Fictional demo code for ECDAT scanning purposes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
)

// ECDSA P-256 key used to sign contact-form submissions for integrity
func generateSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// TLS 1.3 enforced for all public-facing traffic
func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// SHA-256 used for asset integrity checks (CDN cache busting)
func assetHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}
