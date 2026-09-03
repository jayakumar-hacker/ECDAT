import os
import base64
import tempfile
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.scanners.config.scanner import scan_configs
from app.services.scan_service import run_scan
from app.models import models


def _generate_test_cert_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k8s-tls-test.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_scan_sshd_config():
    with tempfile.TemporaryDirectory() as tmp:
        sshd_content = """# OpenSSH Daemon Configuration
Port 22
Ciphers 3des-cbc,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256,sntrup761x25519-sha512@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-rsa,ssh-dss
MACs hmac-sha2-256,hmac-md5
"""
        with open(os.path.join(tmp, "sshd_config"), "w", encoding="utf-8") as f:
            f.write(sshd_content)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "3DES" in algos
        assert "AES-256" in algos
        assert "ChaCha20-Poly1305" in algos
        assert "Diffie-Hellman" in algos
        assert "ML-KEM" in algos  # sntrup761x25519
        assert "ECDH" in algos    # curve25519
        assert "Ed25519" in algos
        assert "RSA" in algos
        assert "DSA" in algos
        assert "MD5" in algos
        assert "HMAC" in algos

        # Check legacy DH group1 key_size
        dh_weak = next(f for f in findings if f["algorithm"] == "Diffie-Hellman" and f["key_size"] == 1024)
        assert dh_weak["purpose"] == "key_establishment"


def test_scan_nginx_and_apache_ssl_directives():
    with tempfile.TemporaryDirectory() as tmp:
        nginx_conf = """server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA:RC4-SHA;
}"""
        with open(os.path.join(tmp, "nginx.conf"), "w", encoding="utf-8") as f:
            f.write(nginx_conf)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "TLS 1.0" in algos
        assert "TLS 1.1" in algos
        assert "TLS 1.2" in algos
        assert "TLS 1.3" in algos
        assert "ECDH" in algos
        assert "RSA" in algos
        assert "AES-256" in algos
        assert "3DES" in algos
        assert "RC4" in algos


def test_scan_openssl_cnf():
    with tempfile.TemporaryDirectory() as tmp:
        cnf_content = """[ req ]
default_bits = 4096
default_md = sha256
prompt = no
distinguished_name = req_distinguished_name

[ system_default_sect ]
MinProtocol = TLSv1.2
"""
        with open(os.path.join(tmp, "openssl.cnf"), "w", encoding="utf-8") as f:
            f.write(cnf_content)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "RSA-4096" in algos
        assert "SHA-256" in algos
        assert "TLS 1.2" in algos

        rsa_finding = next(f for f in findings if "RSA" in f["algorithm"])
        assert rsa_finding["key_size"] == 4096


def test_scan_java_security():
    with tempfile.TemporaryDirectory() as tmp:
        java_sec_content = """jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, 3DES_EDE_CBC, \\
    MD5withRSA, DH keySize < 2048, EC keySize < 224
"""
        with open(os.path.join(tmp, "java.security"), "w", encoding="utf-8") as f:
            f.write(java_sec_content)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "SSL 3.0" in algos
        assert "TLS 1.0" in algos
        assert "TLS 1.1" in algos
        assert "RC4" in algos
        assert "3DES" in algos
        assert "Diffie-Hellman" in algos
        assert "ECDSA" in algos

        dh_constraint = next(f for f in findings if f["algorithm"] == "Diffie-Hellman")
        assert dh_constraint["key_size"] == 2048


def test_scan_terraform():
    with tempfile.TemporaryDirectory() as tmp:
        tf_content = """resource "aws_kms_key" "payment_key" {
  description             = "Payment service KMS key"
  customer_master_key_spec = "RSA_3072"
  key_usage               = "ENCRYPT_DECRYPT"
}

resource "aws_kms_key" "signing_key" {
  description             = "ECC Signing key"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage               = "SIGN_VERIFY"
}

resource "aws_acm_certificate" "cert" {
  domain_name   = "api.example.com"
  key_algorithm = "RSA_2048"
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:..."
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
"""
        with open(os.path.join(tmp, "main.tf"), "w", encoding="utf-8") as f:
            f.write(tf_content)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "RSA-3072" in algos
        assert "RSA-2048" in algos
        assert "ECDSA" in algos
        assert "TLS 1.3" in algos


def test_scan_k8s_tls_secret_and_cert_manager():
    with tempfile.TemporaryDirectory() as tmp:
        cert_pem = _generate_test_cert_pem()
        cert_b64 = base64.b64encode(cert_pem.encode("utf-8")).decode("utf-8")

        k8s_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: test-tls-secret
type: kubernetes.io/tls
data:
  tls.crt: {cert_b64}
  tls.key: dGVzdC1rZXk=
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: internal-api-cert
spec:
  secretName: internal-api-tls
  privateKey:
    algorithm: RSA
    size: 4096
  issuerRef:
    name: ca-issuer
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ca-issuer
spec:
  ca:
    secretName: root-ca-secret
"""
        with open(os.path.join(tmp, "ingress-tls.yaml"), "w", encoding="utf-8") as f:
            f.write(k8s_yaml)

        errors = []
        findings = scan_configs(tmp, errors)
        assert len(errors) == 0

        algos = {f["algorithm"] for f in findings}
        assert "RSA-2048" in algos   # from k8s Secret cert
        assert "RSA-4096" in algos   # from cert-manager Certificate
        assert "X.509" in algos      # from ClusterIssuer

        secret_finding = next(f for f in findings if f["algorithm"] == "RSA-2048")
        assert secret_finding["key_size"] == 2048
        assert secret_finding["purpose"] == "digital_signature"


def test_run_scan_with_config_scanner(db_session):
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "sshd_config"), "w", encoding="utf-8") as f:
            f.write("KexAlgorithms diffie-hellman-group14-sha256\nCiphers aes256-gcm@openssh.com\n")

        scan = models.Scan(target=tmp, target_type="directory", scanners_requested=["config"])
        db_session.add(scan)
        db_session.commit()

        run_scan(db_session, scan)
        assert scan.status == "completed"

        # Verify CryptographicArtefact rows created
        artefacts = db_session.query(models.CryptographicArtefact).filter(
            models.CryptographicArtefact.scan_id == scan.id
        ).all()
        assert len(artefacts) == 2
        for art in artefacts:
            assert art.artefact_type == "config"

        # Verify downstream Asset creation
        assets = db_session.query(models.Asset).filter(models.Asset.scan_id == scan.id).all()
        assert len(assets) >= 1
        for asset in assets:
            assert asset.risk_assessment is not None
            assert asset.mosca_assessment is not None
