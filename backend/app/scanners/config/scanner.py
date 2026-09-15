"""
Configuration and infrastructure protocol scanner.

Read-only: opens files for reading only, never executes or applies configs.
Discovers cryptographic algorithms, key sizes, cipher suites, and protocol versions
in:
- sshd_config / ssh_config
- nginx and apache configurations (ssl_protocols, ssl_ciphers, SSLCipherSuite)
- openssl.cnf / openssl.conf
- java.security (jdk.tls.disabledAlgorithms, minimum key sizes)
- Terraform manifests (*.tf, *.tfvars, *.tf.json: aws_kms_key, aws_acm_certificate, ssl_policy)
- Kubernetes TLS Secrets (kubernetes.io/tls)
- cert-manager manifests (Certificate, Issuer, ClusterIssuer)

Emits findings matching the standard CryptographicArtefact shape.
"""
import base64
import os
import re
import yaml
from app.core.config import settings


def _make_finding(
    algorithm: str,
    file_path: str,
    line: int | None = None,
    usage: str = "Configured cryptographic parameter",
    key_size: int | None = None,
    purpose: str = "",
    confidence: float = 0.85,
    evidence: str = "",
    protocol: str = "",
    component: str = "",
) -> dict:
    return {
        "algorithm": algorithm,
        "file": file_path,
        "line": line,
        "language": "config",
        "usage": usage,
        "key_size": key_size,
        "purpose": purpose,
        "confidence": confidence,
        "evidence": evidence,
        "protocol": protocol,
        "component": component,
    }


def _scan_sshd_config(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Ciphers directive
        m_ciphers = re.match(r"^Ciphers\s+(.+)$", line, re.IGNORECASE)
        if m_ciphers:
            ciphers = [c.strip() for c in m_ciphers.group(1).split(",") if c.strip()]
            for c in ciphers:
                c_lower = c.lower()
                if "3des" in c_lower:
                    findings.append(_make_finding(
                        "3DES", path, line_idx,
                        usage="Legacy SSH cipher: 3DES", key_size=168,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "blowfish" in c_lower:
                    findings.append(_make_finding(
                        "Blowfish", path, line_idx,
                        usage="Legacy SSH cipher: Blowfish", key_size=128,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "arcfour" in c_lower or "rc4" in c_lower:
                    findings.append(_make_finding(
                        "RC4", path, line_idx,
                        usage="Insecure SSH cipher: RC4", key_size=128,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "chacha20-poly1305" in c_lower:
                    findings.append(_make_finding(
                        "ChaCha20-Poly1305", path, line_idx,
                        usage="SSH cipher: ChaCha20-Poly1305", key_size=256,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "aes256" in c_lower:
                    findings.append(_make_finding(
                        "AES-256", path, line_idx,
                        usage="SSH cipher: AES-256", key_size=256,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "aes128" in c_lower:
                    findings.append(_make_finding(
                        "AES-128", path, line_idx,
                        usage="SSH cipher: AES-128", key_size=128,
                        purpose="encryption", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))

        # KexAlgorithms directive
        m_kex = re.match(r"^KexAlgorithms\s+(.+)$", line, re.IGNORECASE)
        if m_kex:
            kex_list = [k.strip() for k in m_kex.group(1).split(",") if k.strip()]
            for k in kex_list:
                k_lower = k.lower()
                if "sntrup761x25519" in k_lower or "mlkem" in k_lower:
                    findings.append(_make_finding(
                        "ML-KEM", path, line_idx,
                        usage="Post-quantum hybrid SSH key exchange",
                        purpose="key_establishment", confidence=0.95, evidence=line,
                        protocol="SSH",
                    ))
                elif "diffie-hellman-group1-" in k_lower:
                    findings.append(_make_finding(
                        "Diffie-Hellman", path, line_idx,
                        usage="Weak legacy SSH key exchange: DH group1 (1024-bit)",
                        key_size=1024, purpose="key_establishment", confidence=0.95, evidence=line,
                        protocol="SSH",
                    ))
                elif "diffie-hellman-group14-" in k_lower:
                    findings.append(_make_finding(
                        "Diffie-Hellman", path, line_idx,
                        usage="SSH key exchange: DH group14 (2048-bit)",
                        key_size=2048, purpose="key_establishment", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "diffie-hellman" in k_lower:
                    findings.append(_make_finding(
                        "Diffie-Hellman", path, line_idx,
                        usage="SSH key exchange: Diffie-Hellman",
                        purpose="key_establishment", confidence=0.85, evidence=line,
                        protocol="SSH",
                    ))
                elif "curve25519" in k_lower:
                    findings.append(_make_finding(
                        "ECDH", path, line_idx,
                        usage="SSH key exchange: Curve25519", key_size=256,
                        purpose="key_establishment", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "ecdh" in k_lower:
                    findings.append(_make_finding(
                        "ECDH", path, line_idx,
                        usage="SSH key exchange: ECDH",
                        purpose="key_establishment", confidence=0.85, evidence=line,
                        protocol="SSH",
                    ))

        # HostKeyAlgorithms or PubkeyAcceptedKeyTypes
        m_hostkey = re.match(r"^(?:HostKeyAlgorithms|PubkeyAcceptedKeyTypes|HostKey)\s+(.+)$", line, re.IGNORECASE)
        if m_hostkey:
            h_list = [h.strip() for h in m_hostkey.group(1).split(",") if h.strip()]
            for h in h_list:
                h_lower = h.lower()
                if "ssh-ed25519" in h_lower:
                    findings.append(_make_finding(
                        "Ed25519", path, line_idx,
                        usage="SSH hostkey/pubkey algorithm: Ed25519", key_size=256,
                        purpose="digital_signature", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "ssh-rsa" in h_lower or "rsa-sha" in h_lower:
                    findings.append(_make_finding(
                        "RSA", path, line_idx,
                        usage="SSH hostkey/pubkey algorithm: RSA",
                        purpose="digital_signature", confidence=0.85, evidence=line,
                        protocol="SSH",
                    ))
                elif "ecdsa" in h_lower:
                    findings.append(_make_finding(
                        "ECDSA", path, line_idx,
                        usage="SSH hostkey/pubkey algorithm: ECDSA",
                        purpose="digital_signature", confidence=0.85, evidence=line,
                        protocol="SSH",
                    ))
                elif "ssh-dss" in h_lower:
                    findings.append(_make_finding(
                        "DSA", path, line_idx,
                        usage="Weak legacy SSH hostkey algorithm: DSA (1024-bit)", key_size=1024,
                        purpose="digital_signature", confidence=0.95, evidence=line,
                        protocol="SSH",
                    ))

        # MACs directive
        m_macs = re.match(r"^MACs\s+(.+)$", line, re.IGNORECASE)
        if m_macs:
            macs = [m.strip() for m in m_macs.group(1).split(",") if m.strip()]
            for mac in macs:
                mac_lower = mac.lower()
                if "md5" in mac_lower:
                    findings.append(_make_finding(
                        "MD5", path, line_idx,
                        usage="Weak legacy SSH MAC: MD5",
                        purpose="mac", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "sha1" in mac_lower:
                    findings.append(_make_finding(
                        "SHA-1", path, line_idx,
                        usage="Legacy SSH MAC: SHA-1",
                        purpose="mac", confidence=0.9, evidence=line,
                        protocol="SSH",
                    ))
                elif "sha2" in mac_lower or "sha512" in mac_lower:
                    findings.append(_make_finding(
                        "HMAC", path, line_idx,
                        usage="SSH MAC: HMAC-SHA2",
                        purpose="mac", confidence=0.85, evidence=line,
                        protocol="SSH",
                    ))

    return findings


def _scan_web_server_ssl(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Nginx ssl_protocols or Apache SSLProtocol
        m_proto = re.search(r"\b(?:ssl_protocols|SSLProtocol)\s+([^;]+)", line, re.IGNORECASE)
        if m_proto:
            protos = m_proto.group(1).split()
            for p in protos:
                p_clean = p.strip("+").upper()
                if p_clean.startswith("-"):
                    continue
                if p_clean in ("SSLV2", "SSLV3"):
                    findings.append(_make_finding(
                        "SSL 3.0" if p_clean == "SSLV3" else "SSL 2.0", path, line_idx,
                        usage=f"Insecure protocol directive: {p_clean}",
                        purpose="protocol", confidence=0.95, evidence=line,
                        protocol="TLS",
                    ))
                elif p_clean in ("TLSV1", "TLSV1.0"):
                    findings.append(_make_finding(
                        "TLS 1.0", path, line_idx,
                        usage="Deprecated protocol directive: TLS 1.0",
                        purpose="protocol", confidence=0.9, evidence=line,
                        protocol="TLS",
                    ))
                elif p_clean in ("TLSV1.1",):
                    findings.append(_make_finding(
                        "TLS 1.1", path, line_idx,
                        usage="Deprecated protocol directive: TLS 1.1",
                        purpose="protocol", confidence=0.9, evidence=line,
                        protocol="TLS",
                    ))
                elif p_clean in ("TLSV1.2",):
                    findings.append(_make_finding(
                        "TLS 1.2", path, line_idx,
                        usage="TLS protocol directive: TLS 1.2",
                        purpose="protocol", confidence=0.9, evidence=line,
                        protocol="TLS",
                    ))
                elif p_clean in ("TLSV1.3",):
                    findings.append(_make_finding(
                        "TLS 1.3", path, line_idx,
                        usage="TLS protocol directive: TLS 1.3",
                        purpose="protocol", confidence=0.9, evidence=line,
                        protocol="TLS",
                    ))

        # Nginx ssl_ciphers or Apache SSLCipherSuite
        m_ciphers = re.search(r"\b(?:ssl_ciphers|SSLCipherSuite)\s+([^;]+)", line, re.IGNORECASE)
        if m_ciphers:
            cipher_spec = m_ciphers.group(1).strip('"\'')
            # Check individual ciphers or tokens in cipher suite string
            c_upper = cipher_spec.upper()
            if "ECDHE" in c_upper:
                findings.append(_make_finding(
                    "ECDH", path, line_idx,
                    usage="TLS cipher suite: ECDHE key exchange",
                    purpose="key_establishment", confidence=0.85, evidence=line,
                    protocol="TLS",
                ))
            if "DHE" in c_upper or "EDH" in c_upper:
                findings.append(_make_finding(
                    "Diffie-Hellman", path, line_idx,
                    usage="TLS cipher suite: DHE key exchange",
                    purpose="key_establishment", confidence=0.85, evidence=line,
                    protocol="TLS",
                ))
            if "RSA" in c_upper and not "!RSA" in c_upper:
                findings.append(_make_finding(
                    "RSA", path, line_idx,
                    usage="TLS cipher suite: RSA key exchange / authentication",
                    purpose="key_establishment", confidence=0.85, evidence=line,
                    protocol="TLS",
                ))
            if "3DES" in c_upper or "DES-CBC3" in c_upper:
                findings.append(_make_finding(
                    "3DES", path, line_idx,
                    usage="Weak TLS cipher: 3DES", key_size=168,
                    purpose="encryption", confidence=0.9, evidence=line,
                    protocol="TLS",
                ))
            if "RC4" in c_upper and not "!RC4" in c_upper:
                findings.append(_make_finding(
                    "RC4", path, line_idx,
                    usage="Insecure TLS cipher: RC4",
                    purpose="encryption", confidence=0.95, evidence=line,
                    protocol="TLS",
                ))
            if "CHACHA20-POLY1305" in c_upper:
                findings.append(_make_finding(
                    "ChaCha20-Poly1305", path, line_idx,
                    usage="TLS cipher: ChaCha20-Poly1305", key_size=256,
                    purpose="encryption", confidence=0.9, evidence=line,
                    protocol="TLS",
                ))
            if "AES256" in c_upper or "AESGCM" in c_upper:
                findings.append(_make_finding(
                    "AES-256", path, line_idx,
                    usage="TLS cipher: AES-256", key_size=256,
                    purpose="encryption", confidence=0.85, evidence=line,
                    protocol="TLS",
                ))
            elif "AES128" in c_upper:
                findings.append(_make_finding(
                    "AES-128", path, line_idx,
                    usage="TLS cipher: AES-128", key_size=128,
                    purpose="encryption", confidence=0.85, evidence=line,
                    protocol="TLS",
                ))

    return findings


def _scan_openssl_cnf(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        m_bits = re.match(r"^default_bits\s*=\s*(\d+)", line)
        if m_bits:
            bits = int(m_bits.group(1))
            algo_name = f"RSA-{bits}" if bits >= 1024 else "RSA"
            findings.append(_make_finding(
                algo_name, path, line_idx,
                usage=f"OpenSSL default RSA key size: {bits} bits",
                key_size=bits, purpose="key_establishment", confidence=0.9, evidence=line,
                component="OpenSSL",
            ))

        m_md = re.match(r"^default_md\s*=\s*([a-zA-Z0-9_-]+)", line)
        if m_md:
            md = m_md.group(1).lower()
            algo = "SHA-256" if "sha256" in md else ("SHA-1" if "sha1" in md else ("MD5" if "md5" in md else md.upper()))
            findings.append(_make_finding(
                algo, path, line_idx,
                usage=f"OpenSSL default digest: {md}",
                purpose="hashing", confidence=0.9, evidence=line,
                component="OpenSSL",
            ))

        m_proto = re.match(r"^(?:MinProtocol|MaxProtocol)\s*=\s*([a-zA-Z0-9_.-]+)", line, re.IGNORECASE)
        if m_proto:
            proto = m_proto.group(1)
            tls_name = "TLS 1.2" if "1.2" in proto else ("TLS 1.3" if "1.3" in proto else proto)
            findings.append(_make_finding(
                tls_name, path, line_idx,
                usage=f"OpenSSL protocol boundary: {line}",
                purpose="protocol", confidence=0.9, evidence=line,
                protocol="TLS", component="OpenSSL",
            ))

    return findings


def _scan_java_security(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return findings

    # In Java properties files, lines ending with backslash continue onto the next line
    clean_text = re.sub(r"\\\r?\n\s*", " ", text)

    for prop in ("jdk.tls.disabledAlgorithms", "jdk.certpath.disabledAlgorithms", "jdk.tls.legacyAlgorithms"):
        m = re.search(rf"{prop}\s*=\s*([^\r\n#]+)", clean_text)
        if m:
            val = m.group(1).strip()
            # Find key size constraints, e.g. DH keySize < 1024, RSA keySize < 2048, EC keySize < 224
            for m_key in re.finditer(r"\b(DH|RSA|EC)\s+keySize\s*<\s*(\d+)", val, re.IGNORECASE):
                ktype = m_key.group(1).upper()
                threshold = int(m_key.group(2))
                algo_name = "Diffie-Hellman" if ktype == "DH" else ("RSA" if ktype == "RSA" else "ECDSA")
                purpose = "key_establishment" if ktype in ("DH", "RSA") else "digital_signature"
                findings.append(_make_finding(
                    algo_name, path, line=None,
                    usage=f"Java security constraint: {ktype} minimum keySize {threshold} bits",
                    key_size=threshold, purpose=purpose, confidence=0.9,
                    evidence=f"{prop}: {m_key.group(0)}", component="Java Runtime",
                ))

            # Flag legacy algorithms disabled
            for legacy in ("SSLv3", "TLSv1", "TLSv1.1", "RC4", "DES", "3DES_EDE_CBC", "MD5withRSA"):
                if re.search(rf"\b{re.escape(legacy)}\b", val, re.IGNORECASE):
                    algo = "SSL 3.0" if legacy == "SSLv3" else ("TLS 1.0" if legacy == "TLSv1" else ("TLS 1.1" if legacy == "TLSv1.1" else ("RC4" if legacy == "RC4" else ("3DES" if "3DES" in legacy else ("MD5" if "MD5" in legacy else legacy)))))
                    purpose = "protocol" if "SSL" in legacy or "TLS" in legacy else ("encryption" if legacy in ("RC4", "DES", "3DES_EDE_CBC") else "hashing")
                    findings.append(_make_finding(
                        algo, path, line=None,
                        usage=f"Java security policy references: {legacy}",
                        purpose=purpose, confidence=0.85,
                        evidence=f"{prop} contains {legacy}", component="Java Runtime",
                    ))

    return findings


def _scan_terraform(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # aws_kms_key customer_master_key_spec
        m_kms = re.search(r'customer_master_key_spec\s*=\s*"([^"]+)"', line, re.IGNORECASE)
        if m_kms:
            spec = m_kms.group(1).upper()
            if "RSA_2048" in spec:
                findings.append(_make_finding(
                    "RSA-2048", path, line_idx,
                    usage="AWS KMS customer master key spec: RSA-2048",
                    key_size=2048, purpose="key_establishment", confidence=0.95,
                    evidence=line, component="Terraform / AWS KMS",
                ))
            elif "RSA_3072" in spec:
                findings.append(_make_finding(
                    "RSA-3072", path, line_idx,
                    usage="AWS KMS customer master key spec: RSA-3072",
                    key_size=3072, purpose="key_establishment", confidence=0.95,
                    evidence=line, component="Terraform / AWS KMS",
                ))
            elif "RSA_4096" in spec:
                findings.append(_make_finding(
                    "RSA-4096", path, line_idx,
                    usage="AWS KMS customer master key spec: RSA-4096",
                    key_size=4096, purpose="key_establishment", confidence=0.95,
                    evidence=line, component="Terraform / AWS KMS",
                ))
            elif "ECC_NIST" in spec or "ECC_SECG" in spec:
                key_size = 256 if "256" in spec else (384 if "384" in spec else 521)
                findings.append(_make_finding(
                    "ECDSA", path, line_idx,
                    usage=f"AWS KMS ECC key spec: {spec}",
                    key_size=key_size, purpose="digital_signature", confidence=0.95,
                    evidence=line, component="Terraform / AWS KMS",
                ))
            elif "SYMMETRIC_DEFAULT" in spec:
                findings.append(_make_finding(
                    "AES-256", path, line_idx,
                    usage="AWS KMS symmetric key: AES-256-GCM",
                    key_size=256, purpose="encryption", confidence=0.9,
                    evidence=line, component="Terraform / AWS KMS",
                ))

        # aws_acm_certificate key_algorithm
        m_acm = re.search(r'key_algorithm\s*=\s*"([^"]+)"', line, re.IGNORECASE)
        if m_acm:
            acm_spec = m_acm.group(1).upper()
            if "RSA_2048" in acm_spec:
                findings.append(_make_finding(
                    "RSA-2048", path, line_idx,
                    usage="AWS ACM certificate key algorithm: RSA-2048",
                    key_size=2048, purpose="digital_signature", confidence=0.95,
                    evidence=line, component="Terraform / AWS ACM",
                ))
            elif "EC_" in acm_spec:
                findings.append(_make_finding(
                    "ECDSA", path, line_idx,
                    usage=f"AWS ACM certificate EC algorithm: {acm_spec}",
                    key_size=256 if "256" in acm_spec else 384, purpose="digital_signature",
                    confidence=0.95, evidence=line, component="Terraform / AWS ACM",
                ))

        # TLS policy ARNs or ssl_policy
        m_policy = re.search(r'(?:ssl_policy|minimum_protocol_version)\s*=\s*"([^"]+)"', line, re.IGNORECASE)
        if m_policy:
            pol = m_policy.group(1)
            pol_upper = pol.upper()
            if "TLS13" in pol_upper or "TLS-1-3" in pol_upper:
                findings.append(_make_finding(
                    "TLS 1.3", path, line_idx,
                    usage=f"AWS TLS security policy: {pol}",
                    purpose="protocol", confidence=0.9, evidence=line,
                    protocol="TLS", component="Terraform / AWS ELB",
                ))
            elif "TLS12" in pol_upper or "TLS-1-2" in pol_upper or "TLSV1.2" in pol_upper:
                findings.append(_make_finding(
                    "TLS 1.2", path, line_idx,
                    usage=f"AWS TLS security policy: {pol}",
                    purpose="protocol", confidence=0.9, evidence=line,
                    protocol="TLS", component="Terraform / AWS ELB",
                ))
            elif "2016-08" in pol_upper or "2015-05" in pol_upper or "TLSV1" in pol_upper:
                findings.append(_make_finding(
                    "TLS 1.0", path, line_idx,
                    usage=f"Legacy AWS TLS security policy (permits TLS 1.0/1.1): {pol}",
                    purpose="protocol", confidence=0.95, evidence=line,
                    protocol="TLS", component="Terraform / AWS ELB",
                ))

    return findings


def _scan_k8s_cert_manager(path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception:
        return findings

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        # 1. Kubernetes Secret with TLS
        if kind == "Secret" and doc.get("type") == "kubernetes.io/tls":
            data = doc.get("data") or {}
            string_data = doc.get("stringData") or {}
            crt_raw = data.get("tls.crt") or string_data.get("tls.crt")
            if crt_raw:
                try:
                    if isinstance(crt_raw, str) and not crt_raw.strip().startswith("-----BEGIN"):
                        cert_bytes = base64.b64decode(crt_raw)
                    else:
                        cert_bytes = crt_raw.encode("utf-8") if isinstance(crt_raw, str) else crt_raw
                    from cryptography import x509
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
                    cert = x509.load_pem_x509_certificate(cert_bytes)
                    pk = cert.public_key()
                    if isinstance(pk, rsa.RSAPublicKey):
                        algo = f"RSA-{pk.key_size}"
                        key_size = pk.key_size
                    elif isinstance(pk, ec.EllipticCurvePublicKey):
                        algo = "ECDSA"
                        key_size = pk.curve.key_size
                    elif isinstance(pk, ed25519.Ed25519PublicKey):
                        algo = "Ed25519"
                        key_size = 256
                    elif isinstance(pk, dsa.DSAPublicKey):
                        algo = "DSA"
                        key_size = pk.key_size
                    else:
                        algo = "Unknown"
                        key_size = None

                    findings.append(_make_finding(
                        algo, path, line=None,
                        usage="Kubernetes TLS Secret Certificate",
                        key_size=key_size, purpose="digital_signature", confidence=0.95,
                        evidence=f"Secret: {doc.get('metadata', {}).get('name', 'unnamed')}",
                        protocol="TLS", component="Kubernetes Secret",
                    ))
                except Exception:
                    # If cert cannot be parsed with x509, record a generic finding
                    findings.append(_make_finding(
                        "TLS 1.2", path, line=None,
                        usage="Kubernetes TLS Secret configuration",
                        purpose="protocol", confidence=0.7,
                        evidence=f"Secret: {doc.get('metadata', {}).get('name', 'unnamed')}",
                        protocol="TLS", component="Kubernetes Secret",
                    ))

        # 2. cert-manager Certificate resource
        if kind == "Certificate":
            spec = doc.get("spec") or {}
            pk_spec = spec.get("privateKey") or {}
            algo = pk_spec.get("algorithm", "RSA").upper()
            size = pk_spec.get("size")
            if algo == "RSA":
                size = int(size) if size else 2048
                algo_name = f"RSA-{size}"
                purpose = "key_establishment"
            elif algo == "ECDSA":
                size = int(size) if size else 256
                algo_name = "ECDSA"
                purpose = "digital_signature"
            elif algo in ("ED25519",):
                algo_name = "Ed25519"
                size = 256
                purpose = "digital_signature"
            else:
                algo_name = algo
                size = int(size) if size else None
                purpose = "digital_signature"

            findings.append(_make_finding(
                algo_name, path, line=None,
                usage=f"cert-manager Certificate specification ({algo_name})",
                key_size=size, purpose=purpose, confidence=0.95,
                evidence=f"cert-manager Certificate: {doc.get('metadata', {}).get('name', 'unnamed')}",
                protocol="TLS", component="cert-manager",
            ))

        # 3. cert-manager Issuer / ClusterIssuer resource
        if kind in ("Issuer", "ClusterIssuer"):
            spec = doc.get("spec") or {}
            if "ca" in spec or "vault" in spec or "selfSigned" in spec:
                findings.append(_make_finding(
                    "X.509", path, line=None,
                    usage=f"cert-manager {kind} PKI authority",
                    purpose="digital_signature", confidence=0.85,
                    evidence=f"{kind}: {doc.get('metadata', {}).get('name', 'unnamed')}",
                    protocol="TLS", component="cert-manager",
                ))

    return findings


def _matches_filter(path: str, file_filter: set[str] | None) -> bool:
    if file_filter is None:
        return True
    norm_abs = os.path.abspath(path)
    norm_slash = norm_abs.replace("\\", "/")
    basename = os.path.basename(path)
    for f in file_filter:
        f_norm = os.path.abspath(f) if not os.path.isabs(f) else f
        if norm_abs == f_norm or norm_slash.endswith(f.replace("\\", "/")) or basename == f:
            return True
    return False


def scan_configs(root: str, errors: list, file_filter: set[str] | None = None) -> list[dict]:
    """
    Scans candidate configuration and protocol files across root directory or single file.
    Returns list of CryptographicArtefact finding dicts.
    """
    findings: list[dict] = []
    targets: list[str] = []

    if os.path.isfile(root):
        if _matches_filter(root, file_filter):
            targets = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in settings.SCAN_EXCLUDED_DIRS and not d.startswith(".")]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if _matches_filter(p, file_filter):
                    targets.append(p)

    for path in targets:
        base = os.path.basename(path).lower()
        try:
            if base in ("sshd_config", "ssh_config") or "sshd_config" in base or "ssh_config" in base:
                findings.extend(_scan_sshd_config(path))
            elif base in ("openssl.cnf", "openssl.conf"):
                findings.extend(_scan_openssl_cnf(path))
            elif base == "java.security":
                findings.extend(_scan_java_security(path))
            elif base in ("nginx.conf", "apache2.conf", "httpd.conf", "ssl.conf", "default.conf") or base.endswith((".vhost", ".conf")):
                findings.extend(_scan_web_server_ssl(path))
            elif base.endswith((".tf", ".tfvars", ".tf.json")):
                findings.extend(_scan_terraform(path))
            elif base.endswith((".yaml", ".yml")):
                findings.extend(_scan_k8s_cert_manager(path))
        except Exception as e:
            errors.append({"scanner": "config", "level": "error", "message": str(e), "file": path})

    return findings
