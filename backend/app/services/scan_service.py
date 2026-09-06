"""
Scan orchestrator.

Coordinates the individual scanners, persists results to the database,
and normalizes findings into CryptographicArtefact + Asset rows so that
downstream engines (CBOM, risk, Mosca, recommendations, migration) all
operate on the same normalized data.

A failure in one scanner is recorded as scan evidence and does not abort
the whole scan (see app/models/models.py:ScanEvidence).
"""
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models import models
from app.scanners.source.scanner import scan_source
from app.scanners.dependency.scanner import scan_dependencies
from app.scanners.certificate.scanner import scan_certificates
from app.scanners.binary.scanner import scan_binaries
from app.scanners.container.scanner import scan_containers
from app.scanners.config.scanner import scan_configs
from app.core.logging import logger, audit

VALID_SCANNERS = {"source", "dependency", "certificate", "binary", "container", "config"}


def get_changed_files_since(target_dir: str, git_ref: str) -> set[str]:
    """
    Returns set of paths of files modified or added since git_ref.
    """
    import subprocess
    if not os.path.isdir(target_dir):
        return {os.path.abspath(target_dir)}

    res = subprocess.run(
        ["git", "diff", "--name-only", git_ref],
        cwd=target_dir,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git diff failed: {res.stderr.strip()}")

    changed = set()
    for line in res.stdout.splitlines():
        rel = line.strip()
        if rel:
            changed.add(rel)
            changed.add(rel.replace("\\", "/"))
            changed.add(os.path.abspath(os.path.join(target_dir, rel)))

    # Also capture untracked / new files
    res_untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=target_dir,
        capture_output=True,
        text=True,
    )
    if res_untracked.returncode == 0:
        for line in res_untracked.stdout.splitlines():
            rel = line.strip()
            if rel:
                changed.add(rel)
                changed.add(rel.replace("\\", "/"))
                changed.add(os.path.abspath(os.path.join(target_dir, rel)))

    return changed


def run_scan(
    db: Session,
    scan: models.Scan,
    since_ref: str | None = None,
    changed_files: set[str] | None = None,
    policy_path: str | None = None,
) -> models.Scan:
    scan.status = "running"
    scan.start_time = datetime.now(timezone.utc)
    if since_ref:
        scan.since_git_ref = since_ref
    db.commit()

    target = scan.target
    requested = set(scan.scanners_requested or list(VALID_SCANNERS))
    errors: list[dict] = []
    total_files_scanned = 0
    artefact_count = 0

    if not os.path.exists(target):
        scan.status = "failed"
        scan.errors = [{"scanner": "orchestrator", "level": "error",
                         "message": f"Target path does not exist: {target}", "file": target}]
        scan.end_time = datetime.now(timezone.utc)
        db.commit()
        return scan

    # Resolve git diff if since_ref requested
    if since_ref and changed_files is None:
        try:
            changed_files = get_changed_files_since(target, since_ref)
        except Exception as e:
            errors.append({"scanner": "orchestrator", "level": "warning",
                           "message": f"Could not compute git diff since {since_ref}: {e}", "file": target})
            changed_files = None

    try:
        # 1. Source code scanning
        if "source" in requested:
            try:
                findings, files_scanned = scan_source(target, errors, file_filter=changed_files)
                total_files_scanned += files_scanned
                for f in findings:
                    artefact = models.CryptographicArtefact(
                        scan_id=scan.id, artefact_type="source", algorithm=f["algorithm"],
                        file=f["file"], line=f["line"], language=f["language"], usage=f["usage"],
                        key_size=f["key_size"], purpose=f["purpose"], confidence=f["confidence"],
                        evidence=f["evidence"], provenance_risk=f.get("provenance_risk", "unknown"),
                    )
                    db.add(artefact)
                    artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "source", "level": "error", "message": str(e), "file": target})
                logger.exception("Source scanner failed")

        # 2. Dependency scanning
        if "dependency" in requested:
            try:
                deps = scan_dependencies(target, errors, file_filter=changed_files)
                for d in deps:
                    dep_row = models.Dependency(
                        scan_id=scan.id, name=d["name"], version=d["version"], ecosystem=d["ecosystem"],
                        source_file=d["source_file"], crypto_related=d["crypto_related"],
                        known_algorithms=d["known_algorithms"], confidence=d["confidence"],
                        is_transitive=d.get("is_transitive", False),
                        depth=d.get("depth", 0),
                        parent_dependency=d.get("parent_dependency", ""),
                        provenance_chain=d.get("provenance_chain", []),
                    )
                    db.add(dep_row)
                    if d["crypto_related"]:
                        lib_row = models.Library(
                            scan_id=scan.id, name=d["name"], version=d["version"], ecosystem=d["ecosystem"],
                            source_file=d["source_file"], crypto_capable=True,
                            known_algorithms=d["known_algorithms"], confidence=d["confidence"],
                        )
                        db.add(lib_row)
                        for algo in d["known_algorithms"]:
                            chain = d.get("provenance_chain", [])
                            chain_str = " -> ".join(chain) if chain else d["name"]
                            if d.get("is_transitive"):
                                parent = d.get("parent_dependency") or (chain[0] if chain else "direct")
                                depth = d.get("depth", 1)
                                usage = f"Transitive crypto dependency: {d['name']} (depth {depth} via {parent})"
                                evidence = f"{d['name']}=={d['version']} [transitive depth={depth} chain={chain_str}]"
                            else:
                                usage = f"Crypto-capable dependency: {d['name']}"
                                evidence = f"{d['name']}=={d['version']}"
                            artefact = models.CryptographicArtefact(
                                scan_id=scan.id, artefact_type="dependency", algorithm=algo,
                                file=d["source_file"], language="", usage=usage,
                                purpose="", confidence=d["confidence"], evidence=evidence,
                                library=d["name"],
                            )
                            db.add(artefact)
                            artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "dependency", "level": "error", "message": str(e), "file": target})
                logger.exception("Dependency scanner failed")

        # 3. Certificate scanning
        if "certificate" in requested:
            try:
                certs = scan_certificates(target, errors, file_filter=changed_files)
                for c in certs:
                    cert_row = models.Certificate(
                        scan_id=scan.id, file=c["file"], subject=c.get("subject", ""),
                        issuer=c.get("issuer", ""), serial_number=c.get("serial_number", ""),
                        valid_from=c.get("valid_from"), valid_until=c.get("valid_until"),
                        expired=c.get("expired", False), days_remaining=c.get("days_remaining"),
                        public_key_algorithm=c.get("public_key_algorithm", ""), key_size=c.get("key_size"),
                        signature_algorithm=c.get("signature_algorithm", ""), san=c.get("san", []),
                        weak_key=c.get("weak_key", False), weak_signature=c.get("weak_signature", False),
                        parse_error=c.get("parse_error"),
                    )
                    db.add(cert_row)
                    db.flush()
                    if not c.get("parse_error"):
                        artefact = models.CryptographicArtefact(
                            scan_id=scan.id, artefact_type="certificate",
                            algorithm=c.get("public_key_algorithm", "unknown"), file=c["file"],
                            usage="X.509 certificate public key algorithm", key_size=c.get("key_size"),
                            purpose="digital_signature", confidence=0.95,
                            evidence=f"Subject: {c.get('subject','')}", certificate_id=cert_row.id,
                        )
                        db.add(artefact)
                        artefact_count += 1
                        if c.get("signature_algorithm"):
                            sig_algo_name = "SHA-1" if "sha1" in c["signature_algorithm"].lower() else (
                                "MD5" if "md5" in c["signature_algorithm"].lower() else "SHA-256")
                            artefact2 = models.CryptographicArtefact(
                                scan_id=scan.id, artefact_type="certificate", algorithm=sig_algo_name,
                                file=c["file"], usage="X.509 certificate signature algorithm",
                                purpose="hashing", confidence=0.9,
                                evidence=c["signature_algorithm"], certificate_id=cert_row.id,
                            )
                            db.add(artefact2)
                            artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "certificate", "level": "error", "message": str(e), "file": target})
                logger.exception("Certificate scanner failed")

        # 4. Binary scanning
        if "binary" in requested:
            try:
                bin_findings = scan_binaries(target, errors, file_filter=changed_files)
                for b in bin_findings:
                    artefact = models.CryptographicArtefact(
                        scan_id=scan.id, artefact_type="binary", algorithm=b["label"], file=b["file"],
                        usage=b["note"], purpose="", confidence={"HIGH": 0.8, "MEDIUM": 0.55, "LOW": 0.3}.get(b["confidence_level"], 0.4),
                        evidence=f"format={b['format']} evidence={b['evidence_type']}",
                    )
                    db.add(artefact)
                    artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "binary", "level": "error", "message": str(e), "file": target})
                logger.exception("Binary scanner failed")

        # 5. Container scanning
        if "container" in requested:
            try:
                container_result = scan_containers(target, errors, file_filter=changed_files)
                for pkg_dep in container_result["crypto_packages"]:
                    for algo in pkg_dep["known_algorithms"]:
                        artefact = models.CryptographicArtefact(
                            scan_id=scan.id, artefact_type="container", algorithm=algo,
                            file=pkg_dep["source_file"], usage=f"Container base package: {pkg_dep['name']}",
                            purpose="", confidence=pkg_dep["confidence"], library=pkg_dep["name"],
                        )
                        db.add(artefact)
                        artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "container", "level": "error", "message": str(e), "file": target})
                logger.exception("Container scanner failed")

        # 6. Config & protocol scanning
        if "config" in requested:
            try:
                config_findings = scan_configs(target, errors, file_filter=changed_files)
                for c in config_findings:
                    artefact = models.CryptographicArtefact(
                        scan_id=scan.id, artefact_type="config", algorithm=c["algorithm"],
                        file=c["file"], line=c.get("line"), language=c.get("language", "config"),
                        usage=c.get("usage", "Configured cryptographic parameter"),
                        key_size=c.get("key_size"), purpose=c.get("purpose", ""),
                        confidence=c.get("confidence", 0.85),
                        evidence=c.get("evidence", ""),
                        protocol=c.get("protocol", ""),
                        component=c.get("component", ""),
                    )
                    db.add(artefact)
                    artefact_count += 1
            except Exception as e:
                errors.append({"scanner": "config", "level": "error", "message": str(e), "file": target})
                logger.exception("Config scanner failed")

        db.flush()

        # Persist scan evidence (warnings/errors gathered above)
        for e in errors:
            db.add(models.ScanEvidence(
                scan_id=scan.id, scanner=e.get("scanner", "unknown"),
                level=e.get("level", "info"), message=e.get("message", ""), file=e.get("file", ""),
            ))

        # Build Asset rows from artefacts (group source/certificate findings into assets)
        from app.services.risk_service import build_assets_from_artefacts
        build_assets_from_artefacts(db, scan.id)

        # Policy-as-code evaluation
        from app.services.policy_service import load_policy, evaluate_policy
        policy_dict, loaded_policy_path = load_policy(policy_path or target)
        if policy_dict:
            violations = evaluate_policy(policy_dict, scan, db)
            scan.policy_violations = violations
            scan.policy_status = "FAIL" if violations else "PASS"
        else:
            scan.policy_violations = []
            scan.policy_status = "NOT_RUN"

        scan.status = "completed"
        scan.files_scanned = total_files_scanned
        scan.artefacts_found = artefact_count
        scan.errors = errors
        scan.end_time = datetime.now(timezone.utc)
        db.commit()
        audit("scan_completed", scan.created_by or "system", f"scan_id={scan.id} target={target}")

    except Exception as e:
        db.rollback()
        scan.status = "failed"
        scan.errors = [{"scanner": "orchestrator", "level": "error", "message": str(e), "file": target}]
        scan.end_time = datetime.now(timezone.utc)
        db.commit()
        logger.exception("Scan failed")

    return scan
