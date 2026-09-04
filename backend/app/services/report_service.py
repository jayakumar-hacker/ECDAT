"""
Report generation: JSON, CSV, and PDF (via reportlab).
"""
import json
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import models
from app.services.cbom_service import generate_cbom, cbom_to_csv
from app.services.hndl_service import evaluate_hndl, resolve_threshold
from app.core.config import settings


def build_report_data(db: Session, scan_id: str) -> dict:
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise ValueError("Scan not found")

    assets = db.query(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    risks = [a.risk_assessment for a in assets if a.risk_assessment]
    critical = [r for r in risks if r.severity == "CRITICAL"]
    high = [r for r in risks if r.severity == "HIGH"]

    certificates = db.query(models.Certificate).filter(models.Certificate.scan_id == scan_id).all()
    libraries = db.query(models.Library).filter(models.Library.scan_id == scan_id).all()
    migration_plans = db.query(models.MigrationPlan).join(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    recommendations = db.query(models.Recommendation).join(models.Asset).filter(models.Asset.scan_id == scan_id).all()
    hndl_matched = evaluate_hndl(db, scan_id=scan_id)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "target": scan.target,
            "files_scanned": scan.files_scanned,
            "artefacts_found": scan.artefacts_found,
            "total_assets": len(assets),
            "critical_risks": len(critical),
            "high_risks": len(high),
            "certificates_found": len(certificates),
            "crypto_libraries_found": len(libraries),
        },
        "scan_information": {
            "id": scan.id, "target": scan.target, "status": scan.status,
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "scanners_requested": scan.scanners_requested,
        },
        "cryptographic_inventory": generate_cbom(db, scan_id)["components"],
        "critical_findings": [
            {"asset": next((a.name for a in assets if a.id == r.asset_id), "?"), "score": r.score, "severity": r.severity, "factors": r.factors}
            for r in critical
        ],
        "quantum_risk_summary": {
            "LOW": len([r for r in risks if r.severity == "LOW"]),
            "MEDIUM": len([r for r in risks if r.severity == "MEDIUM"]),
            "HIGH": len(high),
            "CRITICAL": len(critical),
        },
        "pqc_recommendations": [
            {"current": r.current_algorithm, "recommended": r.recommended_algorithm,
             "type": r.recommended_type, "priority": r.priority, "reason": r.reason}
            for r in recommendations
        ],
        "migration_priorities": [
            {"priority": p.priority, "rationale": p.rationale, "replacement": p.replacement, "blockers": p.blockers}
            for p in migration_plans
        ],
        "hndl_lens": {
            "threshold_years": resolve_threshold(None),
            "count": len(hndl_matched),
            "assets": hndl_matched,
        },
        "certificates": [
            {"file": c.file, "subject": c.subject, "expired": c.expired, "days_remaining": c.days_remaining,
             "public_key_algorithm": c.public_key_algorithm, "key_size": c.key_size, "weak_key": c.weak_key,
             "weak_signature": c.weak_signature}
            for c in certificates
        ],
        "libraries": [{"name": l.name, "version": l.version, "ecosystem": l.ecosystem} for l in libraries],
        "limitations": [
            "Static analysis only; findings reflect pattern matches, not proven runtime behavior.",
            "Risk scoring is an ECDAT-defined model, not an official NIST/CVSS score.",
            "Threat horizon and migration timelines are configurable assumptions, not predictions.",
        ],
    }


def export_json(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def hndl_to_csv(db: Session, scan_id: str) -> str:
    """CSV section for the HNDL exposure lens (additive, does not replace CBOM rows)."""
    import csv as _csv
    import io as _io
    matched = evaluate_hndl(db, scan_id=scan_id)
    output = _io.StringIO()
    fieldnames = ["asset_id", "name", "algorithm", "purpose", "business_asset",
                  "internet_exposed", "data_sensitivity", "data_retention_years",
                  "hndl_exposed", "hndl_reason"]
    writer = _csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for m in matched:
        writer.writerow({
            "asset_id": m.get("asset_id", ""),
            "name": m.get("name", ""),
            "algorithm": m.get("algorithm_name", ""),
            "purpose": m.get("purpose", ""),
            "business_asset": m.get("business_asset", ""),
            "internet_exposed": m.get("internet_exposed", ""),
            "data_sensitivity": m.get("data_sensitivity", ""),
            "data_retention_years": m.get("data_retention_years", ""),
            "hndl_exposed": m.get("hndl_exposed", ""),
            "hndl_reason": m.get("hndl_reason", ""),
        })
    return output.getvalue()


def export_csv(db: Session, scan_id: str, path: str):
    cbom = generate_cbom(db, scan_id)
    csv_text = cbom_to_csv(cbom)
    # Append the HNDL exposure lens as an additional section (not a replacement).
    hndl_section = hndl_to_csv(db, scan_id)
    with open(path, "w", encoding="utf-8") as f:
        f.write(csv_text)
        f.write("\n")
        f.write("# Harvest-now-decrypt-later (HNDL) exposure lens\n")
        f.write(hndl_section)
        if not hndl_section.endswith("\n"):
            f.write("\n")


def export_pdf(data: dict, path: str):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors

    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("ECDAT Cryptographic Risk Report", styles["Title"]), Spacer(1, 12)]

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    for k, v in data["executive_summary"].items():
        story.append(Paragraph(f"<b>{k.replace('_',' ').title()}:</b> {v}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Quantum Risk Summary", styles["Heading2"]))
    risk_table_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in data["quantum_risk_summary"].items()]
    t = Table(risk_table_data)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey)]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Critical Findings", styles["Heading2"]))
    if data["critical_findings"]:
        for f in data["critical_findings"][:25]:
            story.append(Paragraph(f"{f['asset']} - score {f['score']} ({f['severity']})", styles["Normal"]))
    else:
        story.append(Paragraph("None identified in this scan.", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("PQC Recommendations", styles["Heading2"]))
    for r in data["pqc_recommendations"][:30]:
        story.append(Paragraph(f"{r['current']} -> {r['recommended']} ({r['priority']} priority)", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Limitations", styles["Heading2"]))
    for lim in data["limitations"]:
        story.append(Paragraph(f"- {lim}", styles["Normal"]))

    doc.build(story)
