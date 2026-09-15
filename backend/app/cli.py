"""
ECDAT Command Line Interface (ecdat).

Supports diff-native CI mode and policy-as-code gating:
  ecdat scan . --since main --policy ecdat-policy.yaml
"""
import argparse
import json
import os
import sys

from app.core.database import SessionLocal, init_db
from app.models import models
from app.services.scan_service import run_scan
from app.services.policy_service import load_policy, evaluate_policy, format_policy_report
from app.services.migration_service import build_migration_plans_for_scan
from app.services.hndl_service import evaluate_hndl, resolve_threshold
from app.api.serializers import serialize_asset


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecdat",
        description="ECDAT: Enterprise Cryptographic Discovery & Analysis Tool",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Scan repository or directory for cryptography")
    scan_p.add_argument("target", nargs="?", default=".", help="Target path to scan (default: current directory)")
    scan_p.add_argument("--since", dest="since_ref", default=None, help="Scan only files modified since this git ref (e.g. main, HEAD~1)")
    scan_p.add_argument("--policy", dest="policy_path", default=None, help="Path to ecdat-policy.yaml file")
    scan_p.add_argument("--scanners", default=None, help="Comma-separated list of scanners (source,dependency,certificate,binary,container,config)")
    scan_p.add_argument("--json", action="store_true", help="Output results in JSON format")
    scan_p.add_argument("--fail-on-violation", action="store_true", default=True, help="Exit with code 1 if policy violations are found (default: True)")
    scan_p.add_argument("--no-fail-on-violation", dest="fail_on_violation", action="store_false", help="Do not exit with code 1 on policy violation")

    # Check-policy command
    pol_p = subparsers.add_parser("check-policy", help="Evaluate policy-as-code rules on a target or scan")
    pol_p.add_argument("target", nargs="?", default=".", help="Target directory containing scan and/or ecdat-policy.yaml")
    pol_p.add_argument("--policy", dest="policy_path", default=None, help="Path to ecdat-policy.yaml")
    pol_p.add_argument("--scan-id", default=None, help="Existing scan ID to evaluate")
    pol_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # HNDL lens command
    hndl_p = subparsers.add_parser("hndl", help="Harvest-now-decrypt-later (HNDL) exposure lens over prior scans")
    hndl_p.add_argument("target", nargs="?", default=".", help="Target directory whose most recent scan should be evaluated")
    hndl_p.add_argument("--scan-id", default=None, help="Existing scan ID to evaluate")
    hndl_p.add_argument("--shelf-life-threshold-years", dest="threshold_years", type=int, default=None,
                        help="Override the shelf-life threshold in years (default from settings)")
    hndl_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # Drift command
    drift_p = subparsers.add_parser("drift", help="Crypto-posture drift dashboard across historical scans")
    drift_p.add_argument("target", nargs="?", default=None, help="Target directory to evaluate drift for (default: most recent target)")
    drift_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    return parser



def main(args: list[str] | None = None) -> int:
    init_db()
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    # Resolve target path — drift allows None (meaning "most recent scan")
    target = os.path.abspath(parsed.target) if getattr(parsed, "target", None) else None


    if parsed.command == "scan":
        scanners_list = None
        if parsed.scanners:
            scanners_list = [s.strip() for s in parsed.scanners.split(",") if s.strip()]

        db = SessionLocal()
        try:
            scan = models.Scan(
                target=target,
                target_type="file" if os.path.isfile(target) else "directory",
                scanners_requested=scanners_list,
                created_by="cli",
            )
            db.add(scan)
            db.commit()

            run_scan(
                db=db,
                scan=scan,
                since_ref=parsed.since_ref,
                policy_path=parsed.policy_path,
            )

            # Build migration plans
            build_migration_plans_for_scan(db, scan.id)

            violations = scan.policy_violations or []

            if parsed.json:
                assets = db.query(models.Asset).filter(models.Asset.scan_id == scan.id).all()
                out = {
                    "scan_id": scan.id,
                    "target": scan.target,
                    "status": scan.status,
                    "since_git_ref": scan.since_git_ref,
                    "files_scanned": scan.files_scanned,
                    "artefacts_found": scan.artefacts_found,
                    "policy_status": scan.policy_status,
                    "policy_violations": violations,
                    "assets": [serialize_asset(a) for a in assets],
                }
                print(json.dumps(out, indent=2, default=str))
            else:
                print("=" * 70)
                print(f"ECDAT Cryptographic Scan Complete: {scan.status.upper()}")
                print(f"Target: {scan.target}")
                if scan.since_git_ref:
                    print(f"Diff-native mode: scanned files modified since '{scan.since_git_ref}'")
                print(f"Files scanned: {scan.files_scanned} | Artefacts found: {scan.artefacts_found}")
                print("=" * 70)

                if scan.policy_status != "NOT_RUN":
                    report = format_policy_report(violations, parsed.policy_path or "")
                    print(report)

            if parsed.fail_on_violation and violations:
                return 1
            return 0
        finally:
            db.close()

    elif parsed.command == "check-policy":
        db = SessionLocal()
        try:
            policy_dict, loaded_path = load_policy(parsed.policy_path or target)
            if not policy_dict:
                print(f"Error: No policy file found at {parsed.policy_path or target}", file=sys.stderr)
                return 2

            scan = None
            if parsed.scan_id:
                scan = db.query(models.Scan).filter(models.Scan.id == parsed.scan_id).first()
            if not scan:
                scan = db.query(models.Scan).filter(models.Scan.target == target).order_by(models.Scan.created_at.desc()).first()

            if not scan:
                print(f"Error: No scan found for target {target}. Run 'ecdat scan' first.", file=sys.stderr)
                return 2

            violations = evaluate_policy(policy_dict, scan, db)
            if parsed.json:
                print(json.dumps({"policy_status": "FAIL" if violations else "PASS", "violations": violations}, indent=2))
            else:
                print(format_policy_report(violations, loaded_path or ""))

            return 1 if violations else 0
        finally:
            db.close()

    elif parsed.command == "hndl":
        db = SessionLocal()
        try:
            scan = None
            if parsed.scan_id:
                scan = db.query(models.Scan).filter(models.Scan.id == parsed.scan_id).first()
            if not scan:
                scan = db.query(models.Scan).filter(models.Scan.target == target).order_by(models.Scan.created_at.desc()).first()

            if not scan:
                print(f"Error: No scan found for target {target}. Run 'ecdat scan' first.", file=sys.stderr)
                return 2

            matched = evaluate_hndl(db, scan_id=scan.id, shelf_life_threshold_years=parsed.threshold_years)
            threshold = resolve_threshold(parsed.threshold_years)

            if parsed.json:
                print(json.dumps({
                    "scan_id": scan.id,
                    "threshold_years": threshold,
                    "count": len(matched),
                    "assets": matched,
                }, indent=2, default=str))
            else:
                print("=" * 70)
                print("ECDAT Harvest-now-decrypt-later (HNDL) Exposure Lens")
                print(f"Scan: {scan.id} | Target: {scan.target}")
                print(f"Shelf-life threshold: {threshold} years")
                print("=" * 70)
                if not matched:
                    print("Status: [PASS] - No asset matches the HNDL profile "
                          "(internet-exposed/captured-in-transit + long shelf-life + quantum-vulnerable key exchange).")
                else:
                    print(f"Status: {len(matched)} asset(s) match the HNDL profile:")
                    print("-" * 70)
                    for i, m in enumerate(matched, start=1):
                        print(f"{i}. [{m['algorithm_name']}] {m['name']} ({m['location']})")
                        print(f"   Reason: {m['hndl_reason']}")
                    print("-" * 70)
                    print("Action required: treat as harvest-now-decrypt-later risk; remediate now, not at Q-Day.")
            return 0
        finally:
            db.close()

    elif parsed.command == "drift":
        from app.services.drift_service import compute_posture_drift
        db = SessionLocal()
        try:
            target = os.path.abspath(parsed.target) if parsed.target else None
            res = compute_posture_drift(db, target=target)
            if parsed.json:
                print(json.dumps(res, indent=2))
            else:
                print("=" * 72)
                print("ECDAT Crypto-Posture Drift Trend Dashboard")
                print(f"Target: {res['target']} | Historical Scans Tracked: {res['scans_tracked']}")
                print("=" * 72)
                if not res["history"]:
                    print("No historical completed scans found for this target.")
                else:
                    print(f"{'Timestamp':<20} | {'Vulnerable':<10} | {'PQC %':<7} | {'Avg Priority':<12} | {'Total Artefacts':<15}")
                    print("-" * 72)
                    for h in res["history"]:
                        ts = (h["timestamp"] or "")[:19]
                        print(f"{ts:<20} | {h['vulnerable_artefacts_count']:<10} | {h['pqc_adoption_percentage']:<6.1f}% | {h['average_migration_priority']:<12.2f} | {h['total_artefacts']:<15}")
                    if res.get("delta"):
                        d = res["delta"]
                        print("-" * 72)
                        print("Posture Drift Summary:")
                        print(f"  - Vulnerable Artefacts Delta: {d['vulnerable_artefacts_delta']:+d}")
                        print(f"  - PQC Adoption Delta:         {d['pqc_adoption_percentage_delta']:+.2f}%")
                        print(f"  - Avg Migration Priority:     {d['average_migration_priority_delta']:+.2f}")
                        print(f"  - Overall Posture Improved:   {'YES' if d['posture_improved'] else 'NO'}")
                print("=" * 72)
            return 0
        finally:
            db.close()

    return 0



if __name__ == "__main__":
    sys.exit(main())
