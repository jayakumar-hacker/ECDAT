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

    return parser


def main(args: list[str] | None = None) -> int:
    init_db()
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    target = os.path.abspath(parsed.target)

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
