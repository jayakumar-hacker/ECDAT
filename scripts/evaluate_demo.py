"""
Self-evaluation script for ECDAT: runs demo scan against bundled Acme Corp
demo repo and scores findings against annotated ground-truth.

Reports Precision, Recall, and F1 score per scanner.

Usage:
    python scripts/evaluate_demo.py
    python scripts/evaluate_demo.py --json
"""
import argparse
import json
import os
import sys

# Ensure backend is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.core.database import SessionLocal, init_db
from app.models import models
from app.services.scan_service import run_scan
from app.api.scans import DEMO_REPO_PATH
from app.evaluation.scoring import evaluate_scan_artefacts


def load_ground_truth(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def format_table(report: dict) -> str:
    lines = [
        "=" * 78,
        "  ECDAT SELF-EVALUATION REPORT: DEMO REPOSITORY GROUND TRUTH",
        "=" * 78,
        f"{'Scanner':<14} | {'Expected':<8} | {'Detected':<8} | {'TP':<5} | {'FP':<5} | {'FN':<5} | {'Precision':<9} | {'Recall':<8} | {'F1':<6}",
        "-" * 78,
    ]
    for scanner, s in report.get("scanners", {}).items():
        exp = s["total_expected"]
        det = s["total_detected"]
        tp = s["true_positives"]
        fp = s["false_positives"]
        fn = s["false_negatives"]
        prec = f"{s['precision']*100:.1f}%"
        rec = f"{s['recall']*100:.1f}%"
        f1 = f"{s['f1_score']:.3f}"
        lines.append(f"{scanner:<14} | {exp:<8} | {det:<8} | {tp:<5} | {fp:<5} | {fn:<5} | {prec:<9} | {rec:<8} | {f1:<6}")

    lines.append("-" * 78)
    o = report.get("overall", {})
    tot_exp = sum(s["total_expected"] for s in report.get("scanners", {}).values())
    tot_det = sum(s["total_detected"] for s in report.get("scanners", {}).values())
    tp = o.get("true_positives", 0)
    fp = o.get("false_positives", 0)
    fn = o.get("false_negatives", 0)
    prec = f"{o.get('precision', 0)*100:.1f}%"
    rec = f"{o.get('recall', 0)*100:.1f}%"
    f1 = f"{o.get('f1_score', 0):.3f}"
    lines.append(f"{'OVERALL':<14} | {tot_exp:<8} | {tot_det:<8} | {tp:<5} | {fp:<5} | {fn:<5} | {prec:<9} | {rec:<8} | {f1:<6}")
    lines.append("=" * 78)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Evaluate ECDAT scanners on annotated demo data.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    parser.add_argument("--truth", default=os.path.join(REPO_ROOT, "demo-data", "expected-results", "ground_truth.json"),
                        help="Path to ground_truth.json")
    args = parser.parse_args()

    if not os.path.exists(args.truth):
        print(f"Error: ground-truth file not found: {args.truth}", file=sys.stderr)
        sys.exit(1)

    ground_truth = load_ground_truth(args.truth)

    init_db()
    db = SessionLocal()
    try:
        scan = models.Scan(
            target=DEMO_REPO_PATH,
            target_type="demo",
            scanners_requested=["source", "dependency", "certificate", "binary", "container", "config"],
            status="pending",
            created_by="self-eval",
        )
        db.add(scan)
        db.commit()

        run_scan(db, scan)

        report = evaluate_scan_artefacts(scan.artefacts, ground_truth, base_dir=DEMO_REPO_PATH)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(format_table(report))
    finally:
        db.close()


if __name__ == "__main__":
    main()
