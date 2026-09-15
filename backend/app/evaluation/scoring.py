"""
Self-evaluation and scoring harness for ECDAT scanners on labelled ground-truth data.

Computes Precision, Recall, and F1 score per scanner type:
  Precision = TP / (TP + FP)   [Of findings surfaced, what fraction was genuine?]
  Recall    = TP / (TP + FN)   [Of ground-truth items, what fraction was surfaced?]
  F1        = 2 * (Precision * Recall) / (Precision + Recall)
"""
import os
import re
from typing import Any


def _normalize_algo_name(name: str) -> str:
    """Normalize algorithm name for flexible ground-truth matching."""
    n = (name or "").upper().strip()
    # Map common aliases/sizes to family
    if n.startswith("RSA"):
        return "RSA"
    if n.startswith("ECDSA") or "ECDSA" in n:
        return "ECDSA"
    if n.startswith("ECDH") or "ECDH" in n:
        return "ECDH"
    if "ED25519" in n:
        return "ED25519"
    if n.startswith("AES"):
        return "AES"
    if n in ("3DES", "DES"):
        return "DES"
    if n.startswith("SHA-2") or n == "SHA-256":
        return "SHA-256"
    if n == "SHA-1":
        return "SHA-1"
    if n.startswith("TLS"):
        return "TLS"
    return n


def _normalize_path(path: str) -> str:
    """Normalize file path to unix relative path."""
    return (path or "").replace("\\", "/").lower().strip()


def calculate_prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Calculate precision, recall, and F1 given TP, FP, FN."""
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def evaluate_scanner_findings(
    detected_findings: list[dict[str, Any]],
    expected_findings: list[dict[str, Any]],
    base_dir: str = "",
) -> dict[str, Any]:
    """
    Evaluate detected findings against expected findings for a single scanner.
    
    Matches on (relative_file_path_suffix, normalized_algorithm_family).
    """
    # Build expected signature set: (file_suffix, normalized_algo)
    expected_set: set[tuple[str, str]] = set()
    for exp in expected_findings:
        f_norm = _normalize_path(exp.get("file", ""))
        a_norm = _normalize_algo_name(exp.get("algorithm", ""))
        expected_set.add((f_norm, a_norm))

    detected_set: set[tuple[str, str]] = set()
    for det in detected_findings:
        raw_file = det.get("file") or ""
        if base_dir and raw_file.startswith(base_dir):
            rel = os.path.relpath(raw_file, base_dir)
        else:
            rel = raw_file
        f_norm = _normalize_path(rel)
        a_norm = _normalize_algo_name(det.get("algorithm", ""))
        # Match by checking if any expected file matches suffix of detected file
        matched_file = None
        for exp_f, _ in expected_set:
            if exp_f in f_norm or f_norm.endswith(exp_f):
                matched_file = exp_f
                break
        matched_f = matched_file if matched_file else f_norm
        detected_set.add((matched_f, a_norm))

    tp = len(detected_set.intersection(expected_set))
    fp = len(detected_set - expected_set)
    fn = len(expected_set - detected_set)

    prf = calculate_prf(tp, fp, fn)

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": prf["precision"],
        "recall": prf["recall"],
        "f1_score": prf["f1"],
        "total_detected": len(detected_set),
        "total_expected": len(expected_set),
    }


def evaluate_scan_artefacts(
    artefacts: list[Any],
    ground_truth: dict[str, Any],
    base_dir: str = "",
) -> dict[str, Any]:
    """
    Score all scanners across a complete scan result against ground truth.
    """
    expected_by_scanner = ground_truth.get("expected_findings", {})
    detected_by_scanner: dict[str, list[dict]] = {}

    for a in artefacts:
        scanner_type = getattr(a, "artefact_type", None) or (a.get("artefact_type") if isinstance(a, dict) else "source")
        file_path = getattr(a, "file", None) or (a.get("file") if isinstance(a, dict) else "")
        algo = getattr(a, "algorithm", None) or (a.get("algorithm") if isinstance(a, dict) else "")
        purpose = getattr(a, "purpose", None) or (a.get("purpose") if isinstance(a, dict) else "")

        detected_by_scanner.setdefault(scanner_type, []).append({
            "file": file_path,
            "algorithm": algo,
            "purpose": purpose,
        })

    report: dict[str, Any] = {"scanners": {}}
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for scanner, expected in expected_by_scanner.items():
        detected = detected_by_scanner.get(scanner, [])
        res = evaluate_scanner_findings(detected, expected, base_dir=base_dir)
        report["scanners"][scanner] = res
        total_tp += res["true_positives"]
        total_fp += res["false_positives"]
        total_fn += res["false_negatives"]

    overall_prf = calculate_prf(total_tp, total_fp, total_fn)
    report["overall"] = {
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "precision": overall_prf["precision"],
        "recall": overall_prf["recall"],
        "f1_score": overall_prf["f1"],
    }
    return report
