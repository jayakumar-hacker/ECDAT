"""
Tests for Feature F15: Self-eval harness on labelled demo data.
"""
import os
import json
from app.evaluation.scoring import calculate_prf, evaluate_scanner_findings, evaluate_scan_artefacts


def test_calculate_prf_perfect_match():
    # 10 TP, 0 FP, 0 FN -> 1.0 P, 1.0 R, 1.0 F1
    res = calculate_prf(10, 0, 0)
    assert res["precision"] == 1.0
    assert res["recall"] == 1.0
    assert res["f1"] == 1.0


def test_calculate_prf_zero_division_is_safe():
    res = calculate_prf(0, 0, 0)
    assert res["precision"] == 0.0
    assert res["recall"] == 0.0
    assert res["f1"] == 0.0


def test_calculate_prf_partial_score():
    # 5 TP, 5 FP, 5 FN -> P = 5/10 = 0.5, R = 5/10 = 0.5, F1 = 0.5
    res = calculate_prf(5, 5, 5)
    assert res["precision"] == 0.5
    assert res["recall"] == 0.5
    assert res["f1"] == 0.5


def test_evaluate_scanner_findings_matches_file_and_algorithm():
    expected = [
        {"file": "src/tokens.js", "algorithm": "RSA-4096"},
        {"file": "src/tokens.js", "algorithm": "ECDSA"},
        {"file": "src/missing.js", "algorithm": "AES-256"},
    ]
    detected = [
        {"file": "auth-service/src/tokens.js", "algorithm": "RSA-4096"},
        {"file": "auth-service/src/tokens.js", "algorithm": "ECDSA"},
        {"file": "auth-service/src/tokens.js", "algorithm": "DES"},  # Extra FP
    ]
    res = evaluate_scanner_findings(detected, expected)
    # TP: RSA, ECDSA (2)
    # FP: DES (1)
    # FN: missing.js AES-256 (1)
    assert res["true_positives"] == 2
    assert res["false_positives"] == 1
    assert res["false_negatives"] == 1
    assert res["recall"] == round(2 / 3, 4)
    assert res["precision"] == round(2 / 3, 4)


def test_ground_truth_file_is_valid():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    truth_path = os.path.join(repo_root, "demo-data", "expected-results", "ground_truth.json")
    assert os.path.exists(truth_path), f"Ground truth file not found at {truth_path}"

    with open(truth_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "expected_findings" in data
    findings = data["expected_findings"]
    for scanner in ("source", "dependency", "certificate", "container"):
        assert scanner in findings
        assert len(findings[scanner]) > 0
        for item in findings[scanner]:
            assert "file" in item
            assert "algorithm" in item


def test_evaluate_scan_artefacts_integration():
    ground_truth = {
        "expected_findings": {
            "source": [
                {"file": "app.py", "algorithm": "RSA"},
                {"file": "app.py", "algorithm": "AES"},
            ],
            "certificate": [
                {"file": "cert.pem", "algorithm": "RSA"},
            ],
        }
    }

    mock_artefacts = [
        {"artefact_type": "source", "file": "app.py", "algorithm": "RSA-2048"},
        {"artefact_type": "source", "file": "app.py", "algorithm": "AES-256"},
        {"artefact_type": "certificate", "file": "cert.pem", "algorithm": "RSA"},
    ]

    report = evaluate_scan_artefacts(mock_artefacts, ground_truth)
    assert "scanners" in report
    assert "source" in report["scanners"]
    assert "certificate" in report["scanners"]

    assert report["scanners"]["source"]["true_positives"] == 2
    assert report["scanners"]["source"]["recall"] == 1.0
    assert report["scanners"]["certificate"]["recall"] == 1.0
    assert report["overall"]["recall"] == 1.0
