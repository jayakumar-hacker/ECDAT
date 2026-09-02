from app.crypto.classifier import classify_line, dedupe_findings
from app.crypto.knowledge_base import get_algorithm, is_quantum_vulnerable, load_algorithms


def test_classify_line_basic():
    findings = classify_line("cipher = AES256(key)", "test.py", 1, "python")
    assert any(f["algorithm"] == "AES-256" for f in findings)


def test_dedupe_keeps_highest_confidence():
    findings = [
        {"algorithm": "RSA", "file": "a.py", "line": 1, "confidence": 0.5},
        {"algorithm": "RSA", "file": "a.py", "line": 1, "confidence": 0.9},
    ]
    deduped = dedupe_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["confidence"] == 0.9


def test_knowledge_base_loads():
    algos = load_algorithms()
    assert len(algos) > 20
    names = {a["name"] for a in algos}
    assert "RSA-2048" in names
    assert "AES-256" in names
    assert "ML-KEM" not in names  # PQC algos are recommendations, not scanned targets


def test_rsa_is_quantum_vulnerable():
    assert is_quantum_vulnerable("RSA-2048") is True


def test_aes256_is_not_quantum_vulnerable():
    assert is_quantum_vulnerable("AES-256") is False


def test_unknown_algorithm_defaults_conservative():
    assert is_quantum_vulnerable("SomeUnknownAlgorithm") is True


def test_get_algorithm_case_insensitive():
    assert get_algorithm("rsa-2048") is not None
    assert get_algorithm("RSA-2048")["name"] == "RSA-2048"
