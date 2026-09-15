"""
Loads the offline crypto knowledge base (knowledge-base/algorithms/algorithms.json)
and exposes lookup helpers. No network access required.
"""
import json
import os

_KB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "knowledge-base", "algorithms", "algorithms.json",
)

_cache: list[dict] | None = None


def load_algorithms() -> list[dict]:
    global _cache
    if _cache is None:
        with open(_KB_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache


def get_algorithm(name: str) -> dict | None:
    name_norm = name.strip().upper()
    for algo in load_algorithms():
        if algo["name"].upper() == name_norm:
            return algo
    return None


def is_quantum_vulnerable(name: str) -> bool:
    algo = get_algorithm(name)
    if algo is None:
        # Unknown algorithm: conservative default - flag for manual review, do not silently mark safe.
        return True
    return bool(algo["quantum_vulnerable"])
