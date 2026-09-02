"""
AI Assistant (optional).

Core principle: the assistant must retrieve structured ECDAT data before
answering, and must never invent scan findings. If no LLM is configured
(AI_ENABLED=false, the default), it falls back to a deterministic
keyword-routed query engine that answers directly from the database -
this fallback is always available and requires no network access.

If an LLM IS configured (Ollama or an OpenAI-compatible API), the
retrieved structured data is passed to the model as context and the
model is instructed to answer only from that context. Source code is
never sent externally unless AI_ALLOW_EXTERNAL_CONTEXT is explicitly
set to true.
"""
from sqlalchemy.orm import Session
from app.models import models
from app.core.config import settings


def _gather_context(db: Session, scan_id: str | None) -> dict:
    asset_q = db.query(models.Asset)
    if scan_id:
        asset_q = asset_q.filter(models.Asset.scan_id == scan_id)
    assets = asset_q.all()

    risky = sorted(
        [a for a in assets if a.risk_assessment],
        key=lambda a: a.risk_assessment.score, reverse=True,
    )
    return {"assets": assets, "risky": risky}


def _deterministic_answer(question: str, ctx: dict) -> str:
    q = question.lower()
    assets = ctx["assets"]
    risky = ctx["risky"]

    if not assets:
        return "No scan data is available yet for this query. Run a scan first."

    if "most vulnerable" in q or "quantum" in q and ("which" in q or "what" in q):
        top = [a for a in risky if a.risk_assessment.severity in ("CRITICAL", "HIGH")][:5]
        if not top:
            return "No CRITICAL or HIGH severity quantum-risk assets were found in this scan."
        lines = [f"- {a.name}: risk score {a.risk_assessment.score} ({a.risk_assessment.severity})" for a in top]
        return "The most quantum-vulnerable assets in this scan are:\n" + "\n".join(lines)

    if "sha-1" in q or "sha1" in q:
        matches = [a for a in assets if (a.algorithm_name or "").upper() == "SHA-1"]
        return f"{len(matches)} SHA-1 asset(s) were found." + (
            "" if not matches else " Files: " + ", ".join(sorted({a.location.split(':')[0] for a in matches if a.location})[:10]))

    if "rsa" in q and "migrat" in q:
        rsa_assets = sorted(
            [a for a in assets if (a.algorithm_name or "").upper().startswith("RSA") and a.risk_assessment],
            key=lambda a: a.risk_assessment.score, reverse=True,
        )
        if not rsa_assets:
            return "No RSA assets were found in this scan."
        lines = [f"- {a.name}: risk {a.risk_assessment.score} ({a.risk_assessment.severity}), priority: "
                 f"{a.recommendation.priority if a.recommendation else 'not analyzed'}" for a in rsa_assets[:8]]
        return "RSA assets ranked by migration priority (highest risk first):\n" + "\n".join(lines)

    if "mosca" in q:
        m_assets = [a for a in assets if a.mosca_assessment]
        if not m_assets:
            return "No Mosca analysis is available for this scan yet."
        lines = [f"- {a.name}: X+Y={a.mosca_assessment.x_plus_y:.1f}y vs Z={a.mosca_assessment.z_threat_horizon_years:.1f}y -> {a.mosca_assessment.result}"
                 for a in m_assets[:8]]
        return "Mosca analysis results:\n" + "\n".join(lines)

    if "pqc" in q or "replace" in q or "recommend" in q:
        recs = [a.recommendation for a in assets if a.recommendation]
        if not recs:
            return "No PQC recommendations are available for this scan yet."
        seen = {}
        for r in recs:
            seen[r.current_algorithm] = r.recommended_algorithm
        lines = [f"- {k} -> {v}" for k, v in seen.items()]
        return "PQC recommendations found in this scan:\n" + "\n".join(lines)

    # Generic fallback: summarize
    critical = len([a for a in assets if a.risk_assessment and a.risk_assessment.severity == "CRITICAL"])
    high = len([a for a in assets if a.risk_assessment and a.risk_assessment.severity == "HIGH"])
    return (
        f"This scan found {len(assets)} cryptographic assets: {critical} CRITICAL and {high} HIGH risk. "
        "Try asking about specific algorithms (e.g. 'which RSA assets should migrate first'), "
        "the Mosca analysis, or PQC recommendations for more detail."
    )


def answer_question(db: Session, question: str, scan_id: str | None) -> dict:
    ctx = _gather_context(db, scan_id)

    if not settings.AI_ENABLED or settings.AI_PROVIDER == "none":
        return {
            "answer": _deterministic_answer(question, ctx),
            "mode": "deterministic",
            "note": "AI assistant is running in deterministic mode (no LLM configured). "
                    "This always works offline and never invents findings.",
        }

    # Optional LLM-backed mode (Ollama / OpenAI-compatible). Structured context only.
    try:
        import httpx
        structured_summary = _deterministic_answer(question, ctx)
        prompt = (
            "You are ECDAT's assistant. Answer ONLY using the structured data below. "
            "Do not invent findings.\n\nStructured data:\n" + structured_summary +
            f"\n\nQuestion: {question}\nAnswer:"
        )
        if settings.AI_PROVIDER == "ollama":
            resp = httpx.post(f"{settings.AI_API_BASE}/api/generate",
                               json={"model": settings.AI_MODEL, "prompt": prompt, "stream": False}, timeout=30)
            resp.raise_for_status()
            return {"answer": resp.json().get("response", structured_summary), "mode": "ollama"}
        elif settings.AI_PROVIDER == "openai_compatible":
            headers = {"Authorization": f"Bearer {settings.AI_API_KEY}"} if settings.AI_API_KEY else {}
            resp = httpx.post(f"{settings.AI_API_BASE}/chat/completions",
                               json={"model": settings.AI_MODEL, "messages": [{"role": "user", "content": prompt}]},
                               headers=headers, timeout=30)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return {"answer": content, "mode": "openai_compatible"}
    except Exception as e:
        return {
            "answer": _deterministic_answer(question, ctx),
            "mode": "deterministic_fallback",
            "note": f"LLM backend unavailable ({e}); fell back to deterministic search/report functionality.",
        }

    return {"answer": _deterministic_answer(question, ctx), "mode": "deterministic"}
