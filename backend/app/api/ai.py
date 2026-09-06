from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import models
from app.scanners.schemas.schemas import AIChatRequest
from app.ai.assistant import answer_question
from app.core.config import settings

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.post("/chat")
def chat(req: AIChatRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if not settings.AI_ENABLED:
        result = answer_question(db, req.question, req.scan_id)
        result["ai_assistant_status"] = "unavailable_using_deterministic_fallback"
        return result
    return answer_question(db, req.question, req.scan_id)
