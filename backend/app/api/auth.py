from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.core.logging import audit
from app.models import models
from app.scanners.schemas.schemas import LoginRequest, TokenResponse



router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(user.username, user.role)
    audit("login", user.username)
    return TokenResponse(access_token=token, role=user.role)


@router.post("/logout")
def logout():
    # Stateless JWT - logout is handled client-side by discarding the token.
    return {"detail": "Logged out. Discard the client-side token."}
