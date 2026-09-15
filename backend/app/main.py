from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.core.seed import seed_all

from app.api import auth, scans, assets, cbom, risks, mosca, recommendations, migration, certificates, reports, ai, dashboard, libraries, hndl

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(cbom.router)
app.include_router(risks.router)
app.include_router(mosca.router)
app.include_router(recommendations.router)
app.include_router(migration.router)
app.include_router(certificates.router)
app.include_router(libraries.router)
app.include_router(reports.router)
app.include_router(ai.router)
app.include_router(dashboard.router)
app.include_router(hndl.router)


@app.on_event("startup")
def on_startup():
    init_db()
    db = SessionLocal()
    try:
        seed_all(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}
