import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.gettempdir(), "ecdat_test.db")


@pytest.fixture(scope="function")
def db_session():
    from app.core.database import Base, engine, SessionLocal
    from app.models import models  # noqa: F401
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(db_session):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.database import get_db

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(client):
    # app startup seeds a default admin user - reuse those credentials.
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "EcdatDemo123!"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]
