def test_login_success(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "EcdatDemo123!"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["role"] == "admin"


def test_login_wrong_password(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    assert resp.status_code == 401


def test_protected_endpoint_requires_auth(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 401


def test_protected_endpoint_with_token(client, admin_token):
    resp = client.get("/api/scans", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200


def test_invalid_token_rejected(client):
    resp = client.get("/api/scans", headers={"Authorization": "Bearer not.a.valid.token"})
    assert resp.status_code == 401


def test_health_endpoint_no_auth_required(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
