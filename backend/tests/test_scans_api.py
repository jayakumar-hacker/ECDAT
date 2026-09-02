import os
import tempfile
import time


def _auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def test_create_scan_rejects_nonexistent_path(client, admin_token):
    resp = client.post("/api/scans", json={"target": "/no/such/path", "target_type": "directory"},
                        headers=_auth(admin_token))
    assert resp.status_code == 400


def test_create_and_run_scan_against_real_dir(client, admin_token):
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "app.py"), "w") as f:
            f.write("key = rsa.generate_private_key(key_size=2048)\nh = hashlib.md5(x)\n")
        resp = client.post("/api/scans", json={"target": tmp, "target_type": "directory",
                                                 "scanners": ["source"]}, headers=_auth(admin_token))
        assert resp.status_code == 200
        scan_id = resp.json()["id"]

        # background task runs inline in TestClient's threadpool; poll briefly
        for _ in range(20):
            r = client.get(f"/api/scans/{scan_id}", headers=_auth(admin_token))
            if r.json()["status"] in ("completed", "failed"):
                break
            time.sleep(0.2)

        final = client.get(f"/api/scans/{scan_id}", headers=_auth(admin_token)).json()
        assert final["status"] == "completed"
        assert final["files_scanned"] == 1
        assert final["artefacts_found"] >= 2


def test_list_scans_empty_initially(client, admin_token):
    resp = client.get("/api/scans", headers=_auth(admin_token))
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_nonexistent_scan_404(client, admin_token):
    resp = client.get("/api/scans/does-not-exist", headers=_auth(admin_token))
    assert resp.status_code == 404


def test_dashboard_empty_state(client, admin_token):
    resp = client.get("/api/dashboard", headers=_auth(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_crypto_assets"] == 0
    assert body["risk_distribution"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def test_cbom_export_json(client, admin_token):
    resp = client.get("/api/cbom/export?format=json", headers=_auth(admin_token))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")


def test_cbom_export_csv(client, admin_token):
    resp = client.get("/api/cbom/export?format=csv", headers=_auth(admin_token))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


def test_ai_chat_deterministic_fallback(client, admin_token):
    resp = client.post("/api/ai/chat", json={"question": "which systems are most vulnerable?"},
                        headers=_auth(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] in ("deterministic", "deterministic_fallback")
    assert "answer" in body
