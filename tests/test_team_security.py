"""End-to-end Phase-1 access controls: no production bypass."""
from __future__ import annotations

from datetime import datetime, timezone

from app import create_app
from database.db import get_db
from werkzeug.security import generate_password_hash


def private_app(tmp_path):
    application = create_app({
        "TESTING": True,
        "AUTH_TEST_BYPASS": False,
        "SECRET_KEY": "test-secret-only-do-not-deploy",
        "SESSION_COOKIE_SECURE": False,
        "DATABASE_PATH": str(tmp_path / "private.db"),
        "SCAN_RATE_LIMIT": "1000 per minute",
        "DEFAULT_RATE_LIMIT": "1000 per hour",
        "VIRUSTOTAL_API_KEY": "",
    })
    with application.app_context():
        db = get_db()
        for name, role in (("admin", "admin"), ("alice", "analyst"), ("bob", "analyst")):
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (name, generate_password_hash("passphrase-12345"), role,
                 datetime.now(timezone.utc).isoformat())
            )
        db.commit()
    return application


def login(client, name):
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]
    return client.post("/login", data={
        "username": name,
        "password": "passphrase-12345",
        "csrf_token": token,
    })


def csrf(client):
    with client.session_transaction() as sess:
        return {"X-CSRF-Token": sess["csrf_token"]}


def test_unauthenticated_reads_and_writes_are_blocked(tmp_path):
    app = private_app(tmp_path)
    client = app.test_client()
    assert client.get("/").status_code == 302
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/graph").status_code == 401
    assert client.get("/api/scans.csv").status_code == 401
    assert client.post("/api/scan/domain", json={
        "target": "demo-corp.test", "mode": "demo"}).status_code == 401
    assert client.get("/api/health").status_code == 200


def test_login_csrf_and_audit(tmp_path):
    app = private_app(tmp_path)
    client = app.test_client()
    assert client.post("/login", data={"username": "alice", "password": "passphrase-12345"}).status_code == 403
    assert login(client, "alice").status_code == 302
    assert client.get("/api/me").get_json()["user"]["role"] == "analyst"
    assert client.post("/api/scan/domain", json={"target": "demo-corp.test"}).status_code == 403
    response = client.post("/api/scan/domain", json={
        "target": "demo-corp.test", "mode": "demo"}, headers=csrf(client))
    assert response.status_code == 201
    scan = response.get_json()["scan"]
    assert scan["owner_id"] == 2
    assert client.get("/api/admin/audit").status_code == 403
    assert client.post("/logout").status_code == 403
    assert client.post("/logout", headers=csrf(client)).status_code == 302
    assert client.get("/api/me").status_code == 401


def test_users_cannot_read_export_or_delete_others_scans(tmp_path):
    app = private_app(tmp_path)
    alice = app.test_client()
    bob = app.test_client()
    admin = app.test_client()
    login(alice, "alice")
    response = alice.post("/api/scan/domain", json={
        "target": "demo-corp.test", "mode": "demo"}, headers=csrf(alice))
    assert response.status_code == 201
    sid = response.get_json()["scan"]["id"]
    login(bob, "bob")
    assert bob.get("/api/scans").get_json()["scans"] == []
    assert bob.get(f"/api/scans/{sid}").status_code == 404
    assert bob.get(f"/api/scans/{sid}/graph").status_code == 404
    assert bob.get(f"/api/scans/{sid}/report.pdf").status_code == 404
    assert bob.get(f"/api/scans/{sid}/report.csv").status_code == 404
    assert bob.get(f"/scan/{sid}").status_code == 404
    assert bob.get("/api/scans.csv").data.decode("utf-8-sig").count("demo-corp.test") == 0
    assert bob.delete(f"/api/scans/{sid}", headers=csrf(bob)).status_code == 404
    assert bob.get(f"/api/graph?ids={sid}").get_json()["graph"]["scans"] == []
    assert alice.get(f"/api/scans/{sid}").status_code == 200
    login(admin, "admin")
    assert admin.get(f"/api/scans/{sid}").status_code == 200
    events = admin.get("/api/admin/audit").get_json()["events"]
    assert any(e["action"] == "scan_created" and e["actor"] == "alice" for e in events)
    assert any(e["action"] == "login" and e["actor"] == "alice" for e in events)


def test_wrong_password_does_not_create_session(tmp_path):
    app = private_app(tmp_path)
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]
    response = client.post("/login", data={
        "username": "alice", "password": "bad", "csrf_token": token})
    assert response.status_code == 401
    assert client.get("/api/scans").status_code == 401
