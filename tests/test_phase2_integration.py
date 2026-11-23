"""Phase 2 live integration tests, run only with disposable PostgreSQL and Redis."""
import os
from datetime import datetime, timezone

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from database.db import get_db


@pytest.mark.skipif(not os.getenv("PG_TEST_URL"), reason="PG_TEST_URL not configured")
def test_postgres_persistence_security_and_redis():
    import redis
    url = os.environ["PG_TEST_URL"]
    cache = os.environ["REDIS_TEST_URL"]
    assert redis.from_url(cache, socket_connect_timeout=3).ping()
    settings = {
        "TESTING": True,
        "AUTH_TEST_BYPASS": False,
        "SECRET_KEY": "ci-test-secret-not-for-production",
        "SESSION_COOKIE_SECURE": False,
        "DATABASE_URL": url,
        "REDIS_URL": cache,
        "RATELIMIT_STORAGE_URI": cache,
        "SCAN_RATE_LIMIT": "1000 per minute",
        "DEFAULT_RATE_LIMIT": "1000 per hour",
    }
    app = create_app(settings)
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            ("phase2admin", generate_password_hash("long-test-password-123"), "admin",
             datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
    client = app.test_client()
    assert client.get("/api/scans").status_code == 401
    assert client.get("/login").status_code == 200
    # Actual rate-limit requests must write counters into Redis.
    assert redis.from_url(cache).dbsize() > 0
    with client.session_transaction() as state:
        token = state["csrf_token"]
    assert client.post("/login", data={
        "username": "phase2admin",
        "password": "long-test-password-123",
        "csrf_token": token,
    }).status_code == 302
    with client.session_transaction() as state:
        token = state["csrf_token"]
    response = client.post("/api/scan/domain",
        json={"target": "demo-corp.test", "mode": "demo"},
        headers={"X-CSRF-Token": token})
    assert response.status_code == 201, response.get_data(as_text=True)[:500]
    scan_id = response.get_json()["scan"]["id"]
    assert scan_id > 0
    row = client.get(f"/api/scans/{scan_id}")
    assert row.status_code == 200
    assert row.get_json()["scan"]["target"] == "demo-corp.test"
    assert row.get_json()["scan"]["findings"]
    stats = client.get("/api/stats").get_json()["stats"]
    assert stats["total_scans"] == 1

    app2 = create_app(settings)
    with app2.app_context():
        from database.db import get_scan
        stored = get_scan(scan_id)
        assert stored["target"] == "demo-corp.test"
        assert stored["owner_id"] is not None
    assert client.post("/logout", headers={"X-CSRF-Token": token}).status_code == 302
    assert client.get("/api/scans").status_code == 401
