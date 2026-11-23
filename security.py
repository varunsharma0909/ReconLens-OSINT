"""Phase-1 small-team authentication, authorization and audit helpers.

Only a local admin can provision accounts via the Flask CLI; self-registration
is deliberately disabled. Production requires a stable SECRET_KEY.
"""
from __future__ import annotations

import hmac
import re
import secrets
from datetime import datetime, timezone
from functools import wraps

import click
from flask import (abort, current_app, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import get_db

USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,39}$")
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def current_user():
    if not hasattr(g, "security_user"):
        uid = session.get("user_id")
        g.security_user = None
        if type(uid) is int:
            row = get_db().execute(
                "SELECT id, username, role, active FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if row is not None and row["active"]:
                g.security_user = dict(row)
    return g.security_user


def audit(action: str, resource: str = "", *, actor_id=None):
    if actor_id is None:
        user = current_user()
        actor_id = user["id"] if user else None
    get_db().execute(
        "INSERT INTO audit_events(actor_id, action, resource, created_at, remote_ip) "
        "VALUES(?,?,?,?,?)",
        (actor_id, action[:80], resource[:200],
         datetime.now(timezone.utc).isoformat(), request.remote_addr if request else None)
    )
    get_db().commit()


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_authentication_and_csrf():
    if current_app.config.get("AUTH_TEST_BYPASS") and current_app.testing:
        return None
    if request.endpoint == "static" or request.path == "/api/health":
        return None
    if request.endpoint in {"security.login", "security.login_post"}:
        if request.method == "POST" and not valid_csrf():
            return deny(403, "csrf_failed", "Invalid or missing CSRF token.")
        return None
    user = current_user()
    if not user:
        if request.path.startswith("/api/"):
            return deny(401, "authentication_required", "Sign in to use ReconLens.")
        return redirect(url_for("security.login", next=request.path))
    if request.method in UNSAFE and not valid_csrf():
        return deny(403, "csrf_failed", "Invalid or missing CSRF token.")
    return None


def valid_csrf():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def deny(status, code, message):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": {"code": code, "message": message}}), status
    abort(status)


def can_view_scan(scan):
    user = current_user()
    return bool(user and (user["role"] == "admin" or scan.get("owner_id") == user["id"]))


def require_scan_access(scan):
    if not can_view_scan(scan):
        from routes.common import ApiError
        raise ApiError(404, "not_found", "Scan does not exist.")
    return scan


def admin_required(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        if not current_user() or current_user()["role"] != "admin":
            return deny(403, "forbidden", "Administrator role required.")
        return fn(*args, **kwargs)
    return decorated


def init_security(app):
    from flask import Blueprint
    bp = Blueprint("security", __name__)

    @bp.get("/login")
    def login():
        if current_user():
            return redirect("/")
        return render_template("login.html", csrf_token=csrf_token(), error=None)

    @bp.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, role, active, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        if not user or not user["active"] or not check_password_hash(user["password_hash"], password):
            audit("login_failed", "username:" + username[:40])
            return render_template("login.html", csrf_token=csrf_token(),
                                   error="Invalid credentials."), 401
        session.clear()
        session["user_id"] = user["id"]
        csrf_token()
        audit("login", "session")
        return redirect("/")

    @bp.post("/logout")
    def logout():
        audit("logout", "session")
        session.clear()
        return redirect("/login")

    @bp.get("/api/me")
    def me():
        return jsonify({"ok": True, "user": current_user()})

    @bp.get("/api/admin/audit")
    @admin_required
    def audit_history():
        records = [dict(r) for r in get_db().execute(
            "SELECT e.id, u.username AS actor, e.action, e.resource, e.created_at, e.remote_ip "
            "FROM audit_events e LEFT JOIN users u ON u.id = e.actor_id "
            "ORDER BY e.id DESC LIMIT 200"
        )]
        return jsonify({"ok": True, "events": records})

    app.register_blueprint(bp)
    app.before_request(require_authentication_and_csrf)
    app.context_processor(lambda: {"csrf_token": csrf_token, "security_user": current_user})

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option("--role", type=click.Choice(["admin", "analyst"]), default="analyst")
    @click.password_option()
    def create_user(username, role, password):
        """Provision a team account from a trusted server shell."""
        if not USERNAME.fullmatch(username):
            raise click.ClickException("Username must be 3-40 alphanumeric/._- characters.")
        if len(password) < 12:
            raise click.ClickException("Password must have at least 12 characters.")
        try:
            get_db().execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                (username, generate_password_hash(password, method="scrypt"),
                 role, datetime.now(timezone.utc).isoformat())
            )
            get_db().commit()
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise click.ClickException("Username already exists.") from exc
            raise
        click.echo(f"Created {role} account {username}." )
