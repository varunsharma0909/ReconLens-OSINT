# Phase 2 — PostgreSQL, Redis and HTTPS-ready Render deployment

## What is implemented

* **Local testing remains simple:** no `DATABASE_URL` means SQLite, no `REDIS_URL` means in-memory rate limiting. `START_RECONLENS_WINDOWS.bat` still works without PostgreSQL or Redis.
* **Hosted data persistence:** setting `DATABASE_URL` (PostgreSQL DSN) stores users, scans, findings, audit events and account passwords in PostgreSQL. The SQL schema is created on startup and rows stay after normal app restarts.
* **Shared rate limiting:** setting `REDIS_URL` enables a Redis-backed Flask-Limiter store shared across workers. Redis is not yet used as a background job queue; that is Phase 3.
* **HTTPS-aware sessions:** `SESSION_COOKIE_SECURE=true` in Render, `TRUST_PROXY_HEADERS=true` only behind its trusted reverse proxy; HSTS is emitted on HTTPS responses.
* **Render Blueprint:** `render.yaml` provisions one Docker web service, a PostgreSQL database and Render Key Value (Redis-compatible) instance with internal networking.
* **Data migration:** a separate guarded script imports an **existing local SQLite** database into an **empty** PostgreSQL database without changing the SQLite source. It preserves user password hashes, account IDs and scan ownership.

## Local Windows testing (no external services)

Download the Phase 2 ZIP, extract, then run `START_RECONLENS_WINDOWS.bat`. It automatically creates a local .env and a random Flask secret if needed. On first launch it prompts you to create your administrator. Visit http://127.0.0.1:5000/login. The application uses SQLite unless you deliberately set DATABASE_URL.

To use PostgreSQL/Redis on your computer instead, start services separately (for example in Docker), then set variables in your local untracked `.env`:

```dotenv
DATABASE_URL=postgresql://reconlens:local-password@localhost:5432/reconlens
REDIS_URL=redis://localhost:6379/0
SESSION_COOKIE_SECURE=false
TRUST_PROXY_HEADERS=false
```

Do not copy real database passwords or secrets into GitHub. Local HTTP must use SESSION_COOKIE_SECURE=false; on Render keep it true.

## Render deployment

1. On GitHub use branch `feature/team-auth-audit`. On Render choose **New → Blueprint**; select your repository and this branch, then review `render.yaml` before applying.
2. **Review costs before proceeding:** the Blueprint declares paid `starter` web/Key Value and `basic-256mb` PostgreSQL resources. Resources are not free by default; choose a suitable lower-cost plan manually if offered.
3. Render connects PostgreSQL using `DATABASE_URL` and Key Value using `REDIS_URL`, and generates a persistent `SECRET_KEY`. HTTPS is provided by Render. `ALLOW_LIVE_MODE=false` protects the initial deployment from running real queries.
4. After the first deploy, the hosted app **does not have a default admin password**. Create one in the Render service's trusted Shell (if available): `python -m flask --app app:create_app create-user admin1 --role admin`. Otherwise provision an account using a **one-off trusted service command** with the same configuration and database (never by enabling public signup). Do not expose this command via HTTP.
5. Open the assigned HTTPS hostname and sign in. Verify `/api/health`, a demo scan, its PDF/CSV download, navigation logout, and that records remain after redeployment.
6. Add only the API keys you actually need in Render environment settings. Do not turn on `ALLOW_LIVE_MODE` until authorization/privacy requirements and provider limits are reviewed.

**Do not use a Render Static Site for Flask.** Use a web service (Blueprint creates it). The Blueprint's PostgreSQL and Key Value IP allow lists are empty to prevent public external connections; use internal service connections.

**Never reuse a local `.env` for production.** The local `.env` included in test ZIPs is deliberately for HTTP testing and is regenerated to have a unique secret.

## Optional one-time migration of existing accounts and scan history

1. Stop your old SQLite-based app. Make a backup copy of its `database/osint.db` file (the original has your users and scans). Ensure any SQLite WAL sidecars are fully checkpointed; stop the app first.
2. Create and initialize an **empty** PostgreSQL database (the ReconLens app automatically creates its schema on initial startup).
3. With `DATABASE_URL` set for that database in the shell used to run the script, preview:
   `python scripts/migrate_sqlite_to_postgres.py --sqlite "D:\\path\\to\\old\\database\\osint.db"`
4. When preview counts are correct, run the same command with `--yes`. It refuses to merge if the destination already contains rows. **Do not run it on your live database unless you have verified backups and selected the correct destination.**
5. If you need to migrate an *existing Render SQLite deployment*, take an authorized database export while the app is stopped. Redeploying with an empty PostgreSQL database does **not** automatically copy its previous SQLite data.

## Verification

`python -m pytest -q` covers the offline SQLite demo. GitHub Actions also starts real disposable PostgreSQL and Redis containers and runs `tests/test_phase2_integration.py` to verify database persistence, account login, a demo scan, and Redis connectivity.

## Boundaries

* Phase 2 does **not** add background scan workers, a task queue, retry handling or job statuses — that is Phase 3.
* PostgreSQL schema initialization is currently lightweight and idempotent; use versioned schema migrations before further production database changes.
* This is not a claim of full production security. Before using it for real users, plan monitoring, database backups, MFA, comprehensive authorization and penetration testing.
