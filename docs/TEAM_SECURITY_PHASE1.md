# ReconLens team-security branch — Phase 1

**Status:** development-only branch. Do **not** deploy it as a production service or merge into the college demo without independent review. It retains SQLite, process-local rate limiting, synchronous scans, and third-party API constraints.

## Implemented

- Private team accounts: no public registration. Create users from a trusted CLI shell.
- Roles: `admin` (all scans and audit events) and `analyst` (own scans only).
- Server-side authentication on pages and API, except the public `/api/health` probe and static assets.
- CSRF token bound to session for login, logout and all POST/PUT/PATCH/DELETE requests; the app's JS API wrapper sends `X-CSRF-Token`. Cross-user scan/report paths return 404.
- Scan owner stored in the SQLite database, with a migration for existing databases. Historical unowned scans are visible **only to admins**.
- Audit events for login attempts, login/logout, scan creation/deletion and report downloads. Audit records include actor id, timestamp, action, resource, and source IP.
- A stable `SECRET_KEY` is required: no auto-generated secret per process.
- Rate limiting on password attempts (5 per minute per client IP; still memory-backed in this phase).

## Local setup

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Generate a stable secret and set it in your **local `.env`** (never commit this file):

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

For localhost **only**, also set `SESSION_COOKIE_SECURE=false`; over HTTPS in real deployments this must remain `true`. This branch uses secure cookies by default.

Provision accounts from a trusted terminal (the CLI prompts for passwords):

```bash
flask --app 'app:create_app' create-user admin1 --role admin
flask --app 'app:create_app' create-user analyst1 --role analyst
```

Start with `python app.py` and open `http://127.0.0.1:5000/login`.

Run tests using `python -m pytest -q`; tests use an **explicit test-only bypass** of login where intended, and dedicated `test_team_security.py` integration tests run with that bypass disabled.

## Deployment cautions

- **Do not change the existing Render service to this branch yet.** It requires persistent `SECRET_KEY`, account provisioning, a writable persistent database, HTTPS, and hardened stateful services.
- SQLite ownership is a transitional measure; multi-user production requires Postgres, migrations, backups and retention.
- Memory-backed rate limiting is not shared between Gunicorn workers. Plan Redis before multi-worker use.
- The authorization checkbox cannot verify ownership of arbitrary third-party targets. Live scans should stay disabled until acceptable-use restrictions and analyst approval are implemented.
- No password resets, MFA, invitations, or an administrative user-management UI yet. No penetration test or security audit has been completed.
- Audit records are basic and not tamper-proof; retention, monitoring, export and administrative oversight need review.
- The GET health endpoint is public for hosting probes. Restrict it if the deployment needs a private health surface.

## Next steps

Use a real Postgres database with a proper schema migration; shared Redis rate-limiter; RQ workers for long lookups; policy-aware target allow-lists; privacy review and an independent security test before any external exposure.
