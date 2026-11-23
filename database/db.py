"""
database/db.py - SQLite helpers.

Uses Python's built-in sqlite3 module, so no database server is needed.
Every query uses "?" placeholders (parameterised queries) to prevent SQL
injection.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

POSTGRES_SCHEMA_PATH = Path(__file__).resolve().parent / "schema_postgres.sql"

class PgRow(dict):
    """Compatibility with both row['field'] and row[0] access."""
    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)

class PgCursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.rowcount = cursor.rowcount
    def fetchone(self):
        row = self.cursor.fetchone()
        return PgRow(row) if row is not None else None
    def fetchall(self):
        return [PgRow(row) for row in self.cursor.fetchall()]
    def __iter__(self):
        return (PgRow(row) for row in self.cursor)

class PgConnection:
    """Parameterised PostgreSQL adapter for existing query functions."""
    def __init__(self, url):
        import psycopg
        from psycopg.rows import dict_row
        self.conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=10)
    def execute(self, sql, params=()):
        return PgCursor(self.conn.execute(sql.replace("?", "%s"), params))
    def executemany(self, sql, values):
        with self.conn.cursor() as cur:
            cur.executemany(sql.replace("?", "%s"), values)
    def commit(self):
        self.conn.commit()
    def rollback(self):
        self.conn.rollback()
    def close(self):
        self.conn.close()



def _connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """One connection per request, stored on Flask's `g` object."""
    if "db" not in g:
        url = current_app.config.get("DATABASE_URL")
        g.db = PgConnection(url) if url else _connect(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables (if missing) and apply the data-retention policy."""

    url = app.config.get("DATABASE_URL")
    if url:
        conn = PgConnection(url)
        try:
            for statement in POSTGRES_SCHEMA_PATH.read_text(encoding="utf-8").split(";"):
                if statement.strip():
                    conn.execute(statement)
            removed = purge_old_scans(conn, app.config["RETENTION_DAYS"])
            conn.commit()
            if removed:
                app.logger.info("Retention policy removed %d old scan(s)", removed)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        with _connect(app.config["DATABASE_PATH"]) as conn:
            conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
            if "owner_id" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN owner_id INTEGER REFERENCES users(id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id, id)")
            removed = purge_old_scans(conn, app.config["RETENTION_DAYS"])
            if removed:
                app.logger.info("Retention policy removed %d old scan(s)", removed)
    app.teardown_appcontext(close_db)


def purge_old_scans(conn: sqlite3.Connection, days: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    cur = conn.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,))
    return cur.rowcount


# ------------------------------------------------------------------ writes
def save_scan(scan: dict, owner_id: int | None = None) -> int:
    db = get_db()
    cur = db.execute(
        """INSERT INTO scans (scan_type, target, mode, status, exposure_score,
               exposure_level, "authorization", started_at, completed_at, duration_ms,
               modules_json, recommendations_json, limitations_json, scoring_json, owner_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""" +
        (" RETURNING id" if current_app.config.get("DATABASE_URL") else ""),
        (
            scan["scan_type"], scan["target"], scan["mode"], scan["status"],
            scan["exposure_score"], scan["exposure_level"], scan.get("authorization"),
            scan["started_at"], scan["completed_at"], scan["duration_ms"],
            json.dumps(scan["modules"]), json.dumps(scan["recommendations"]),
            json.dumps(scan["limitations"]), json.dumps(scan["scoring"]), owner_id,
        ),
    )
    scan_id = cur.fetchone()["id"] if current_app.config.get("DATABASE_URL") else cur.lastrowid
    db.executemany(
        """INSERT INTO findings (scan_id, module, source, code, title, value, status,
               severity, source_url, collected_at, details_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                scan_id, f["module"], f["source"], f["code"], f["title"], f.get("value"),
                f["status"], f["severity"], f.get("source_url"), f["collected_at"],
                json.dumps(f.get("details") or {}),
            )
            for f in scan["findings"]
        ],
    )
    # Apply the retention policy on every save too, not only at start-up,
    # so a server that runs for weeks still forgets old scans.
    purge_old_scans(db, current_app.config["RETENTION_DAYS"])
    db.commit()
    return scan_id


def delete_scan(scan_id: int) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    return cur.rowcount > 0


# ------------------------------------------------------------------- reads
def _scan_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "scan_type": row["scan_type"],
        "target": row["target"],
        "mode": row["mode"],
        "status": row["status"],
        "exposure_score": row["exposure_score"],
        "exposure_level": row["exposure_level"],
        "authorization": row["authorization"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "duration_ms": row["duration_ms"],
    }


def get_scan(scan_id: int) -> dict | None:
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    scan = _scan_row_to_dict(row)
    scan["modules"] = json.loads(row["modules_json"] or "[]")
    scan["recommendations"] = json.loads(row["recommendations_json"] or "[]")
    scan["limitations"] = json.loads(row["limitations_json"] or "[]")
    scan["scoring"] = json.loads(row["scoring_json"] or "{}")
    findings = db.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
    ).fetchall()
    scan["findings"] = [
        {
            "id": f["id"], "module": f["module"], "source": f["source"], "code": f["code"],
            "title": f["title"], "value": f["value"], "status": f["status"],
            "severity": f["severity"], "source_url": f["source_url"],
            "collected_at": f["collected_at"],
            "details": json.loads(f["details_json"] or "{}"),
        }
        for f in findings
    ]
    return scan


def list_scans(limit: int = 50, scan_type: str | None = None,
               owner_id: int | None = None) -> list[dict]:
    db = get_db()
    sql = """SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count
             FROM scans s"""
    params: list = []
    filters = []
    if scan_type:
        filters.append("s.scan_type = ?")
        params.append(scan_type)
    if owner_id is not None:
        filters.append("s.owner_id = ?")
        params.append(owner_id)
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY s.id DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(sql, params).fetchall()
    result = []
    for row in rows:
        item = _scan_row_to_dict(row)
        item["finding_count"] = row["finding_count"]
        result.append(item)
    return result


def get_stats(owner_id: int | None = None) -> dict:
    db = get_db()
    predicate = " WHERE owner_id = ?" if owner_id is not None else ""
    params = (owner_id,) if owner_id is not None else ()
    total = db.execute("SELECT COUNT(*) FROM scans" + predicate, params).fetchone()[0]
    avg = db.execute("SELECT AVG(exposure_score) FROM scans" + predicate, params).fetchone()[0]
    by_type = {
        r["scan_type"]: r["n"]
        for r in db.execute("SELECT scan_type, COUNT(*) AS n FROM scans" + predicate + " GROUP BY scan_type", params)
    }
    by_level = {
        r["exposure_level"]: r["n"]
        for r in db.execute(
            "SELECT exposure_level, COUNT(*) AS n FROM scans" + predicate + " GROUP BY exposure_level", params
        )
    }
    by_status = {
        r["status"]: r["n"]
        for r in db.execute(
            "SELECT f.status, COUNT(*) AS n FROM findings f JOIN scans s ON s.id = f.scan_id" +
            (" WHERE s.owner_id = ?" if owner_id is not None else "") +
            " GROUP BY f.status", params
        )
    }
    return {
        "total_scans": total,
        "average_score": round(avg, 1) if avg is not None else None,
        "scans_by_type": by_type,
        "scans_by_level": by_level,
        "findings_by_status": by_status,
    }
