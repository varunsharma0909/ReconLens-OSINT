"""One-time SQLite -> PostgreSQL migration with preserved IDs and password hashes.

Requires DATABASE_URL, a PostgreSQL database initialized by ReconLens, and --yes.
Always back up the SQLite file first. The source file is never modified.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TABLES = ("users", "scans", "findings", "audit_events")


def migrate(source: Path, *, commit: bool) -> dict:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is required; do not put it into source control.")
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source not found: {source}")

    import psycopg
    from psycopg import sql
    from app import create_app
    # Creates destination schema if needed, without switching the source database.
    create_app({"DATABASE_URL": url, "RETENTION_DAYS": 36500})

    counts = {}
    with sqlite3.connect(f"file:{source.resolve().as_posix()}?mode=ro", uri=True) as src:
        src.row_factory = sqlite3.Row
        with psycopg.connect(url) as dest:
            # Refuse merging data into an existing database: avoids duplicate IDs and ownership errors.
            for table in TABLES:
                n = dest.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]
                if n:
                    raise RuntimeError(
                        f"Destination table {table} has {n} rows; migration requires an empty destination."
                    )
            for table in TABLES:
                records = src.execute(f"SELECT * FROM {table}").fetchall()
                counts[table] = len(records)
                if not commit or not records:
                    continue
                columns = records[0].keys()
                statement = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(table),
                    sql.SQL(", ").join(map(sql.Identifier, columns)),
                    sql.SQL(", ").join(sql.Placeholder() for _ in columns),
                )
                with dest.cursor() as cur:
                    cur.executemany(statement, [tuple(rec[c] for c in columns) for rec in records])
                dest.execute(
                    sql.SQL("SELECT setval(pg_get_serial_sequence(%s, 'id'), "
                            "COALESCE((SELECT MAX(id) FROM {}), 1), TRUE)").format(sql.Identifier(table)),
                    (table,),
                )
            if not commit:
                dest.rollback()
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path, default=ROOT / "database" / "osint.db")
    parser.add_argument("--yes", action="store_true",
                        help="Actually insert rows into empty PostgreSQL; default only previews counts")
    args = parser.parse_args()
    counts = migrate(args.sqlite, commit=args.yes)
    print("Rows:", ", ".join(f"{table}={n}" for table, n in counts.items()))
    print("Migration completed." if args.yes else "DRY RUN. Nothing copied. Pass --yes after backup.")
