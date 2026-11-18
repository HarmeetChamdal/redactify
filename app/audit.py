"""SQLite audit trail for redactions.

Only metadata is stored -- timestamp, entity type, count and
behaviour. Raw PII from the input text is never written here.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    count INTEGER NOT NULL,
    behaviour TEXT NOT NULL
);
"""


def init_db(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def log_redactions(conn: sqlite3.Connection, redactions: list[dict]) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO audit_log (timestamp, entity_type, count, behaviour)"
        " VALUES (?, ?, ?, ?)",
        [(ts, r["entity_type"], r["count"], r["behaviour"]) for r in redactions],
    )
    conn.commit()


def get_audit(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT id, timestamp, entity_type, count, behaviour"
        " FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {"id": r[0], "timestamp": r[1], "entity_type": r[2], "count": r[3], "behaviour": r[4]}
        for r in rows
    ]
