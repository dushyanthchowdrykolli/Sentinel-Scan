"""
app/database.py

SQLite database initialisation and low-level helpers.
All database interaction goes through the functions here so that the
connection lifecycle is managed in one place.
"""

import sqlite3
import threading
from pathlib import Path

# The database file lives at the project root so it is easy to inspect during a demo.
DB_PATH = Path(__file__).resolve().parent.parent / "sentinel_scan.db"

# Thread-local storage so each thread gets its own connection.
_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Return the per-thread SQLite connection, creating it if needed."""
    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Allow concurrent reads
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


def init_db() -> None:
    """Create all tables if they do not already exist."""
    conn = get_conn()
    conn.executescript(
        """
        -- One row per scan job
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url  TEXT    NOT NULL,
            started_at  TEXT    NOT NULL,   -- ISO-8601 UTC
            finished_at TEXT,               -- NULL while running
            status      TEXT    NOT NULL DEFAULT 'running',  -- running/done/error
            authorized  INTEGER NOT NULL DEFAULT 0,          -- 1 if user confirmed auth
            scan_meta   TEXT                                 -- JSON blob
        );

        -- One row per finding produced by a scanner module
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL REFERENCES scans(id),
            finding_id      TEXT    NOT NULL,   -- deterministic slug
            title           TEXT    NOT NULL,
            category        TEXT    NOT NULL,   -- OWASP Top 10 label
            severity        TEXT    NOT NULL,   -- Critical/High/Medium/Low/Info
            affected_url    TEXT    NOT NULL,
            description     TEXT    NOT NULL,
            evidence_raw    TEXT    NOT NULL,   -- full request + response excerpt (plain text)
            evidence_hash   TEXT    NOT NULL,   -- SHA-256 of evidence_raw
            remediation     TEXT    NOT NULL
        );

        -- Hash-chained tamper-evident ledger
        CREATE TABLE IF NOT EXISTS ledger (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,   -- ISO-8601 UTC
            scan_id         INTEGER,            -- may be NULL for system events
            action          TEXT    NOT NULL,   -- e.g. "scan_started", "finding_recorded"
            evidence_hash   TEXT    NOT NULL,   -- SHA-256 of associated payload
            prev_hash       TEXT    NOT NULL,   -- SHA-256 of previous ledger entry (genesis = "0"*64)
            entry_hash      TEXT    NOT NULL    -- SHA-256(timestamp|scan_id|action|evidence_hash|prev_hash)
        );
        """
    )
    conn.commit()
