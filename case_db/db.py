import sqlite3
from pathlib import Path

DB_PATH = Path("cases.db")


def get_connection():
    """
    Create a hardened SQLite connection.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # ---------------- SAFETY HARDENING ----------------
    # Crash safety + concurrent reads
    conn.execute("PRAGMA journal_mode=WAL;")

    # Balance durability vs performance (safe for local forensic tooling)
    conn.execute("PRAGMA synchronous=NORMAL;")

    # Enforce relational integrity (future-proofing)
    conn.execute("PRAGMA foreign_keys=ON;")
    # --------------------------------------------------

    return conn


def init_db():
    """
    Initialise case database schema (idempotent).
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT,
            status TEXT,
            tags TEXT,
            notes TEXT,
            event_count INTEGER,
            detection_count INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()

