# case_db/blackbox.py
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _json_default(obj: Any):
    # Make JSON robust (fixes "set is not JSON serializable")
    if isinstance(obj, set):
        return sorted(list(obj))
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def dumps_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=_json_default)


def loads_json(s: str) -> Any:
    return json.loads(s) if s else None


@dataclass(frozen=True)
class WorkOrder:
    id: int
    case_id: str
    snapshot_id: str
    title: str
    description: str
    category: str
    priority: str
    status: str
    owner: str
    due_at: Optional[int]
    evidence_refs_json: str
    created_at: int
    updated_at: int

    @property
    def evidence_refs(self) -> Any:
        return loads_json(self.evidence_refs_json) or []


@dataclass(frozen=True)
class BlackboxEntry:
    id: int
    case_id: str
    snapshot_id: str
    entry_type: str
    title: str
    body: str
    tags_json: str
    evidence_refs_json: str
    created_by: str
    created_at: int

    @property
    def tags(self) -> List[str]:
        return loads_json(self.tags_json) or []

    @property
    def evidence_refs(self) -> Any:
        return loads_json(self.evidence_refs_json) or []


@dataclass(frozen=True)
class AttributionAssessment:
    id: int
    case_id: str
    snapshot_id: str
    origin: str               # internal|external|mixed|unknown
    confidence: str           # low|medium|high
    rationale: str            # text
    evidence_refs_json: str   # json list
    analyst_override: int     # 0/1
    updated_by: str
    updated_at: int

    @property
    def evidence_refs(self) -> Any:
        return loads_json(self.evidence_refs_json) or []


class BlackboxDAO:
    """
    Safe DB access layer (parameterized queries only).
    Uses cases.db in project root by default.
    """

    def __init__(self, db_path: str = "cases.db"):
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_schema()

    def _ensure_db_dir(self):
        # If someone passes a nested db path, ensure directory exists.
        d = os.path.dirname(os.path.abspath(self.db_path))
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS work_orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    due_at INTEGER,
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_work_orders_case_snapshot
                ON work_orders(case_id, snapshot_id);

                CREATE TABLE IF NOT EXISTS blackbox_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    entry_type TEXT NOT NULL,      -- note|finding|recommendation|ioc|summary
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_blackbox_case_snapshot
                ON blackbox_entries(case_id, snapshot_id);

                CREATE TABLE IF NOT EXISTS attribution_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    origin TEXT NOT NULL,           -- internal|external|mixed|unknown
                    confidence TEXT NOT NULL,       -- low|medium|high
                    rationale TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    analyst_override INTEGER NOT NULL DEFAULT 0,
                    updated_by TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(case_id, snapshot_id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_case_snapshot
                ON audit_log(case_id, snapshot_id);
                """
            )

    # -----------------------
    # Audit
    # -----------------------
    def _audit(self, conn: sqlite3.Connection, case_id: str, snapshot_id: str, actor: str, action: str, details: Dict[str, Any]):
        conn.execute(
            """
            INSERT INTO audit_log(case_id, snapshot_id, actor, action, details_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (case_id, snapshot_id, actor, action, dumps_json(details), int(time.time())),
        )

    def list_audit(self, case_id: str, snapshot_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_log
                WHERE case_id = ? AND snapshot_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (case_id, snapshot_id, int(limit)),
            ).fetchall()
            out = []
            for r in rows:
                out.append(
                    {
                        "id": r["id"],
                        "actor": r["actor"],
                        "action": r["action"],
                        "details": loads_json(r["details_json"]),
                        "created_at": r["created_at"],
                    }
                )
            return out

    # -----------------------
    # Work Orders
    # -----------------------
    def create_work_order(
        self,
        *,
        case_id: str,
        snapshot_id: str,
        title: str,
        description: str,
        category: str = "Triage",
        priority: str = "P2",
        status: str = "OPEN",
        owner: str = "Analyst",
        due_at: Optional[int] = None,
        evidence_refs: Optional[Any] = None,
        actor: str = "analyst",
    ) -> int:
        now = int(time.time())
        evidence_refs = evidence_refs or []
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO work_orders(
                    case_id, snapshot_id, title, description, category,
                    priority, status, owner, due_at, evidence_refs_json,
                    created_at, updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, snapshot_id, title, description, category,
                    priority, status, owner, due_at, dumps_json(evidence_refs),
                    now, now
                ),
            )
            wo_id = int(cur.lastrowid)
            self._audit(conn, case_id, snapshot_id, actor, "work_order_created", {"work_order_id": wo_id, "title": title})
            return wo_id

    def list_work_orders(self, case_id: str, snapshot_id: str) -> List[WorkOrder]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM work_orders
                WHERE case_id = ? AND snapshot_id = ?
                ORDER BY updated_at DESC, id DESC
                """,
                (case_id, snapshot_id),
            ).fetchall()
            return [WorkOrder(**dict(r)) for r in rows]

    def update_work_order_status(self, work_order_id: int, status: str, actor: str = "analyst"):
        status = status.upper().strip()
        with self._connect() as conn:
            row = conn.execute("SELECT case_id, snapshot_id, status FROM work_orders WHERE id = ?", (int(work_order_id),)).fetchone()
            if not row:
                return
            conn.execute(
                "UPDATE work_orders SET status = ?, updated_at = ? WHERE id = ?",
                (status, int(time.time()), int(work_order_id)),
            )
            self._audit(conn, row["case_id"], row["snapshot_id"], actor, "work_order_status_updated", {"work_order_id": work_order_id, "from": row["status"], "to": status})

    # -----------------------
    # Blackbox Journal (append-only)
    # -----------------------
    def append_entry(
        self,
        *,
        case_id: str,
        snapshot_id: str,
        entry_type: str,
        title: str,
        body: str,
        tags: Optional[List[str]] = None,
        evidence_refs: Optional[Any] = None,
        created_by: str = "analyst",
    ) -> int:
        tags = tags or []
        evidence_refs = evidence_refs or []
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO blackbox_entries(
                    case_id, snapshot_id, entry_type, title, body,
                    tags_json, evidence_refs_json, created_by, created_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id, snapshot_id, entry_type, title, body,
                    dumps_json(tags), dumps_json(evidence_refs),
                    created_by, now
                ),
            )
            entry_id = int(cur.lastrowid)
            self._audit(conn, case_id, snapshot_id, created_by, "blackbox_entry_appended", {"entry_id": entry_id, "type": entry_type, "title": title})
            return entry_id

    def list_entries(self, case_id: str, snapshot_id: str, limit: int = 200) -> List[BlackboxEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM blackbox_entries
                WHERE case_id = ? AND snapshot_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (case_id, snapshot_id, int(limit)),
            ).fetchall()
            return [BlackboxEntry(**dict(r)) for r in rows]

    # -----------------------
    # Attribution
    # -----------------------
    def upsert_attribution(
        self,
        *,
        case_id: str,
        snapshot_id: str,
        origin: str,
        confidence: str,
        rationale: str,
        evidence_refs: Optional[Any] = None,
        analyst_override: bool = False,
        updated_by: str = "analyst",
    ):
        evidence_refs = evidence_refs or []
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO attribution_assessments(
                    case_id, snapshot_id, origin, confidence, rationale,
                    evidence_refs_json, analyst_override, updated_by, updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, snapshot_id) DO UPDATE SET
                    origin = excluded.origin,
                    confidence = excluded.confidence,
                    rationale = excluded.rationale,
                    evidence_refs_json = excluded.evidence_refs_json,
                    analyst_override = excluded.analyst_override,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (
                    case_id, snapshot_id, origin, confidence, rationale,
                    dumps_json(evidence_refs), 1 if analyst_override else 0,
                    updated_by, now
                ),
            )
            self._audit(conn, case_id, snapshot_id, updated_by, "attribution_upserted", {"origin": origin, "confidence": confidence, "override": bool(analyst_override)})

    def get_attribution(self, case_id: str, snapshot_id: str) -> Optional[AttributionAssessment]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM attribution_assessments WHERE case_id = ? AND snapshot_id = ?",
                (case_id, snapshot_id),
            ).fetchone()
            return AttributionAssessment(**dict(row)) if row else None

