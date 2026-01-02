from datetime import datetime
from typing import List, Optional

from .db import get_connection, init_db
from .models import Case


# --------------------------------------------------
# Input Validation Boundary
# --------------------------------------------------

def _validate_text(value: str, max_len: int = 255) -> str:
    """
    Defensive validation for all user-controlled text.

    Protects against:
    - UI bugs
    - AI hallucinations
    - Accidental DB abuse
    """
    if value is None:
        return ""

    if not isinstance(value, str):
        raise ValueError("Invalid input type")

    value = value.strip()

    if len(value) > max_len:
        raise ValueError(f"Input exceeds {max_len} characters")

    return value


# --------------------------------------------------
# Case DAO
# --------------------------------------------------

class CaseDAO:
    def __init__(self):
        init_db()

    def create_case(
        self,
        snapshot_id: str,
        title: str,
        severity: str = "medium",
        status: str = "open",
        tags: str = "",
        notes: str = "",
        event_count: Optional[int] = None,
        detection_count: Optional[int] = None,
    ):
        now = datetime.utcnow().isoformat()

        snapshot_id = _validate_text(snapshot_id, 128)
        title = _validate_text(title, 255)
        severity = _validate_text(severity, 20)
        status = _validate_text(status, 20)
        tags = _validate_text(tags, 255)
        notes = _validate_text(notes, 2000)

        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT OR REPLACE INTO cases (
                id,
                title,
                severity,
                status,
                tags,
                notes,
                event_count,
                detection_count,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                title,
                severity,
                status,
                tags,
                notes,
                event_count,
                detection_count,
                now,
                now,
            ),
        )

        conn.commit()
        conn.close()

    def list_cases(self) -> List[Case]:
        conn = get_connection()
        cur = conn.cursor()

        rows = cur.execute(
            "SELECT * FROM cases ORDER BY created_at DESC"
        ).fetchall()

        conn.close()

        return [Case(**dict(row)) for row in rows]

    def update_case(
        self,
        snapshot_id: str,
        title: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[str] = None,
        notes: Optional[str] = None,
    ):
        fields = []
        values = []

        snapshot_id = _validate_text(snapshot_id, 128)

        if title is not None:
            fields.append("title = ?")
            values.append(_validate_text(title, 255))

        if severity is not None:
            fields.append("severity = ?")
            values.append(_validate_text(severity, 20))

        if status is not None:
            fields.append("status = ?")
            values.append(_validate_text(status, 20))

        if tags is not None:
            fields.append("tags = ?")
            values.append(_validate_text(tags, 255))

        if notes is not None:
            fields.append("notes = ?")
            values.append(_validate_text(notes, 2000))

        if not fields:
            return

        fields.append("updated_at = ?")
        values.append(datetime.utcnow().isoformat())
        values.append(snapshot_id)

        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            f"""
            UPDATE cases
            SET {", ".join(fields)}
            WHERE id = ?
            """,
            values,
        )

        conn.commit()
        conn.close()

