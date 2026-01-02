from dataclasses import dataclass
from typing import Optional


@dataclass
class Case:
    id: str                     # snapshot_id
    title: Optional[str]
    severity: Optional[str]
    status: Optional[str]
    tags: Optional[str]
    notes: Optional[str]
    event_count: Optional[int]
    detection_count: Optional[int]
    created_at: str
    updated_at: str

