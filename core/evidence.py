import hashlib
from typing import List
from .event import ForensicEvent


def compute_evidence_hash(events: List[ForensicEvent]) -> str:
    """
    Deterministic evidence hash over a replay.
    """
    h = hashlib.sha256()
    for e in events:
        h.update(e.stable_repr().encode("utf-8"))
    return h.hexdigest()

