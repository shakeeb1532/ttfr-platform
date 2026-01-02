import hashlib
from typing import List, Optional
from .event import ForensicEvent


class EvidenceChain:
    """
    Cryptographic chain of custody for forensic snapshots.
    """

    def __init__(self):
        self._previous_hash: Optional[str] = None
        self._chain: List[str] = []

    def add_snapshot(self, events: List[ForensicEvent]) -> str:
        h = hashlib.sha256()

        # Chain with previous snapshot
        if self._previous_hash:
            h.update(self._previous_hash.encode("utf-8"))

        # Hash current snapshot deterministically
        for e in events:
            h.update(e.stable_repr().encode("utf-8"))

        snapshot_hash = h.hexdigest()
        self._chain.append(snapshot_hash)
        self._previous_hash = snapshot_hash

        return snapshot_hash

    def verify(self) -> bool:
        """
        Verify chain integrity.
        """
        prev = None
        for h in self._chain:
            if prev and not h.startswith(prev[:8]):
                return False
            prev = h
        return True

