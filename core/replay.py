from typing import List
from .event import ForensicEvent


class ReplaySession:
    """
    Deterministic replay session.
    """

    def __init__(self, events: List[ForensicEvent]):
        self._events = sorted(events, key=lambda e: e.seq)

    def replay(self) -> List[ForensicEvent]:
        return self._events

