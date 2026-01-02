from typing import List
from .event import ForensicEvent


class TTFR:
    """
    Time-Travel Forensic Record (append-only).
    """

    def __init__(self):
        self._events: List[ForensicEvent] = []
        self._seq = 0

    def record(self, timestamp: int, event_type: str, payload: dict) -> None:
        event = ForensicEvent(
            seq=self._seq,
            timestamp=timestamp,
            event_type=event_type,
            payload=payload,
        )
        self._events.append(event)
        self._seq += 1

    def snapshot(self) -> List[ForensicEvent]:
        """
        Immutable snapshot of recorded events.
        """
        return list(self._events)

