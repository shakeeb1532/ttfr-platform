from dataclasses import dataclass
from typing import Dict, Any


@dataclass(frozen=True)
class ForensicEvent:
    """
    Canonical forensic event.
    """
    seq: int
    timestamp: int
    event_type: str
    payload: Dict[str, Any]

    def stable_repr(self) -> str:
        return f"{self.seq}|{self.timestamp}|{self.event_type}|{self.payload}"

