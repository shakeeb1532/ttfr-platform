from abc import ABC, abstractmethod
import json
from typing import Iterable, Protocol

from .ttfr import TTFR
from .replay import ReplaySession
from .event import ForensicEvent
from ttfr.reader import TTFRAdapter


# ==================================================
# Replay Source Contract
# ==================================================

class ReplaySource(ABC):
    """
    Abstract replay source.

    A replay source is responsible ONLY for producing
    a ReplaySession with canonical forensic events.
    """

    @abstractmethod
    def load(self) -> ReplaySession:
        raise NotImplementedError


# ==================================================
# JSONL Replay Source (Stable / Default)
# ==================================================

class JsonReplaySource(ReplaySource):
    """
    Replay source backed by a JSONL event file.
    """

    def __init__(self, path: str):
        self.path = path

    def load(self) -> ReplaySession:
        ttfr = TTFR()

        with open(self.path, "r") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    e = json.loads(line)
                except json.JSONDecodeError as err:
                    raise RuntimeError(
                        f"Invalid JSON on line {line_num}: {err}"
                    ) from err

                ttfr.record(
                    timestamp=int(e["timestamp"]),
                    event_type=str(e["type"]),
                    payload=dict(e.get("payload", {})),
                )

        return ReplaySession(ttfr.snapshot())


# ==================================================
# TTFR Replay Source (REAL IMPLEMENTATION)
# ==================================================

class TTFRReplaySource(ReplaySource):
    """
    Replay source backed by a real TTFR engine.

    TTFR is treated as a black box and adapted
    into canonical forensic events.
    """

    def __init__(self, ttfr_engine):
        self.adapter = TTFRAdapter(ttfr_engine)

    def load(self) -> ReplaySession:
        ttfr = TTFR()

        for e in self.adapter.replay():
            ttfr.record(
                timestamp=int(e.timestamp),
                event_type=str(e.type),
                payload=dict(e.payload),
            )

        return ReplaySession(ttfr.snapshot())

