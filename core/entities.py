"""
Entity Extraction

Hardened for real-world telemetry:
- Missing fields tolerated
- No KeyErrors under stress data
"""

from dataclasses import dataclass
from typing import Set, Dict, Any
from .event import ForensicEvent


@dataclass(frozen=True)
class ProcessEntity:
    pid: int
    image: str


@dataclass(frozen=True)
class NetworkEntity:
    dst: str
    port: int


@dataclass(frozen=True)
class FileEntity:
    path: str


class EntityExtractor:
    def __init__(self):
        self.processes: Set[ProcessEntity] = set()
        self.networks: Set[NetworkEntity] = set()
        self.files: Set[FileEntity] = set()

    def extract(self, events):
        for e in events:
            self.process_event(e)

    def process_event(self, e: ForensicEvent):
        p = e.payload or {}

        # ---------------- Process ----------------
        if e.event_type == "process_start":
            self.processes.add(
                ProcessEntity(
                    pid=int(p.get("pid", -1)),
                    image=str(p.get("image", "<unknown>")),
                )
            )

        # ---------------- Network ----------------
        elif e.event_type == "network_connect":
            self.networks.add(
                NetworkEntity(
                    dst=str(p.get("dst", "<unknown>")),
                    port=int(p.get("port", -1)),
                )
            )

        # ---------------- File ----------------
        elif e.event_type == "file_write":
            self.files.add(
                FileEntity(
                    path=str(p.get("path", "<unknown>")),
                )
            )

