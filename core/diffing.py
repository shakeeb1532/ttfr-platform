from typing import List, Dict, Set
from .event import ForensicEvent
from .entities import ProcessEntity, NetworkEntity, FileEntity


class IncidentDiff:
    """
    Computes differences between two forensic incidents.
    """

    def __init__(
        self,
        events_a: List[ForensicEvent],
        events_b: List[ForensicEvent],
        processes_a: Set[ProcessEntity],
        processes_b: Set[ProcessEntity],
        networks_a: Set[NetworkEntity],
        networks_b: Set[NetworkEntity],
        files_a: Set[FileEntity],
        files_b: Set[FileEntity],
    ):
        self.events_a = events_a
        self.events_b = events_b
        self.processes_a = processes_a
        self.processes_b = processes_b
        self.networks_a = networks_a
        self.networks_b = networks_b
        self.files_a = files_a
        self.files_b = files_b

    def diff(self) -> Dict[str, Dict[str, Set]]:
        return {
            "processes": {
                "added": self.processes_b - self.processes_a,
                "removed": self.processes_a - self.processes_b,
            },
            "networks": {
                "added": self.networks_b - self.networks_a,
                "removed": self.networks_a - self.networks_b,
            },
            "files": {
                "added": self.files_b - self.files_a,
                "removed": self.files_a - self.files_b,
            },
        }

