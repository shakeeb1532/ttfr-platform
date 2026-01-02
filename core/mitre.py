from dataclasses import dataclass
from typing import List, Dict
from .event import ForensicEvent


@dataclass(frozen=True)
class MitreTechnique:
    """
    MITRE ATT&CK technique instance bound to time.
    """
    technique_id: str
    name: str
    event_seq: int
    timestamp: int
    rationale: str


class MitreMapper:
    """
    Deterministic mapping from forensic events to MITRE techniques.
    """

    def map_event(self, event: ForensicEvent) -> List[MitreTechnique]:
        et = event.event_type
        p = event.payload

        techniques: List[MitreTechnique] = []

        # -------------------------------
        # Process Execution
        # -------------------------------
        if et == "process_start":
            image = p.get("image", "").lower()

            if "powershell" in image:
                techniques.append(
                    MitreTechnique(
                        technique_id="T1059.001",
                        name="PowerShell",
                        event_seq=event.seq,
                        timestamp=event.timestamp,
                        rationale="PowerShell process execution detected",
                    )
                )
            else:
                techniques.append(
                    MitreTechnique(
                        technique_id="T1059",
                        name="Command and Scripting Interpreter",
                        event_seq=event.seq,
                        timestamp=event.timestamp,
                        rationale="Generic process execution",
                    )
                )

        # -------------------------------
        # Network Command & Control
        # -------------------------------
        elif et == "network_connect":
            techniques.append(
                MitreTechnique(
                    technique_id="T1071.001",
                    name="Application Layer Protocol: Web Protocols",
                    event_seq=event.seq,
                    timestamp=event.timestamp,
                    rationale="Outbound network connection observed",
                )
            )

        # -------------------------------
        # File Write / Payload Drop
        # -------------------------------
        elif et == "file_write":
            techniques.append(
                MitreTechnique(
                    technique_id="T1105",
                    name="Ingress Tool Transfer",
                    event_seq=event.seq,
                    timestamp=event.timestamp,
                    rationale="Executable written to disk",
                )
            )

        return techniques

    def map_timeline(self, events: List[ForensicEvent]) -> List[MitreTechnique]:
        timeline: List[MitreTechnique] = []

        for e in events:
            timeline.extend(self.map_event(e))

        return timeline

