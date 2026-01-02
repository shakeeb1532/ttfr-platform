from dataclasses import dataclass
from typing import List
from .event import ForensicEvent


@dataclass(frozen=True)
class DetectionHit:
    """
    A detection hit bound to a forensic event.
    """
    rule_id: str
    description: str
    event_seq: int
    timestamp: int
    evidence: str


class DetectionRule:
    """
    Base class for retroactive detection rules.
    """

    rule_id: str = "RULE-BASE"
    description: str = "Base detection rule"

    def evaluate(self, event: ForensicEvent) -> List[DetectionHit]:
        raise NotImplementedError


# --------------------------------------------------
# Example Detection Rules
# --------------------------------------------------

class SuspiciousPowerShellRule(DetectionRule):
    rule_id = "DET-PS-001"
    description = "Suspicious PowerShell execution"

    def evaluate(self, event: ForensicEvent) -> List[DetectionHit]:
        if event.event_type == "process_start":
            image = event.payload.get("image", "").lower()
            if "powershell" in image:
                return [
                    DetectionHit(
                        rule_id=self.rule_id,
                        description=self.description,
                        event_seq=event.seq,
                        timestamp=event.timestamp,
                        evidence=f"Process image: {image}",
                    )
                ]
        return []


class SuspiciousC2ConnectionRule(DetectionRule):
    rule_id = "DET-C2-001"
    description = "Suspicious outbound network connection"

    def evaluate(self, event: ForensicEvent) -> List[DetectionHit]:
        if event.event_type == "network_connect":
            port = int(event.payload.get("port", 0))
            if port not in (80, 443):
                return [
                    DetectionHit(
                        rule_id=self.rule_id,
                        description=self.description,
                        event_seq=event.seq,
                        timestamp=event.timestamp,
                        evidence=f"Outbound connection on port {port}",
                    )
                ]
        return []


# --------------------------------------------------
# Detection Engine
# --------------------------------------------------

class RetroDetectionEngine:
    """
    Applies detection rules retroactively over replayed events.
    """

    def __init__(self, rules: List[DetectionRule]):
        self.rules = rules

    def run(self, events: List[ForensicEvent]) -> List[DetectionHit]:
        hits: List[DetectionHit] = []

        for e in events:
            for rule in self.rules:
                hits.extend(rule.evaluate(e))

        return hits

