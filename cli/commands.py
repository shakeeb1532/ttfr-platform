# cli/commands.py
import json
import os
import time

from core.replay_source import JsonReplaySource, TTFRReplaySource
from core.entities import EntityExtractor
from core.mitre import MitreMapper
from core.bookmarks import BookmarkStore
from core.detections import (
    RetroDetectionEngine,
    SuspiciousPowerShellRule,
    SuspiciousC2ConnectionRule,
)
from intelligence.narrative import NarrativeGenerator
from reports.forensic_report import ForensicReportBuilder
from reports.executive_summary import ExecutiveSummaryBuilder
from ttfr.engine import TTFREngine
from case_db import CaseDAO


# ==================================================
# Batch Ingest
# ==================================================

def run_ingest(input_path: str, snapshot_id: str):
    ttfr = TTFREngine()

    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            ttfr.record(
                timestamp=e["timestamp"],
                event_type=e["type"],
                payload=e.get("payload", {}),
            )

    path = ttfr.save_snapshot(snapshot_id)
    print(f"[OK] Ingested snapshot '{snapshot_id}'")
    print(f"[OK] Saved to {path}")


# ==================================================
# Streaming Ingest (true tail-follow)
# ==================================================

def run_stream(input_path: str, snapshot_id: str, sleep_seconds: float, checkpoint_every: int):
    ttfr = TTFREngine()
    checkpoint_every = int(checkpoint_every) if checkpoint_every and checkpoint_every > 0 else 200
    sleep_seconds = float(sleep_seconds) if sleep_seconds and sleep_seconds > 0 else 0.0

    print(f"[STREAM] Starting live ingest → snapshot '{snapshot_id}'")
    print(f"[STREAM] Following file: {input_path}")
    print(f"[STREAM] checkpoint_every={checkpoint_every} • sleep={sleep_seconds}s")

    # Wait until file exists (common in live pipelines)
    while not os.path.exists(input_path):
        time.sleep(0.25)

    event_count = 0

    with open(input_path, "r") as f:
        # Start at end if you want "only new"
        # Comment out next line if you want replay from beginning.
        f.seek(0, os.SEEK_END)

        try:
            while True:
                line = f.readline()
                if not line:
                    # No new data yet
                    time.sleep(max(0.05, sleep_seconds))
                    continue

                line = line.strip()
                if not line:
                    continue

                e = json.loads(line)
                ttfr.record(
                    timestamp=e["timestamp"],
                    event_type=e["type"],
                    payload=e.get("payload", {}),
                )
                event_count += 1

                if event_count % checkpoint_every == 0:
                    ttfr.save_snapshot(snapshot_id)
                    print(f"[STREAM] Checkpoint at event {event_count}")

                if sleep_seconds > 0:
                    time.sleep(sleep_seconds)

        except KeyboardInterrupt:
            pass

    path = ttfr.save_snapshot(snapshot_id)
    print(f"[STREAM] Final snapshot saved to {path}")


# ==================================================
# Replay Source Selection
# ==================================================

def load_replay(source: str, input_path: str | None, snapshot_id: str | None):
    if source == "json":
        if not input_path:
            raise ValueError("JSON source requires input path")
        return JsonReplaySource(input_path).load()

    if source == "ttfr":
        if not snapshot_id:
            raise ValueError("TTFR source requires --snapshot")
        ttfr = TTFREngine.load_snapshot(snapshot_id)
        return TTFRReplaySource(ttfr).load()

    raise ValueError(source)


def common_analysis(source: str, input_path: str | None, snapshot_id: str | None):
    replay = load_replay(source, input_path, snapshot_id)
    events = replay.replay()

    extractor = EntityExtractor()
    extractor.extract(events)

    mapper = MitreMapper()
    mitre = mapper.map_timeline(events)

    bookmarks = BookmarkStore()
    if events:
        bookmarks.add(0, min(1, len(events) - 1), "Initial Activity")

    return events, extractor, mitre, bookmarks


# ==================================================
# Analysis Commands
# ==================================================

def run_analysis(source: str, input_path: str | None, snapshot_id: str | None):
    events, extractor, mitre, _ = common_analysis(source, input_path, snapshot_id)

    print("=== ANALYSIS ===")
    print(f"Events: {len(events)}")
    print(f"Processes: {len(extractor.processes)}")
    print(f"Networks: {len(extractor.networks)}")
    print(f"Files: {len(extractor.files)}")

    print("\nMITRE Timeline:")
    for t in mitre[:50]:
        print(f"[{t.timestamp}] {t.technique_id} - {t.name}")


def run_detections(source: str, input_path: str | None, snapshot_id: str | None):
    replay = load_replay(source, input_path, snapshot_id)
    events = replay.replay()

    engine = RetroDetectionEngine(
        rules=[
            SuspiciousPowerShellRule(),
            SuspiciousC2ConnectionRule(),
        ]
    )

    hits = engine.run(events)

    print("=== RETROACTIVE DETECTIONS ===")
    for h in hits:
        print(f"[{h.timestamp}] {h.rule_id} (event {h.event_seq}) -> {h.evidence}")


def run_report(source: str, input_path: str | None, snapshot_id: str | None):
    events, extractor, mitre, bookmarks = common_analysis(source, input_path, snapshot_id)

    narrator = NarrativeGenerator()
    narrative = narrator.generate(
        mitre_timeline=mitre,
        bookmarks=bookmarks.all(),
        processes=extractor.processes,
        networks=extractor.networks,
        files=extractor.files,
    )

    builder = ForensicReportBuilder()
    report = builder.build(
        narrative=narrative,
        mitre_timeline=mitre,
        bookmarks=bookmarks.all(),
        processes=extractor.processes,
        networks=extractor.networks,
        files=extractor.files,
    )

    print(json.dumps(report, indent=2))


def run_exec_summary(source: str, input_path: str | None, snapshot_id: str | None):
    events, extractor, mitre, _ = common_analysis(source, input_path, snapshot_id)

    incident_summary = {
        "process_count": len(extractor.processes),
        "network_count": len(extractor.networks),
        "file_count": len(extractor.files),
    }

    builder = ExecutiveSummaryBuilder()
    summary = builder.build(
        incident_summary=incident_summary,
        mitre_timeline=mitre,
    )

    print(json.dumps(summary, indent=2))


# ==================================================
# Case Database Commands
# ==================================================

def run_case_create(snapshot_id: str, title: str):
    dao = CaseDAO()
    dao.create_case(snapshot_id=snapshot_id, title=title)
    print(f"[OK] Case '{snapshot_id}' registered")


def run_case_list():
    dao = CaseDAO()
    cases = dao.list_cases()

    if not cases:
        print("No cases found.")
        return

    print("=== CASES ===")
    for c in cases:
        print(f"{c.id} | {c.title} | severity={c.severity} | status={c.status}")

