"""Structured, redacted audit timeline events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .redaction import redact_payload
from .store import EvidenceStore
from .models import TimelineEvent, TimelineEventType


def _event_value(event_type: TimelineEventType | str) -> Any:
    if isinstance(event_type, TimelineEventType):
        return event_type
    text = str(event_type)
    # Accept both the public enum values and compact names used by integrations.
    for candidate in TimelineEventType:
        if text.lower() in {candidate.value.lower(), candidate.name.lower()}:
            return candidate
    return text


def make_timeline_event(
    event_type: TimelineEventType | str,
    *,
    audit_run_id: str,
    finding_id: str | None = None,
    actor: str = "system",
    summary: str = "",
    metadata: dict[str, Any] | None = None,
) -> TimelineEvent:
    """Build a validated event without retaining unredacted metadata."""

    safe_metadata = redact_payload(metadata or {})
    values = {
        "event_id": uuid4().hex,
        "timestamp": datetime.now(timezone.utc),
        "type": _event_value(event_type),
        "event_type": _event_value(event_type),
        "audit_run_id": str(audit_run_id),
        "finding_id": finding_id,
        "actor": actor or "system",
        "summary": redact_payload(str(summary)),
        "metadata": safe_metadata,
    }
    # The model supports aliases in current code; retry with the minimal field
    # set so integrations built against an early Phase 4 contract still work.
    try:
        return TimelineEvent(**values)
    except Exception:
        values.pop("event_type", None)
        return TimelineEvent(**values)


def append_timeline(
    store: EvidenceStore,
    event_type: TimelineEventType | str,
    *,
    audit_run_id: str,
    finding_id: str | None = None,
    actor: str = "system",
    summary: str = "",
    metadata: dict[str, Any] | None = None,
    evidence_directory: str | None = None,
) -> TimelineEvent:
    """Append an event to the redacted state index and optional run artifact."""

    event = make_timeline_event(
        event_type,
        audit_run_id=audit_run_id,
        finding_id=finding_id,
        actor=actor,
        summary=summary,
        metadata=metadata,
    )
    state = store.read_state()
    timeline = state.get("timeline", [])
    if not isinstance(timeline, list):
        timeline = []
    timeline.append(event.model_dump(mode="json"))
    state["timeline"] = timeline
    store.write_state(state)
    if evidence_directory:
        existing: list[dict[str, Any]] = []
        try:
            value = store.read_json(store._artifact_path(evidence_directory, "timeline.json"))
            if isinstance(value, list):
                existing = value
        except (OSError, ValueError):
            pass
        existing.append(event.model_dump(mode="json"))
        store.write_json(evidence_directory, "timeline.json", existing)
    return event


# Common aliases used by API consumers.
record_event = append_timeline
TimelineRecorder = append_timeline


__all__ = ["TimelineRecorder", "append_timeline", "make_timeline_event", "record_event"]
