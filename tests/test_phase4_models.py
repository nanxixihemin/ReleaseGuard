from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from releaseguard.models import Finding, FindingStatus, Severity
from releaseguard.phase4.models import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    AuthorizationChannel,
    ProjectSnapshot,
    RemediationPlan,
    TimelineEvent,
    TimelineEventType,
)
from releaseguard.phase4.redaction import (
    assert_no_raw_secrets,
    contains_raw_secret,
    redact_for_persistence,
    redact_text,
    redact_value,
)
from releaseguard.remediation import RemediationItem, remediation_for


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": "RG-SECRET-001",
        "title": "Credential detected",
        "severity": Severity.CRITICAL,
        "category": "secrets",
        "file": "src/config.py",
        "line": 7,
        "evidence": 'API_KEY = "[REDACTED_TOKEN]"',
    }
    values.update(overrides)
    return Finding(**values)


def _snapshot() -> ProjectSnapshot:
    return ProjectSnapshot(
        snapshot_id="snap-1",
        files={
            "src/config.py": hashlib.sha256(b"config").hexdigest(),
            "README.md": hashlib.sha256(b"readme").hexdigest(),
        },
    )


def test_phase4_enums_round_trip_to_json_safe_values() -> None:
    record = ApprovalRecord(
        finding_id="RG-SECRET-001",
        action=ApprovalAction.MARK_FALSE_POSITIVE,
        reason="The fixture is intentionally synthetic.",
        audit_run_id="audit-1",
        project_snapshot=_snapshot(),
    )
    event = TimelineEvent(
        type=TimelineEventType.HUMAN_REVIEW_REQUESTED,
        audit_run_id="audit-1",
        finding_id="RG-SECRET-001",
    )

    record_payload = json.loads(record.model_dump_json())
    event_payload = json.loads(event.model_dump_json())

    assert record_payload["action"] == "MARK_FALSE_POSITIVE"
    assert record_payload["status"] == "FALSE_POSITIVE"
    assert event_payload["type"] == "HUMAN_REVIEW_REQUESTED"
    assert ApprovalAction(record_payload["action"]) is ApprovalAction.MARK_FALSE_POSITIVE
    assert TimelineEventType(event_payload["type"]) is TimelineEventType.HUMAN_REVIEW_REQUESTED


def test_approval_binds_identity_and_snapshot() -> None:
    snapshot = _snapshot()
    plan = RemediationPlan(
        finding_id="RG-SECRET-001",
        summary="Move the literal to an environment variable reference.",
        risk="REVIEW_REQUIRED",
        allowed_files=["src/config.py"],
        allowed_operations=["replace the literal with process.env.API_KEY"],
        forbidden_operations=["write a real credential"],
        requires_human_approval=True,
        expected_effect="Rerun ReleaseGuard.",
        fingerprint="f" * 64,
    )
    approval = ApprovalRecord(
        approval_id="approval-1",
        finding_id="RG-SECRET-001",
        finding_fingerprint=plan.fingerprint,
        action="APPROVE_REMEDIATION",
        actor="human",
        audit_run_id="audit-1",
        project_snapshot=snapshot,
        requested_remediation=plan,
    )

    assert approval.approval_id == "approval-1"
    assert approval.finding_id == "RG-SECRET-001"
    assert approval.audit_run_id == "audit-1"
    assert approval.snapshot_hash == snapshot.content_hash
    assert approval.status is ApprovalStatus.APPROVED
    assert approval.approved is True
    assert approval.resolved is False


def test_human_authorization_markers_are_explicit_and_channel_bound() -> None:
    approval = ApprovalRecord(
        finding_id="RG-SECRET-001",
        finding_fingerprint="f" * 64,
        action="APPROVE_REMEDIATION",
        actor="human",
        actor_type="human",
        authorization_channel="dashboard",
        authorization_nonce="a" * 64,
        audit_run_id="audit-1",
        project_snapshot=_snapshot(),
    )
    assert approval.authorization_channel is AuthorizationChannel.DASHBOARD
    assert approval.human_authorized is True
    with pytest.raises(ValidationError, match="dashboard authorization channel"):
        ApprovalRecord(
            finding_id="RG-SECRET-001",
            action="APPROVE_REMEDIATION",
            actor_type="human",
            authorization_channel="cli",
            audit_run_id="audit-1",
            project_snapshot=_snapshot(),
        )


def test_false_positive_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="reason"):
        ApprovalRecord(
            finding_id="RG-SECRET-001",
            action="MARK_FALSE_POSITIVE",
            audit_run_id="audit-1",
            project_snapshot=_snapshot(),
        )


def test_approved_does_not_mean_resolved_and_only_reaudit_can_mark_resolved() -> None:
    finding = _finding()
    assert finding.status is FindingStatus.OPEN

    with pytest.raises(ValueError, match="verified re-audit"):
        finding.with_status(FindingStatus.RESOLVED)

    resolved = finding.mark_resolved_after_reaudit(audit_run_id="audit-2")
    assert finding.status is FindingStatus.OPEN
    assert resolved.status is FindingStatus.RESOLVED
    assert resolved.fingerprint == finding.fingerprint


def test_snapshot_hash_is_stable_and_order_independent() -> None:
    first = _snapshot()
    second = ProjectSnapshot(
        snapshot_id="snap-2",
        files={
            "README.md": hashlib.sha256(b"readme").hexdigest(),
            "src/config.py": hashlib.sha256(b"config").hexdigest(),
        },
    )

    assert first.content_hash == second.content_hash
    assert first.snapshot_hash == first.hash
    with pytest.raises(ValidationError, match="content_hash"):
        ProjectSnapshot(
            files={"src/config.py": hashlib.sha256(b"config").hexdigest()},
            content_hash="0" * 64,
        )


def test_remediation_item_converts_without_changing_phase3_item() -> None:
    finding = _finding(
        rule_id="RG-DEBUG-001",
        title="Debug mode enabled",
        severity=Severity.LOW,
        category="debug",
        metadata={"debug_setting": "debug_enabled"},
        evidence="DEBUG = true",
    )
    item: RemediationItem = remediation_for(finding)
    before = item.model_dump(mode="json")
    plan = RemediationPlan.from_item(item)

    assert item.model_dump(mode="json") == before
    assert plan.finding_id == item.finding
    assert plan.fingerprint == item.fingerprint
    assert plan.allowed_files == [item.target_file]
    assert plan.requires_human_approval is False


def test_redaction_handles_nested_values_and_free_form_evidence() -> None:
    raw = "sk-FAKE_RELEASE_GUARD_1234567890"
    payload = {
        "evidence": f'OPENAI_API_KEY = "{raw}"',
        "nested": [{"password": "super-secret-value"}, raw],
        "safe": "ordinary context",
    }

    redacted = redact_for_persistence(payload, secrets=[raw, "super-secret-value"])

    rendered = json.dumps(redacted, ensure_ascii=False)
    assert raw not in rendered
    assert "super-secret-value" not in rendered
    assert redacted["safe"] == "ordinary context"
    assert contains_raw_secret(redacted, secrets=[raw, "super-secret-value"]) is False
    assert_no_raw_secrets(redacted, secrets=[raw, "super-secret-value"])
    assert raw not in redact_text(f"token={raw}")
    assert raw not in str(redact_value(payload, secrets=[raw, "super-secret-value"]))
