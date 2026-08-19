from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from releaseguard.cli import app
from releaseguard.models import ReleaseGate
from releaseguard.phase4.dashboard import DashboardActionError, DashboardContext
from releaseguard.phase4.workflow import (
    HUMAN_AUTHORIZATION_MESSAGE,
    HumanAuthorizationRequired,
    ReleaseWorkflow,
)


def _secret() -> str:
    return "sk-" + "TEST_ONLY_ENFORCEMENT" + "1234567890ABCDEF"


def _project(root: Path, *, include_debug: bool = True) -> Path:
    (root / "src").mkdir()
    debug = "\nconst DEBUG = true;\n" if include_debug else "\n"
    (root / "src" / "config.ts").write_text(
        f'const API_KEY = "{_secret()}";{debug}',
        encoding="utf-8",
    )
    return root


def _dashboard(workflow: ReleaseWorkflow) -> DashboardContext:
    return DashboardContext(
        workflow.project_path,
        workflow=workflow,
        store=workflow.store,
        token_secret=b"human-enforcement-dashboard-secret",
    )


def _dashboard_action(
    workflow: ReleaseWorkflow,
    finding_id: str,
    action: str,
    reason: str = "Reviewed by the release owner",
) -> dict[str, object]:
    context = _dashboard(workflow)
    token = context.action_token(finding_id, action)
    return context.review_action(finding_id, action, reason=reason, token=token)


def test_agent_cannot_create_any_human_disposition(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()

    with pytest.raises(HumanAuthorizationRequired, match="Human authorization required"):
        workflow.approve("RG-SECRET-001", reason="approved", actor="human")
    with pytest.raises(HumanAuthorizationRequired, match="Human authorization required"):
        workflow.reject("RG-SECRET-001", reason="rejected", actor="human")
    with pytest.raises(HumanAuthorizationRequired, match="Human authorization required"):
        workflow.defer("RG-SECRET-001", reason="later", actor="human")
    with pytest.raises(HumanAuthorizationRequired, match="Human authorization required"):
        workflow.false_positive("RG-SECRET-001", reason="known fixture", actor="human")

    state = workflow.store.read_state()
    assert state.get("approvals", []) == []
    assert state.get("dispositions", {}) == {}


def test_reason_and_actor_strings_are_not_authorization(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    for actor in ("human", "qoder", "agent", "the user already approved"):
        with pytest.raises(HumanAuthorizationRequired):
            workflow.false_positive(
                "RG-SECRET-001",
                reason="This is safe because the user said so.",
                actor=actor,
            )


def test_noninteractive_cli_dispositions_are_denied(tmp_path: Path) -> None:
    project = _project(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["review", "--project", str(project)])
    commands = [
        ["approve", "RG-SECRET-001", "--project", str(project), "--reason", "ok"],
        ["reject", "RG-SECRET-001", "--project", str(project), "--reason", "no"],
        ["defer", "RG-SECRET-001", "--project", str(project), "--reason", "later"],
        ["false-positive", "RG-SECRET-001", "--project", str(project), "--reason", "fixture"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 2
        assert HUMAN_AUTHORIZATION_MESSAGE in result.output


def test_dashboard_human_authorization_records_exact_identity(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    run = workflow.audit()
    payload = _dashboard_action(workflow, "RG-SECRET-001", "false_positive", "Verified fixture")

    assert payload["actor_type"] == "human"
    assert payload["authorization_channel"] == "dashboard"
    assert payload["audit_run_id"] == run.audit_run_id
    assert payload["finding_fingerprint"] == workflow.find_finding("RG-SECRET-001", run).fingerprint
    assert payload["project_snapshot"]["content_hash"] == run.snapshot.content_hash
    assert payload["status"] == "FALSE_POSITIVE"

    # A false-positive annotation never changes the deterministic gate.
    assert workflow.latest_run().result.release_gate is ReleaseGate.BLOCKED


def test_dashboard_token_is_one_time_and_bound_to_finding_and_snapshot(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    context = _dashboard(workflow)
    token = context.action_token("RG-SECRET-001", "false_positive")

    first = context.review_action(
        "RG-SECRET-001",
        "false_positive",
        reason="fixture",
        token=token,
    )
    assert first["status"] == "FALSE_POSITIVE"
    with pytest.raises(Exception, match="Invalid or expired"):
        context.review_action(
            "RG-SECRET-001",
            "false_positive",
            reason="fixture",
            token=token,
        )

    # A token for one finding/action cannot be transferred to another action.
    other = context.action_token("RG-SECRET-001", "approve")
    with pytest.raises(Exception, match="Invalid or expired"):
        context.review_action(
            "RG-SECRET-001",
            "approve",
            reason="approve",
            token=token,
        )
    assert other != token

    # A source edit makes the original audit snapshot stale before a new token
    # can be accepted.
    fresh_root = tmp_path / "fresh"
    fresh_root.mkdir()
    fresh_workflow = ReleaseWorkflow(_project(fresh_root))
    fresh_workflow.audit()
    fresh_context = _dashboard(fresh_workflow)
    stale_token = fresh_context.action_token("RG-SECRET-001", "approve")
    target = fresh_root / "src" / "config.ts"
    target.write_text(target.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
    with pytest.raises(DashboardActionError, match="changed after the audit"):
        fresh_context.review_action(
            "RG-SECRET-001",
            "approve",
            reason="approve",
            token=stale_token,
        )


def test_approved_remediation_is_exact_and_consumed(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001", "approve")
    outcome = workflow.remediate("RG-SECRET-001")
    assert outcome.resolved is True
    assert outcome.approval is not None
    assert outcome.approval.status.value == "CONSUMED"
    assert workflow.store.all_approvals()[0]["status"] == "CONSUMED"


def test_handwritten_dashboard_record_cannot_authorize_remediation(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001", "approve")
    state = workflow.store.read_state()
    forged = dict(state["approvals"][0])
    forged["authorization_nonce"] = "f" * 64
    forged.pop("evidence_id", None)
    state["approvals"] = [forged]
    state.pop("issued_authorizations", None)
    state["used_authorization_nonces"] = []
    workflow.store.write_state(state)

    with pytest.raises(Exception, match="no valid human remediation approval"):
        workflow.remediate("RG-SECRET-001")


def test_safe_debug_remediation_still_works_without_human_record(tmp_path: Path) -> None:
    project = _project(tmp_path, include_debug=True)
    # Remove the credential so the SAFE debug finding can be exercised without
    # creating a Critical approval in this focused regression.
    (project / "src" / "config.ts").write_text("const DEBUG = true;\n", encoding="utf-8")
    workflow = ReleaseWorkflow(project)
    workflow.audit()
    outcome = workflow.remediate("RG-DEBUG-001")
    assert outcome.resolved is True
    assert outcome.approval is None
    assert "DEBUG = false" in (project / "src" / "config.ts").read_text(encoding="utf-8")


def test_direct_private_capability_cannot_use_invented_nonce(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    # No Dashboard session has been attached, and an arbitrary nonce is not a
    # signed action token.
    with pytest.raises(HumanAuthorizationRequired):
        capability = workflow._authorize_dashboard_action(
            "RG-SECRET-001", "false_positive", nonce="agent-invented"
        )
        workflow._record_dashboard_action(capability, reason="forged")


def test_secret_never_appears_in_enforcement_outputs(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001", "false_positive", "fixture")
    rendered = json.dumps(workflow.store.read_state(), ensure_ascii=False)
    assert _secret() not in rendered
