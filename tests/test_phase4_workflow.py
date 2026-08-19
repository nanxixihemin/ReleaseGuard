from __future__ import annotations

import json
from pathlib import Path

import pytest

from releaseguard.models import FindingStatus, ReleaseGate
from releaseguard.phase4.workflow import (
    ApprovalRequired,
    HumanAuthorizationRequired,
    ReleaseWorkflow,
    ScopeViolation,
    StaleApproval,
)
from releaseguard.phase4.dashboard import DashboardContext


def _secret() -> str:
    # Build the sentinel at runtime so this test file never stores a complete
    # credential-shaped value in the repository.
    return "sk-" + "TEST_ONLY_PHASE4_DEMO" + "1234567890ABCDEF"


def _project(root: Path) -> Path:
    (root / "src").mkdir()
    (root / "src" / "config.ts").write_text(
        f'export const API_KEY = "{_secret()}";\nexport const DEBUG = true;\n',
        encoding="utf-8",
    )
    return root


def _dashboard_action(
    workflow: ReleaseWorkflow,
    finding_id: str,
    action: str = "approve",
    reason: str = "Approved migration",
) -> dict[str, object]:
    context = DashboardContext(
        workflow.project_path,
        workflow=workflow,
        store=workflow.store,
        token_secret=b"phase4-test-dashboard-secret",
    )
    token = context.action_token(finding_id, action)
    return context.review_action(finding_id, action, reason=reason, token=token)


def test_review_and_approval_are_bound_without_resolving(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    run = workflow.audit()

    secret = workflow.find_finding("RG-SECRET-001", run)
    assert secret.status is FindingStatus.NEEDS_REVIEW
    with pytest.raises(HumanAuthorizationRequired, match="Human authorization required"):
        workflow.approve("RG-SECRET-001", reason="Approved environment migration")
    record = _dashboard_action(workflow, "RG-SECRET-001")
    assert record["status"] == "APPROVED"
    assert record["actor_type"] == "human"
    assert record["authorization_channel"] == "dashboard"
    assert workflow.latest_run().result.release_gate is ReleaseGate.BLOCKED
    assert workflow.find_finding("RG-SECRET-001").status.value == "APPROVED"
    assert workflow.store.all_approvals()[0]["status"] == "APPROVED"


def test_false_positive_requires_reason_and_invalid_resolution_fails(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    with pytest.raises(Exception, match="reason"):
        workflow.false_positive("RG-SECRET-001", reason="")
    if any(f.rule_id == "RG-ENV-001" for f in workflow.review()):
        _dashboard_action(
            workflow,
            "RG-ENV-001",
            action="false_positive",
            reason="Fixture endpoint is intentionally local",
        )
    workflow.store.read_state()


def test_stale_approval_fails_closed(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001")
    (tmp_path / "src" / "config.ts").write_text(
        (tmp_path / "src" / "config.ts").read_text(encoding="utf-8") + "// unrelated user edit\n",
        encoding="utf-8",
    )
    with pytest.raises(StaleApproval):
        workflow.remediate("RG-SECRET-001")
    assert any("stale_approval" in path.read_text(encoding="utf-8") for path in workflow.store.root.rglob("error.json"))


def test_approved_secret_remediation_is_scope_checked_and_reaudited(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001")
    outcome = workflow.remediate("RG-SECRET-001")

    assert set(outcome.changed_files) == {"src/config.ts", ".env.example"}
    assert outcome.resolved is True
    assert outcome.result.release_gate is ReleaseGate.PASS  # DEBUG is not a blocking critical finding
    assert "process.env.API_KEY" in (tmp_path / "src" / "config.ts").read_text(encoding="utf-8")
    assert _secret() not in (tmp_path / ".env.example").read_text(encoding="utf-8")
    for artifact in workflow.store.root.rglob("*"):
        if artifact.is_file():
            assert _secret() not in artifact.read_text(encoding="utf-8", errors="replace")


def test_unauthorized_executor_change_fails_closed(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    _dashboard_action(workflow, "RG-SECRET-001")

    def unsafe(project: Path, *_args: object) -> None:
        (project / "README.md").write_text("unapproved change\n", encoding="utf-8")

    with pytest.raises(ScopeViolation):
        workflow.remediate("RG-SECRET-001", executor=unsafe)


def test_remediation_requires_approval(tmp_path: Path) -> None:
    workflow = ReleaseWorkflow(_project(tmp_path))
    workflow.audit()
    with pytest.raises(ApprovalRequired):
        workflow.remediate("RG-SECRET-001")
