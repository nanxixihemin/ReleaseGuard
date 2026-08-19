from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from releaseguard.cli import app
from releaseguard.phase4.dashboard import DashboardContext
from releaseguard.phase4.workflow import ReleaseWorkflow


def _token() -> str:
    return "sk-" + "TEST_ONLY_CLI_PHASE4" + "1234567890ABCDEF"


def _project(root: Path) -> Path:
    (root / "src").mkdir()
    (root / "src" / "config.ts").write_text(
        f'const API_KEY = "{_token()}";\n', encoding="utf-8"
    )
    return root


def test_review_approve_and_remediate_cli_flow_is_safe(tmp_path: Path) -> None:
    project = _project(tmp_path)
    runner = CliRunner()

    review = runner.invoke(app, ["review", "--project", str(project)])
    assert review.exit_code == 0
    assert "RG-SECRET-001" in review.output
    assert _token() not in review.output

    approval = runner.invoke(
        app,
        ["approve", "RG-SECRET-001", "--project", str(project), "--reason", "Approved migration"],
    )
    assert approval.exit_code == 2
    assert "Human authorization required." in approval.output
    assert "Open ReleaseGuard Dashboard" in approval.output

    # The legal mutation travels through the local Dashboard trust boundary.
    workflow = ReleaseWorkflow(project)
    context = DashboardContext(
        project,
        workflow=workflow,
        store=workflow.store,
        token_secret=b"phase4-cli-dashboard-secret",
    )
    token = context.action_token("RG-SECRET-001", "approve")
    approval_payload = context.review_action(
        "RG-SECRET-001",
        "approve",
        reason="Approved migration",
        token=token,
    )
    assert approval_payload["status"] == "APPROVED"
    assert approval_payload["authorization_channel"] == "dashboard"
    assert _token() not in approval.output

    remediation = runner.invoke(app, ["remediate", "RG-SECRET-001", "--project", str(project)])
    assert remediation.exit_code == 0
    payload = json.loads(remediation.output)
    assert payload["resolved"] is True
    assert _token() not in remediation.output


def test_false_positive_cli_requires_reason(tmp_path: Path) -> None:
    project = _project(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["review", "--project", str(project)])
    result = runner.invoke(app, ["false-positive", "RG-SECRET-001", "--project", str(project)])
    assert result.exit_code == 2
    assert "requires --reason" in result.output
