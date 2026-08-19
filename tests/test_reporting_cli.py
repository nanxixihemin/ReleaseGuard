from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from releaseguard.cli import app
from releaseguard.models import AuditResult, AuditSummary, Finding, GitSnapshot, ReleaseGate, Severity
from releaseguard.reporters import render_json, render_markdown


def _sample_result() -> AuditResult:
    finding = Finding(
        rule_id="RG-SECRET-001",
        title="Potential API credential detected",
        severity=Severity.CRITICAL,
        category="secrets",
        file="src/config.py",
        line=4,
        evidence="sk-12********def",
        explanation="A credential-like value appears in source.",
        recommendation="Move it to a secret manager.",
    )
    return AuditResult(
        project_path="C:/demo",
        project_name="demo",
        release_score=75,
        release_gate=ReleaseGate.BLOCKED,
        summary=AuditSummary.from_findings([finding], files_scanned=1, rules_executed=7),
        findings=[finding],
        git=GitSnapshot(available=True, is_repository=True, branch="main", head_commit="abc1234"),
    )


def test_json_report_is_parseable_and_does_not_change_contract() -> None:
    payload = json.loads(render_json(_sample_result()))

    assert payload["release_gate"] == "BLOCKED"
    assert payload["findings"][0]["evidence"] == "sk-12********def"


def test_markdown_report_contains_summary_and_recommendation() -> None:
    report = render_markdown(_sample_result())

    assert "# ReleaseGuard Audit" in report
    assert "[CRITICAL] RG-SECRET-001" in report
    assert "Move it to a secret manager." in report
    assert "Git: main (abc1234)" in report


def test_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert "ReleaseGuard 0.2.0" in result.output


def test_audit_command_renders_json(monkeypatch, tmp_path: Path) -> None:
    sample = _sample_result()
    monkeypatch.setattr("releaseguard.cli.audit_project", lambda _: sample)

    result = CliRunner().invoke(app, ["audit", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    assert json.loads(result.output)["project_name"] == "demo"


def test_audit_command_rejects_unknown_format(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["audit", str(tmp_path), "--format", "xml"])

    assert result.exit_code == 2
    assert "--format must be either" in result.output


def test_audit_command_writes_requested_output(monkeypatch, tmp_path: Path) -> None:
    sample = _sample_result()
    destination = tmp_path / "report.json"
    monkeypatch.setattr("releaseguard.cli.audit_project", lambda _: sample)

    result = CliRunner().invoke(
        app,
        ["audit", str(tmp_path), "--format", "json", "--output", str(destination)],
    )

    assert result.exit_code == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["release_gate"] == "BLOCKED"
