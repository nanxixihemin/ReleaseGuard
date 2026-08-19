from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from releaseguard.cli import app
from releaseguard.models import AuditResult, AuditSummary, Finding, ReleaseGate, Severity
from releaseguard.remediation import compare_audits
from releaseguard.reporters import render_reaudit_markdown


def _finding(
    rule_id: str,
    severity: Severity,
    *,
    line: int,
    title: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="test",
        file="src/config.py",
        line=line,
        evidence=f"{rule_id} evidence",
        explanation="A deterministic test finding.",
        recommendation="Resolve it before release.",
    )


def _result(findings: list[Finding]) -> AuditResult:
    score = 100 - sum(
        {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
        }[finding.severity]
        for finding in findings
    )
    gate = ReleaseGate.BLOCKED if any(
        finding.severity is Severity.CRITICAL for finding in findings
    ) else ReleaseGate.PASS
    return AuditResult(
        project_path="C:/demo",
        project_name="demo",
        release_score=score,
        release_gate=gate,
        summary=AuditSummary.from_findings(findings),
        findings=findings,
    )


def test_reaudit_uses_the_later_deterministic_scan_not_ai_advice() -> None:
    debug = _finding(
        "RG-DEBUG-001",
        Severity.HIGH,
        line=1,
        title="Debug mode enabled",
    )
    secret_before = _finding(
        "RG-SECRET-001",
        Severity.CRITICAL,
        line=2,
        title="Potential API credential detected",
    )
    # The line moved after a safe debug edit, but the secret is still detected.
    secret_after = _finding(
        "RG-SECRET-001",
        Severity.CRITICAL,
        line=8,
        title="Potential API credential detected",
    )

    comparison = compare_audits(_result([debug, secret_before]), _result([secret_after]))

    assert comparison.before.score == 63
    assert comparison.after.score == 75
    assert comparison.after.gate == "BLOCKED"
    assert [item.rule_id for item in comparison.resolved_findings] == ["RG-DEBUG-001"]
    assert [item.rule_id for item in comparison.remaining_findings] == ["RG-SECRET-001"]
    assert comparison.new_findings == []

    report = render_reaudit_markdown(comparison)
    assert "# ReleaseGuard Re-Audit" in report
    assert "## Before" in report
    assert "## After" in report
    assert "RG-DEBUG-001" in report
    assert "RG-SECRET-001" in report
    assert "Secret rotation requires manual intervention." in report


def test_compare_command_serializes_valid_saved_audits(tmp_path: Path) -> None:
    before = _result(
        [
            _finding(
                "RG-DEBUG-001",
                Severity.HIGH,
                line=1,
                title="Debug mode enabled",
            )
        ]
    )
    after = _result([])
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(before.to_json(), encoding="utf-8")
    after_path.write_text(after.to_json(), encoding="utf-8")

    response = CliRunner().invoke(
        app,
        ["compare", str(before_path), str(after_path), "--format", "json"],
    )

    assert response.exit_code == 0
    payload = json.loads(response.output)
    assert payload["before"]["score"] == 88
    assert payload["after"]["gate"] == "PASS"
    assert payload["resolved_findings"][0]["rule_id"] == "RG-DEBUG-001"


def test_compare_command_rejects_non_audit_json(tmp_path: Path) -> None:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text("{}", encoding="utf-8")
    after_path.write_text("{}", encoding="utf-8")

    response = CliRunner().invoke(app, ["compare", str(before_path), str(after_path)])

    assert response.exit_code == 2
    assert "valid ReleaseGuard JSON audit" in response.output


def test_audit_remediation_flag_forwards_only_when_requested(monkeypatch, tmp_path: Path) -> None:
    received: dict[str, object] = {}
    result = _result([])

    def fake_audit(path: Path, **kwargs: object) -> AuditResult:
        received["path"] = path
        received.update(kwargs)
        return result

    monkeypatch.setattr("releaseguard.cli.audit_project", fake_audit)

    response = CliRunner().invoke(
        app,
        ["audit", str(tmp_path), "--format", "json", "--remediation-plan"],
    )

    assert response.exit_code == 0
    assert received["path"] == tmp_path
    assert received["include_remediation_plan"] is True
