from __future__ import annotations

from pathlib import Path

from releaseguard.reporters import render_json, render_markdown
from releaseguard.scanner import audit_project, default_rules


def test_default_rules_cover_the_phase_one_release_signals() -> None:
    assert {rule.rule_id for rule in default_rules()} == {
        "RG-ARTIFACT-001",
        "RG-CONFIG-001",
        "RG-DEBUG-001",
        "RG-ENV-001",
        "RG-GIT-001",
        "RG-SECRET-001",
        "RG-SENSITIVE-001",
        "RG-TODO-001",
    }


def test_audit_result_exposes_git_state_and_artifact_findings(tmp_path: Path) -> None:
    (tmp_path / "scratch.sqlite3").write_text("local data", encoding="utf-8")

    result = audit_project(tmp_path)

    assert result.summary.rules_executed == 8
    assert result.git.is_repository is False
    assert any(finding.rule_id == "RG-ARTIFACT-001" for finding in result.findings)


def test_full_reports_do_not_expose_secrets_from_todos_or_endpoints(tmp_path: Path) -> None:
    raw_token = "sk-FAKE_REPORT_TOKEN_1234567890"
    raw_password = "OperatorPassword123!"
    (tmp_path / "config.py").write_text(
        (
            'PRODUCTION_API_URL = "http://operator:'
            f"{raw_password}@localhost:8080/api?token={raw_token}" + '"\n'
            f"# TODO: rotate {raw_token}\n"
        ),
        encoding="utf-8",
    )

    result = audit_project(tmp_path)
    report = render_json(result) + render_markdown(result)

    assert raw_token not in report
    assert raw_password not in report
