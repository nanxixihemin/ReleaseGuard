from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from releaseguard.ai.schemas import AIReview, ReviewStatus
from releaseguard.cli import app
from releaseguard.models import AuditResult, ReleaseGate
from releaseguard.reporters import render_markdown


def test_audit_ai_option_passes_a_local_client_and_keeps_deterministic_result(
    monkeypatch, tmp_path: Path
) -> None:
    received: dict[str, object] = {}
    result = AuditResult(
        project_path=str(tmp_path),
        project_name="demo",
        release_score=100,
        release_gate=ReleaseGate.PASS,
        ai_review=AIReview(
            status=ReviewStatus.UNAVAILABLE,
            error_code="server_unavailable",
            error_message="The local OpenVINO server was unavailable.",
        ),
    )

    def fake_audit(path: Path, **kwargs: object) -> AuditResult:
        received["path"] = path
        received.update(kwargs)
        return result

    monkeypatch.setattr("releaseguard.cli.audit_project", fake_audit)
    runner = CliRunner()
    response = runner.invoke(app, ["audit", str(tmp_path), "--ai", "--ai-timeout", "2"])

    assert response.exit_code == 0
    assert received["ai_timeout_seconds"] == 2.0
    assert "Local AI Review" in response.output
    assert "Local AI fallback" in response.output


def test_ai_status_uses_local_manager_data(monkeypatch) -> None:
    class Manager:
        def status(self) -> dict[str, object]:
            return {
                "ok": True,
                "state": "running",
                "model_id": "OpenVINO/test",
                "device": "GPU",
            }

    monkeypatch.setattr("releaseguard.ai.service.LocalServerManager", Manager)

    response = CliRunner().invoke(app, ["ai", "status"])

    assert response.exit_code == 0
    assert "AI Analyzer: OpenVINO" in response.output
    assert "Device: GPU" in response.output


def test_markdown_ai_success_shows_advisory_metadata() -> None:
    result = AuditResult(
        project_path="C:/demo",
        project_name="demo",
        release_score=100,
        release_gate=ReleaseGate.PASS,
        ai_review=AIReview(
            status=ReviewStatus.COMPLETED,
            model_id="OpenVINO/test",
            device="CPU",
            release_summary="No additional release blockers.",
            overall_confidence=0.8,
        ),
    )

    report = render_markdown(result)

    assert "AI Analyzer: OpenVINO" in report
    assert "Model: OpenVINO/test" in report
    assert "Local: Yes" in report
