from __future__ import annotations

from pathlib import Path

from releaseguard.ai.schemas import (
    AIReview,
    FindingAssessment,
    ReviewStatus,
    SemanticRisk,
)
from releaseguard.models import ReleaseGate, Severity
from releaseguard.scanner import audit_project


class SuccessfulLocalClient:
    def review(self, request: object, *, timeout_seconds: float) -> AIReview:
        del timeout_seconds
        finding = request.findings[0]  # type: ignore[attr-defined]
        return AIReview(
            status=ReviewStatus.COMPLETED,
            model_id="OpenVINO/test-local-model",
            device="CPU",
            finding_assessments=[
                FindingAssessment(
                    fingerprint=finding.fingerprint,
                    likely_true_positive=False,
                    confidence=0.99,
                    semantic_risk=SemanticRisk.LOW,
                    rationale="The model considers this context advisory only.",
                    remediation="Review the deployment configuration.",
                )
            ],
            release_summary="Local semantic review completed.",
            overall_confidence=0.9,
        )


class FailingLocalClient:
    def review(self, request: object, *, timeout_seconds: float) -> AIReview:
        del request, timeout_seconds
        raise TimeoutError("simulated local timeout")


def test_ai_review_is_additive_and_cannot_change_deterministic_gate(tmp_path: Path) -> None:
    (tmp_path / "production.py").write_text(
        'PRODUCTION_API_URL = "http://localhost:8080"\n', encoding="utf-8"
    )
    deterministic = audit_project(tmp_path)
    enhanced = audit_project(tmp_path, ai_client=SuccessfulLocalClient())

    assert deterministic.release_gate is ReleaseGate.BLOCKED
    assert enhanced.release_score == deterministic.release_score
    assert enhanced.release_gate == deterministic.release_gate
    assert [finding.model_dump() for finding in enhanced.findings] == [
        finding.model_dump() for finding in deterministic.findings
    ]
    assert enhanced.findings[0].severity is Severity.CRITICAL
    assert enhanced.ai_review is not None
    assert enhanced.ai_review.status is ReviewStatus.COMPLETED
    assert enhanced.ai_review.finding_assessments[0].likely_true_positive is False


def test_ai_failure_returns_the_deterministic_result_with_advisory_metadata(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'API_URL = "http://localhost:8080"\n', encoding="utf-8"
    )
    deterministic = audit_project(tmp_path)
    enhanced = audit_project(tmp_path, ai_client=FailingLocalClient())

    assert enhanced.release_score == deterministic.release_score
    assert enhanced.release_gate == deterministic.release_gate
    assert enhanced.findings == deterministic.findings
    assert enhanced.ai_review is not None
    assert enhanced.ai_review.status is ReviewStatus.ERROR
    assert enhanced.ai_review.error_code == "ai_review_unavailable"


def test_default_audit_result_keeps_the_phase_one_json_contract(tmp_path: Path) -> None:
    result = audit_project(tmp_path)

    assert "ai_review" not in result.to_dict()
