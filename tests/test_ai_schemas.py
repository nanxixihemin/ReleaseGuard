from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from releaseguard.ai.schemas import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIReview,
    FindingAssessment,
    FindingExcerpt,
    FindingPayload,
    ReviewStatus,
    SemanticRisk,
)


FINGERPRINT = "a" * 64


def _payload() -> FindingPayload:
    return FindingPayload(
        fingerprint=FINGERPRINT,
        rule_id="RG-TEST-001",
        title="Example finding",
        severity="high",
        category="test",
        file="src/config.py",
        line=3,
        evidence="redacted evidence",
        explanation="Explanation.",
        recommendation="Recommendation.",
        confidence=0.9,
        excerpt=FindingExcerpt(start_line=2, end_line=4, text="nearby line"),
    )


def test_request_schema_is_strict_and_bounded() -> None:
    request = AIAnalysisRequest(project_name="demo", findings=[_payload()])

    assert request.protocol_version == "1.0"
    assert request.findings[0].fingerprint == FINGERPRINT

    with pytest.raises(ValidationError):
        AIAnalysisRequest(project_name="demo", findings=[], unexpected="field")
    with pytest.raises(ValidationError):
        FindingPayload(
            fingerprint="not-a-sha256",
            rule_id="RG-TEST-001",
            title="Example finding",
            severity="urgent",
            category="test",
            file="src/config.py",
            confidence=0.9,
        )


def test_excerpt_rejects_inverted_line_ranges() -> None:
    with pytest.raises(ValidationError, match="end_line"):
        FindingExcerpt(start_line=5, end_line=4, text="bad range")


def test_response_schema_accepts_only_protocol_json_shape() -> None:
    response = AIAnalysisResponse.model_validate_json(
        json.dumps(
            {
                "protocol_version": "1.0",
                "model_id": "local-openvino-test",
                "device": "CPU",
                "finding_assessments": [
                    {
                        "fingerprint": FINGERPRINT,
                        "likely_true_positive": True,
                        "confidence": 0.8,
                        "semantic_risk": "high",
                        "rationale": "The configuration is production relevant.",
                    }
                ],
                "release_summary": "Review complete.",
                "overall_confidence": 0.8,
            }
        )
    )

    assert response.finding_assessments[0].semantic_risk is SemanticRisk.HIGH
    assert response.device == "CPU"

    with pytest.raises(ValidationError):
        AIAnalysisResponse.model_validate_json(
            json.dumps(
                {
                    "protocol_version": "1.0",
                    "model_id": "local",
                    "finding_assessments": [],
                    "release_summary": "",
                    "overall_confidence": 0.8,
                    "extra": True,
                }
            )
        )


def test_review_failure_has_no_untrusted_analysis_payload() -> None:
    review = AIReview.failure(
        ReviewStatus.INVALID_RESPONSE,
        error_code="invalid_schema",
        error_message="AI analyzer returned an invalid response schema.",
    )

    assert review.is_successful is False
    assert review.finding_assessments == []
    assert review.error_code == "invalid_schema"

    with pytest.raises(ValueError):
        AIReview.failure(
            ReviewStatus.COMPLETED,
            error_code="not_allowed",
            error_message="Nope",
        )


def test_finding_assessment_requires_valid_semantic_risk() -> None:
    with pytest.raises(ValidationError):
        FindingAssessment(
            fingerprint=FINGERPRINT,
            likely_true_positive=True,
            confidence=0.9,
            semantic_risk="approve",  # type: ignore[arg-type]
        )
