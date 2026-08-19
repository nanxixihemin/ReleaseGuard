from __future__ import annotations

import json

from releaseguard.ai.redaction import REDACTED_TOKEN, REDACTED_URL
from releaseguard.ai.response_parser import parse_analysis_response
from releaseguard.ai.schemas import ReviewStatus, SemanticRisk


FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64


def _valid_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "protocol_version": "1.0",
        "model_id": "local-openvino-model",
        "device": "CPU",
        "finding_assessments": [
            {
                "fingerprint": FINGERPRINT,
                "likely_true_positive": True,
                "confidence": 0.9,
                "semantic_risk": "high",
                "rationale": "The finding is relevant.",
            }
        ],
        "release_summary": "Review complete.",
        "overall_confidence": 0.9,
    }
    payload.update(overrides)
    return payload


def test_parser_returns_completed_review_for_known_fingerprint() -> None:
    review = parse_analysis_response(_valid_payload(), [FINGERPRINT])

    assert review.status is ReviewStatus.COMPLETED
    assert review.is_successful is True
    assert review.finding_assessments[0].semantic_risk is SemanticRisk.HIGH
    assert review.device == "CPU"
    assert review.error_code is None


def test_parser_rejects_unknown_or_duplicate_fingerprints_without_throwing() -> None:
    unknown = parse_analysis_response(
        _valid_payload(
            finding_assessments=[
                {
                    "fingerprint": OTHER_FINGERPRINT,
                    "likely_true_positive": True,
                    "confidence": 0.9,
                    "semantic_risk": "high",
                }
            ]
        ),
        [FINGERPRINT],
    )
    duplicate = parse_analysis_response(
        _valid_payload(
            finding_assessments=[
                {
                    "fingerprint": FINGERPRINT,
                    "likely_true_positive": True,
                    "confidence": 0.9,
                    "semantic_risk": "high",
                },
                {
                    "fingerprint": FINGERPRINT,
                    "likely_true_positive": False,
                    "confidence": 0.5,
                    "semantic_risk": "unknown",
                },
            ]
        ),
        [FINGERPRINT],
    )

    assert (unknown.status, unknown.error_code, unknown.finding_assessments) == (
        ReviewStatus.INVALID_RESPONSE,
        "unknown_fingerprint",
        [],
    )
    assert (duplicate.status, duplicate.error_code, duplicate.finding_assessments) == (
        ReviewStatus.INVALID_RESPONSE,
        "duplicate_fingerprint",
        [],
    )


def test_parser_safely_handles_invalid_or_sensitive_response_payloads() -> None:
    malformed = parse_analysis_response("{not json", [FINGERPRINT])
    secret = "sk-test-only-fixture-1234567890"
    response = parse_analysis_response(
        _valid_payload(
            finding_assessments=[
                {
                    "fingerprint": FINGERPRINT,
                    "likely_true_positive": True,
                    "confidence": 0.9,
                    "semantic_risk": "high",
                    "rationale": f"Use {secret} at https://alice:password@example.test/?token=x",
                }
            ],
            release_summary=f"Raw {secret}",
        ),
        [FINGERPRINT],
    )

    assert malformed.status is ReviewStatus.INVALID_RESPONSE
    assert malformed.error_code == "invalid_json"
    assert "not json" not in (malformed.error_message or "")
    assert secret not in response.finding_assessments[0].rationale
    assert REDACTED_TOKEN in response.finding_assessments[0].rationale
    assert REDACTED_URL in response.finding_assessments[0].rationale
    assert secret not in response.release_summary


def test_parser_rejects_schema_extra_fields() -> None:
    payload = _valid_payload()
    payload["unexpected"] = True

    review = parse_analysis_response(json.dumps(payload), [FINGERPRINT])

    assert review.status is ReviewStatus.INVALID_RESPONSE
    assert review.error_code == "invalid_schema"


def test_parser_extracts_json_from_model_markdown_and_uses_runtime_identity() -> None:
    payload = """```json
    {"finding_assessments": [], "release_summary": "ok", "overall_confidence": 0.8}
    ```"""

    review = parse_analysis_response(
        payload,
        [FINGERPRINT],
        runtime_model_id="OpenVINO/runtime",
        runtime_device="GPU",
    )

    assert review.status is ReviewStatus.COMPLETED
    assert review.model_id == "OpenVINO/runtime"
    assert review.device == "GPU"
