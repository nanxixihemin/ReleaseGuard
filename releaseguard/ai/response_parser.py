"""Validate untrusted local-AI responses into safe, bounded review results."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from typing import Any

from pydantic import ValidationError

from .redaction import redact_and_truncate
from .schemas import (
    AIAnalysisResponse,
    AIReview,
    FindingAssessment,
    MAX_SUMMARY_LENGTH,
    MAX_TEXT_FIELD_LENGTH,
    ReviewStatus,
)


MAX_RESPONSE_BYTES = 262_144


def parse_analysis_response(
    payload: str | bytes | bytearray | Mapping[str, Any],
    known_fingerprints: Iterable[str],
    *,
    runtime_model_id: str | None = None,
    runtime_device: str | None = None,
) -> AIReview:
    """Parse an analyzer response without exposing bad payloads or raising errors.

    Only analyses tied to the deterministic finding fingerprints supplied by the
    caller can be returned. Malformed, oversized, schema-invalid, duplicate, or
    unknown-fingerprint responses become an ``INVALID_RESPONSE`` review with a
    generic message; neither raw model output nor exceptions are surfaced.
    """

    encoded = _encode_payload(payload)
    if encoded is None:
        return _invalid_review("unsupported_payload", "AI analyzer returned an unsupported response.")
    if len(encoded) > MAX_RESPONSE_BYTES:
        return _invalid_review("response_too_large", "AI analyzer response exceeded the size limit.")

    known = _known_fingerprint_set(known_fingerprints)
    if known is None:
        return _invalid_review("invalid_known_fingerprints", "AI review could not validate finding identities.")

    candidate = _extract_json_object(encoded)
    if candidate is None:
        return _invalid_review("invalid_json", "AI analyzer returned invalid JSON.")
    if runtime_model_id is not None:
        candidate["model_id"] = runtime_model_id
    if runtime_device is not None:
        candidate["device"] = runtime_device
    try:
        # JSON validation deliberately keeps the strict schema while accepting
        # JSON string representations of enum values from the local model.
        response = AIAnalysisResponse.model_validate_json(
            json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))
        )
    except (ValidationError, ValueError, TypeError, UnicodeError):
        return _invalid_review("invalid_schema", "AI analyzer returned an invalid response schema.")

    fingerprints = [assessment.fingerprint for assessment in response.finding_assessments]
    if len(set(fingerprints)) != len(fingerprints):
        return _invalid_review("duplicate_fingerprint", "AI analyzer reviewed a finding more than once.")
    if any(fingerprint not in known for fingerprint in fingerprints):
        return _invalid_review("unknown_fingerprint", "AI analyzer referenced an unknown finding.")

    return AIReview(
        status=ReviewStatus.COMPLETED,
        model_id=redact_and_truncate(response.model_id, max_length=256),
        device=(
            redact_and_truncate(response.device, max_length=128)
            if response.device is not None
            else None
        ),
        finding_assessments=[
            _safe_assessment(assessment)
            for assessment in response.finding_assessments
        ],
        release_summary=redact_and_truncate(
            response.release_summary,
            max_length=MAX_SUMMARY_LENGTH,
        ),
        overall_confidence=response.overall_confidence,
    )


def _encode_payload(payload: str | bytes | bytearray | Mapping[str, Any]) -> bytes | None:
    try:
        if isinstance(payload, str):
            return payload.encode("utf-8")
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        if isinstance(payload, Mapping):
            return json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
    except Exception:
        return None
    return None


def _extract_json_object(encoded: bytes) -> dict[str, Any] | None:
    """Find one JSON object in model text, then validate it strictly upstream."""

    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _known_fingerprint_set(fingerprints: Iterable[str]) -> set[str] | None:
    try:
        return {str(fingerprint) for fingerprint in fingerprints}
    except Exception:  # A foreign iterable should never make parser callers fail.
        return None


def _safe_assessment(assessment: FindingAssessment) -> FindingAssessment:
    """Redact model-generated prose before returning it to callers or reports."""

    remediation = assessment.remediation
    return FindingAssessment(
        fingerprint=assessment.fingerprint,
        likely_true_positive=assessment.likely_true_positive,
        confidence=assessment.confidence,
        semantic_risk=assessment.semantic_risk,
        rationale=redact_and_truncate(
            assessment.rationale,
            max_length=MAX_TEXT_FIELD_LENGTH,
        ),
        remediation=(
            redact_and_truncate(remediation, max_length=MAX_TEXT_FIELD_LENGTH)
            if remediation is not None
            else None
        ),
    )


def _invalid_review(error_code: str, error_message: str) -> AIReview:
    return AIReview.failure(
        ReviewStatus.INVALID_RESPONSE,
        error_code=error_code,
        error_message=error_message,
    )


# A concise alias for adapters that call this after receiving HTTP JSON.
parse_ai_response = parse_analysis_response


__all__ = ["MAX_RESPONSE_BYTES", "parse_ai_response", "parse_analysis_response"]
