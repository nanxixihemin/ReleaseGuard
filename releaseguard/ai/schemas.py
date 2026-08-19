"""Bounded, strict wire contracts for the optional local AI reviewer."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


AI_PROTOCOL_VERSION = "1.0"
MAX_FINDINGS_PER_REQUEST = 64
MAX_PROJECT_TYPES = 16
MAX_TEXT_FIELD_LENGTH = 1_600
MAX_EXCERPT_LENGTH = 2_000
MAX_SUMMARY_LENGTH = 2_000
FINGERPRINT_PATTERN = r"^[0-9a-f]{64}$"


class ReviewDisposition(str, Enum):
    """Advisory conclusions that never overwrite deterministic findings."""

    CONFIRMED = "confirmed"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    CONTEXTUAL_RISK = "contextual_risk"


class ReviewStatus(str, Enum):
    """Safe outcomes of an optional local AI review."""

    COMPLETED = "completed"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    ERROR = "error"


class SemanticRisk(str, Enum):
    """Model-estimated semantic risk, kept separate from rule severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class _StrictSchema(BaseModel):
    """Reject extra fields and coercion at the local AI protocol boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class FindingExcerpt(_StrictSchema):
    """A redacted, bounded group of lines surrounding one finding location."""

    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str = Field(min_length=1, max_length=MAX_EXCERPT_LENGTH)

    @model_validator(mode="after")
    def _validate_line_range(self) -> "FindingExcerpt":
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class FindingPayload(_StrictSchema):
    """The bounded, redacted portion of a deterministic finding sent to AI."""

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    rule_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    severity: Literal["critical", "high", "medium", "low"]
    category: str = Field(min_length=1, max_length=128)
    file: str = Field(min_length=1, max_length=512)
    line: int | None = Field(default=None, ge=1)
    evidence: str = Field(default="", max_length=MAX_TEXT_FIELD_LENGTH)
    explanation: str = Field(default="", max_length=MAX_TEXT_FIELD_LENGTH)
    recommendation: str = Field(default="", max_length=MAX_TEXT_FIELD_LENGTH)
    confidence: float = Field(ge=0.0, le=1.0)
    excerpt: FindingExcerpt | None = None


class AIAnalysisRequest(_StrictSchema):
    """A model-ready request that contains no project-wide source payload."""

    protocol_version: Literal[AI_PROTOCOL_VERSION] = AI_PROTOCOL_VERSION
    project_name: str = Field(min_length=1, max_length=256)
    project_types: list[str] = Field(default_factory=list, max_length=MAX_PROJECT_TYPES)
    findings: list[FindingPayload] = Field(
        default_factory=list,
        max_length=MAX_FINDINGS_PER_REQUEST,
    )


class FindingAssessment(_StrictSchema):
    """One advisory model assessment associated with a known finding fingerprint."""

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    likely_true_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    semantic_risk: SemanticRisk
    rationale: str = Field(default="", max_length=MAX_TEXT_FIELD_LENGTH)
    remediation: str | None = Field(default=None, max_length=MAX_TEXT_FIELD_LENGTH)


class AIAnalysisResponse(_StrictSchema):
    """The strict successful response shape expected from a local analyzer."""

    protocol_version: Literal[AI_PROTOCOL_VERSION] = AI_PROTOCOL_VERSION
    model_id: str = Field(min_length=1, max_length=256)
    device: str | None = Field(default=None, max_length=128)
    finding_assessments: list[FindingAssessment] = Field(
        default_factory=list,
        max_length=MAX_FINDINGS_PER_REQUEST,
    )
    release_summary: str = Field(default="", max_length=MAX_SUMMARY_LENGTH)
    overall_confidence: float = Field(ge=0.0, le=1.0)


class AIReview(_StrictSchema):
    """A safe result for callers, including graceful analyzer failure states."""

    status: ReviewStatus
    model_id: str | None = Field(default=None, max_length=256)
    device: str | None = Field(default=None, max_length=128)
    local: bool = True
    finding_assessments: list[FindingAssessment] = Field(
        default_factory=list,
        max_length=MAX_FINDINGS_PER_REQUEST,
    )
    release_summary: str = Field(default="", max_length=MAX_SUMMARY_LENGTH)
    overall_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=256)

    @property
    def is_successful(self) -> bool:
        return self.status is ReviewStatus.COMPLETED

    @classmethod
    def failure(
        cls,
        status: ReviewStatus,
        *,
        error_code: str,
        error_message: str,
    ) -> "AIReview":
        """Build a bounded error result without carrying an untrusted payload."""

        if status is ReviewStatus.COMPLETED:
            raise ValueError("A completed review cannot be constructed as a failure")
        return cls(
            status=status,
            error_code=error_code,
            error_message=error_message,
        )


# Short aliases make the protocol ergonomic without coupling it to scanner models.
AnalysisRequest = AIAnalysisRequest
AnalysisResponse = AIAnalysisResponse
FindingAnalysis = FindingAssessment
Analysis = FindingAssessment
Review = AIReview


__all__ = [
    "AI_PROTOCOL_VERSION",
    "AIAnalysisRequest",
    "AIAnalysisResponse",
    "AIReview",
    "Analysis",
    "AnalysisRequest",
    "AnalysisResponse",
    "FINGERPRINT_PATTERN",
    "FindingAnalysis",
    "FindingAssessment",
    "FindingExcerpt",
    "FindingPayload",
    "MAX_EXCERPT_LENGTH",
    "MAX_FINDINGS_PER_REQUEST",
    "MAX_PROJECT_TYPES",
    "MAX_SUMMARY_LENGTH",
    "MAX_TEXT_FIELD_LENGTH",
    "Review",
    "ReviewDisposition",
    "ReviewStatus",
    "SemanticRisk",
]
