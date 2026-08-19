"""Build bounded, redacted AI requests from existing read-only audit state."""

from __future__ import annotations

from collections.abc import Sequence

from ..context import ProjectContext
from ..models import Finding
from .redaction import redact_and_truncate
from .schemas import (
    AIAnalysisRequest,
    FindingExcerpt,
    FindingPayload,
    MAX_EXCERPT_LENGTH,
    MAX_FINDINGS_PER_REQUEST,
    MAX_PROJECT_TYPES,
    MAX_TEXT_FIELD_LENGTH,
)


DEFAULT_CONTEXT_LINES = 2
MAX_CONTEXT_LINES = 8
MAX_PROJECT_NAME_LENGTH = 256
MAX_PROJECT_TYPE_LENGTH = 64


def build_finding_excerpt(
    context: ProjectContext,
    finding: Finding,
    *,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_excerpt_chars: int = MAX_EXCERPT_LENGTH,
) -> FindingExcerpt | None:
    """Return only the redacted lines adjacent to a finding's source location.

    Files are accessed solely through :meth:`ProjectContext.iter_text_lines`, so
    the context remains responsible for root containment, symlink checks, binary
    checks, and file-size limits. A finding without a line number deliberately
    receives no excerpt instead of an arbitrary beginning-of-file sample.
    """

    _validate_excerpt_limits(context_lines, max_excerpt_chars)
    if finding.line is None:
        return None

    start_line = max(1, finding.line - context_lines)
    end_line = finding.line + context_lines
    nearby_lines: list[tuple[int, str]] = []

    try:
        for line_number, line in context.iter_text_lines(finding.file):
            if line_number < start_line:
                continue
            if line_number > end_line:
                break
            nearby_lines.append((line_number, line))
    except (OSError, UnicodeError, ValueError):
        return None

    if not nearby_lines:
        return None

    # Redact each source line before joining and bounding the complete excerpt.
    # The persisted text is the only source-derived content sent to the analyzer.
    text = "\n".join(
        redact_and_truncate(line, max_length=max_excerpt_chars)
        for _, line in nearby_lines
    )
    text = redact_and_truncate(text, max_length=max_excerpt_chars)
    return FindingExcerpt(
        start_line=nearby_lines[0][0],
        end_line=nearby_lines[-1][0],
        text=text,
    )


def build_finding_payload(
    context: ProjectContext,
    finding: Finding,
    *,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_excerpt_chars: int = MAX_EXCERPT_LENGTH,
) -> FindingPayload:
    """Convert a finding to its bounded local-AI payload representation."""

    return FindingPayload(
        fingerprint=finding.fingerprint,
        rule_id=redact_and_truncate(finding.rule_id, max_length=128),
        title=redact_and_truncate(finding.title, max_length=512),
        severity=finding.severity.value,
        category=redact_and_truncate(finding.category, max_length=128),
        file=redact_and_truncate(finding.file, max_length=512),
        line=finding.line,
        evidence=redact_and_truncate(finding.evidence, max_length=MAX_TEXT_FIELD_LENGTH),
        explanation=redact_and_truncate(
            finding.explanation,
            max_length=MAX_TEXT_FIELD_LENGTH,
        ),
        recommendation=redact_and_truncate(
            finding.recommendation,
            max_length=MAX_TEXT_FIELD_LENGTH,
        ),
        confidence=finding.confidence,
        excerpt=build_finding_excerpt(
            context,
            finding,
            context_lines=context_lines,
            max_excerpt_chars=max_excerpt_chars,
        ),
    )


def build_analysis_request(
    context: ProjectContext,
    findings: Sequence[Finding],
    *,
    max_findings: int = MAX_FINDINGS_PER_REQUEST,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_excerpt_chars: int = MAX_EXCERPT_LENGTH,
) -> AIAnalysisRequest:
    """Build a deterministic, redacted request without reading project-wide text."""

    if not 1 <= max_findings <= MAX_FINDINGS_PER_REQUEST:
        raise ValueError(f"max_findings must be between 1 and {MAX_FINDINGS_PER_REQUEST}")
    _validate_excerpt_limits(context_lines, max_excerpt_chars)

    project_types = [
        redact_and_truncate(str(project_type), max_length=MAX_PROJECT_TYPE_LENGTH)
        for project_type in context.project_types[:MAX_PROJECT_TYPES]
    ]
    return AIAnalysisRequest(
        project_name=redact_and_truncate(
            context.project_name,
            max_length=MAX_PROJECT_NAME_LENGTH,
        ),
        project_types=project_types,
        findings=[
            build_finding_payload(
                context,
                finding,
                context_lines=context_lines,
                max_excerpt_chars=max_excerpt_chars,
            )
            for finding in findings[:max_findings]
        ],
    )


def _validate_excerpt_limits(context_lines: int, max_excerpt_chars: int) -> None:
    if not 0 <= context_lines <= MAX_CONTEXT_LINES:
        raise ValueError(f"context_lines must be between 0 and {MAX_CONTEXT_LINES}")
    if not 16 <= max_excerpt_chars <= MAX_EXCERPT_LENGTH:
        raise ValueError(f"max_excerpt_chars must be between 16 and {MAX_EXCERPT_LENGTH}")


# Clear aliases for later adapters and external integrations.
build_ai_request = build_analysis_request
extract_local_excerpt = build_finding_excerpt


__all__ = [
    "DEFAULT_CONTEXT_LINES",
    "MAX_CONTEXT_LINES",
    "build_ai_request",
    "build_analysis_request",
    "build_finding_excerpt",
    "build_finding_payload",
    "extract_local_excerpt",
]

