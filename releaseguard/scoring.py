"""Central release-readiness scoring and gate policy."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from .models import Finding, ReleaseGate, Severity


BASE_SCORE = 100
PASS_THRESHOLD = 85
WARNING_THRESHOLD = 60
SEVERITY_PENALTIES = MappingProxyType(
    {
        Severity.CRITICAL: 25,
        Severity.HIGH: 12,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
    }
)


def _severity_of(finding: Finding | Severity | str) -> Severity:
    if isinstance(finding, Finding):
        return finding.severity
    if isinstance(finding, Severity):
        return finding
    return Severity(finding.lower())


def calculate_release_score(findings: Iterable[Finding | Severity | str]) -> int:
    """Score findings from 100 using the documented per-severity penalties."""

    score = BASE_SCORE
    for finding in findings:
        score -= SEVERITY_PENALTIES[_severity_of(finding)]
    return max(0, min(BASE_SCORE, score))


def determine_release_gate(
    score: int | float,
    findings: Iterable[Finding | Severity | str] = (),
) -> ReleaseGate:
    """Apply the policy gate, with any critical finding taking precedence."""

    severities = (_severity_of(finding) for finding in findings)
    if any(severity is Severity.CRITICAL for severity in severities):
        return ReleaseGate.BLOCKED
    if score < WARNING_THRESHOLD:
        return ReleaseGate.BLOCKED
    if score < PASS_THRESHOLD:
        return ReleaseGate.WARNING
    return ReleaseGate.PASS


def score_and_gate(findings: Iterable[Finding | Severity | str]) -> tuple[int, ReleaseGate]:
    """Evaluate an iterable once and return its score and release gate."""

    finding_list = list(findings)
    score = calculate_release_score(finding_list)
    return score, determine_release_gate(score, finding_list)


# Short aliases keep scanner code readable while preserving one policy source.
calculate_score = calculate_release_score
calculate_gate = determine_release_gate


__all__ = [
    "BASE_SCORE",
    "PASS_THRESHOLD",
    "SEVERITY_PENALTIES",
    "WARNING_THRESHOLD",
    "calculate_gate",
    "calculate_release_score",
    "calculate_score",
    "determine_release_gate",
    "score_and_gate",
]

