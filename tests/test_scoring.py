from __future__ import annotations

from releaseguard.models import Finding, ReleaseGate, Severity
from releaseguard.scoring import calculate_release_score, determine_release_gate, score_and_gate


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id=f"RG-{severity.value.upper()}-001",
        title="Example finding",
        severity=severity,
        category="test",
        file="example.txt",
        evidence=severity.value,
        explanation="Example explanation.",
        recommendation="Example recommendation.",
    )


def test_score_applies_documented_penalties() -> None:
    score = calculate_release_score(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    )

    assert score == 57


def test_score_is_clamped_to_zero() -> None:
    assert calculate_release_score([Severity.CRITICAL] * 10) == 0


def test_gate_policy_handles_pass_warning_and_blocked() -> None:
    pass_score, pass_gate = score_and_gate([])
    warning_score, warning_gate = score_and_gate([Severity.HIGH, Severity.MEDIUM, Severity.LOW])
    critical_score, critical_gate = score_and_gate([_finding(Severity.CRITICAL)])
    low_score, low_gate = score_and_gate([Severity.HIGH] * 4)

    assert (pass_score, pass_gate) == (100, ReleaseGate.PASS)
    assert (warning_score, warning_gate) == (82, ReleaseGate.WARNING)
    assert (critical_score, critical_gate) == (75, ReleaseGate.BLOCKED)
    assert (low_score, low_gate) == (52, ReleaseGate.BLOCKED)


def test_critical_finding_blocks_even_when_score_is_high() -> None:
    assert determine_release_gate(100, [Severity.CRITICAL]) is ReleaseGate.BLOCKED

