from __future__ import annotations

from datetime import datetime
import json

import pytest
from pydantic import ValidationError

from releaseguard.models import AuditResult, AuditSummary, Finding, ReleaseGate, Severity


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": "RG-TEST-001",
        "title": "Example finding",
        "severity": Severity.HIGH,
        "category": "test",
        "file": "src/config.py",
        "line": 12,
        "evidence": "API_URL=http://localhost:8000",
        "explanation": "Example explanation.",
        "recommendation": "Example recommendation.",
    }
    values.update(overrides)
    return Finding(**values)


def test_finding_fingerprint_is_stable_and_sensitive_to_evidence() -> None:
    first = _finding()
    same = _finding()
    changed = _finding(evidence="API_URL=https://api.example.com")

    assert first.fingerprint == same.fingerprint
    assert first.fingerprint == first.calculate_fingerprint()
    assert first.fingerprint != changed.fingerprint
    assert len(first.fingerprint) == 64
    assert int(first.fingerprint, 16) >= 0


def test_finding_serializes_string_enum_values_and_normalizes_paths() -> None:
    finding = _finding(severity="HIGH", file=r"src\config.py")

    payload = finding.model_dump(mode="json")

    assert finding.severity is Severity.HIGH
    assert payload["severity"] == "high"
    assert finding.file == "src/config.py"


def test_summary_counts_findings_and_accepts_count_aliases() -> None:
    findings = [
        _finding(severity=Severity.CRITICAL),
        _finding(rule_id="RG-TEST-002", severity=Severity.LOW),
    ]

    summary = AuditSummary.from_findings(
        findings,
        files_scanned=8,
        files_skipped=2,
        duration_seconds=0.25,
        rules_executed=3,
    )
    alias_summary = AuditSummary(critical_count=2, high_count=1)

    assert summary.counts == {"critical": 1, "high": 0, "medium": 0, "low": 1}
    assert summary.total_findings == 2
    assert summary.files_scanned == 8
    assert alias_summary.critical == 2
    assert alias_summary.high == 1


def test_audit_result_serializes_uppercase_gate_and_aware_timestamp() -> None:
    result = AuditResult(
        project_path="C:/projects/demo",
        project_name="demo",
        release_score=88,
        release_gate="pass",
        project_types=("python",),
    )

    payload = json.loads(result.to_json())

    assert result.timestamp.tzinfo is not None
    assert payload["release_gate"] == "PASS"
    assert payload["project_types"] == ["python"]
    assert result.release_gate is ReleaseGate.PASS


def test_audit_result_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuditResult(
            project_path=".",
            project_name="demo",
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            release_score=100,
            release_gate=ReleaseGate.PASS,
        )

