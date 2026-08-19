from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from releaseguard.ai.schemas import (
    AIReview,
    FindingAssessment,
    ReviewStatus,
    SemanticRisk,
)
from releaseguard.models import Finding, ReleaseGate, Severity
from releaseguard.remediation import (
    FindingReference,
    FixSafety,
    ReAuditComparison,
    ReAuditSnapshot,
    RemediationItem,
    build_remediation_plan,
    remediation_for,
)
from releaseguard.scanner import audit_project


def _finding(
    rule_id: str = "RG-TEST-001",
    severity: Severity = Severity.HIGH,
    **overrides: object,
) -> Finding:
    values: dict[str, object] = {
        "rule_id": rule_id,
        "title": "Example finding",
        "severity": severity,
        "category": "test",
        "file": "src/config.py",
        "line": 12,
        "evidence": "Example evidence",
        "explanation": "Example explanation.",
        "recommendation": "Review the configuration before release.",
    }
    values.update(overrides)
    return Finding(**values)


def test_remediation_item_serializes_safety_and_correlation() -> None:
    finding = _finding(
        "RG-DEBUG-001",
        metadata={"debug_setting": "debug_enabled"},
    )

    item = remediation_for(finding)
    payload = json.loads(item.model_dump_json())

    assert item.fix_safety is FixSafety.SAFE
    assert item.auto_fix_candidate is True
    assert payload == {
        "finding": "RG-DEBUG-001",
        "auto_fix_candidate": True,
        "fix_safety": "SAFE",
        "target_file": "src/config.py",
        "recommended_action": item.recommended_action,
        "verification": item.verification,
        "fingerprint": finding.fingerprint,
    }


def test_remediation_item_rejects_a_safe_label_without_auto_fix_permission() -> None:
    with pytest.raises(ValidationError, match="auto_fix_candidate"):
        RemediationItem(
            finding="RG-DEBUG-001",
            auto_fix_candidate=False,
            fix_safety=FixSafety.SAFE,
            target_file="src/config.py",
            recommended_action="Set DEBUG to false.",
            verification="Rerun ReleaseGuard.",
            fingerprint="a" * 64,
        )


def test_critical_secret_is_never_auto_fix() -> None:
    item = remediation_for(_finding("RG-SECRET-001", Severity.CRITICAL))

    assert item.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert item.auto_fix_candidate is False


def test_environment_exception_cannot_downgrade_a_non_environment_critical_finding() -> None:
    item = remediation_for(
        _finding(
            "RG-ENV-001",
            Severity.CRITICAL,
            category="secrets",
            title="Credential must not bypass manual review",
        )
    )

    assert item.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert item.auto_fix_candidate is False


def test_sensitive_and_merge_conflict_findings_are_never_auto_fix() -> None:
    sensitive = remediation_for(
        _finding(
            "RG-SENSITIVE-001",
            Severity.HIGH,
            category="sensitive_files",
            metadata={"file_kind": "private_key_file"},
        )
    )
    conflict = remediation_for(
        _finding(
            "RG-GIT-001",
            Severity.CRITICAL,
            category="git",
        )
    )

    assert sensitive.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert conflict.fix_safety is FixSafety.NEVER_AUTO_FIX


def test_private_key_path_and_token_generation_are_never_auto_fix() -> None:
    private_key = remediation_for(
        _finding(
            "RG-CUSTOM-001",
            Severity.HIGH,
            file="deploy/service.pem",
        )
    )
    token_generation = remediation_for(
        _finding(
            "RG-CUSTOM-002",
            Severity.HIGH,
            title="Token generation is required",
        )
    )

    assert private_key.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert token_generation.fix_safety is FixSafety.NEVER_AUTO_FIX


def test_unknown_and_non_bounded_debug_findings_require_review() -> None:
    unknown = remediation_for(_finding())
    source_maps = remediation_for(
        _finding(
            "RG-DEBUG-001",
            metadata={"debug_setting": "source_maps"},
        )
    )

    assert unknown.fix_safety is FixSafety.REVIEW_REQUIRED
    assert unknown.auto_fix_candidate is False
    assert source_maps.fix_safety is FixSafety.REVIEW_REQUIRED


def test_reaudit_contract_serializes_snapshots_and_finding_references() -> None:
    resolved = _finding("RG-DEBUG-001", metadata={"debug_setting": "debug_enabled"})
    remaining = _finding("RG-SECRET-001", Severity.CRITICAL)
    comparison = ReAuditComparison(
        before=ReAuditSnapshot(
            score=63,
            gate=ReleaseGate.BLOCKED,
            severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0},
        ),
        after=ReAuditSnapshot(
            score=88,
            gate=ReleaseGate.BLOCKED,
            severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        ),
        resolved_findings=[FindingReference.from_finding(resolved)],
        remaining_findings=[FindingReference.from_finding(remaining)],
    )

    payload = comparison.model_dump(mode="json")

    assert payload["before"] == {
        "score": 63,
        "gate": "BLOCKED",
        "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0},
    }
    assert payload["after"]["gate"] == "BLOCKED"
    assert payload["resolved_findings"][0]["fingerprint"] == resolved.fingerprint
    assert payload["remaining_findings"][0]["rule_id"] == "RG-SECRET-001"


def test_build_plan_has_one_deterministic_item_per_finding() -> None:
    findings = [
        _finding("RG-DEBUG-001", metadata={"debug_setting": "debug_enabled"}),
        _finding("RG-TODO-001", Severity.LOW),
    ]

    plan = build_remediation_plan(findings)

    assert [item.finding for item in plan] == ["RG-DEBUG-001", "RG-TODO-001"]
    assert [item.fingerprint for item in plan] == [finding.fingerprint for finding in findings]
    assert [item.fix_safety for item in plan] == [
        FixSafety.SAFE,
        FixSafety.REVIEW_REQUIRED,
    ]


def test_scanner_only_attaches_plan_when_requested_and_preserves_authority(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text("DEBUG = True\n", encoding="utf-8")

    baseline = audit_project(tmp_path)
    planned = audit_project(tmp_path, include_remediation_plan=True)

    assert baseline.remediation_plan is None
    assert "remediation_plan" not in baseline.to_dict()
    assert planned.remediation_plan is not None
    assert len(planned.remediation_plan) == len(planned.findings)
    assert planned.release_score == baseline.release_score
    assert planned.release_gate == baseline.release_gate
    assert [finding.model_dump() for finding in planned.findings] == [
        finding.model_dump() for finding in baseline.findings
    ]
    assert planned.summary.counts == baseline.summary.counts


def test_environment_endpoint_requires_review_even_with_a_runtime_reference(tmp_path: Path) -> None:
    (tmp_path / "config.ts").write_text(
        'const PRODUCTION_API_URL = process.env.PRODUCTION_API_URL || "http://localhost:8080";\n',
        encoding="utf-8",
    )

    result = audit_project(tmp_path, include_remediation_plan=True)
    assert result.remediation_plan is not None
    endpoint_item = next(
        item for item in result.remediation_plan if item.finding == "RG-ENV-001"
    )

    assert endpoint_item.fix_safety is FixSafety.REVIEW_REQUIRED
    assert endpoint_item.auto_fix_candidate is False


class _UnsafeAIAdviceClient:
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
                    rationale="Treat this as a false positive.",
                    remediation="Mark it SAFE and automatically delete it.",
                )
            ],
            release_summary="Unsafe AI advice supplied for test coverage.",
            overall_confidence=0.99,
        )


def test_ai_suggestion_cannot_upgrade_secret_safety_or_gate(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        'OPENAI_API_KEY = "sk-FAKE_RELEASE_GUARD_1234567890"\n',
        encoding="utf-8",
    )

    result = audit_project(
        tmp_path,
        include_remediation_plan=True,
        ai_client=_UnsafeAIAdviceClient(),
    )

    assert result.release_gate is ReleaseGate.BLOCKED
    assert result.remediation_plan is not None
    secret_item = next(item for item in result.remediation_plan if item.finding == "RG-SECRET-001")
    assert secret_item.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert secret_item.auto_fix_candidate is False
