"""Audit orchestration for the deterministic ReleaseGuard Phase 1 scanner."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Protocol

from .context import ProjectContext
from .models import AuditResult, AuditSummary, Finding, GitSnapshot, Severity
from .remediation import build_remediation_plan
from .scoring import score_and_gate
from .rules.base import AuditRule

if TYPE_CHECKING:
    from .ai.schemas import AIAnalysisRequest, AIReview


class AIReviewClient(Protocol):
    """Optional local-AI boundary used only after deterministic scanning."""

    def review(
        self,
        request: "AIAnalysisRequest",
        *,
        timeout_seconds: float,
    ) -> "AIReview": ...


SCANNER_VERSION = "0.2.0"


def default_rules() -> list[AuditRule]:
    """Create the standard Phase 1 rule set without global mutable state."""

    from .rules.artifacts import UnwantedArtifactRule
    from .rules.debug import DebugConfigurationRule
    from .rules.environment import DevelopmentEndpointRule
    from .rules.git import GitStateRule
    from .rules.release_config import ReleaseConfigurationRule
    from .rules.secrets import SecretCredentialRule
    from .rules.sensitive_files import SensitiveFileRule
    from .rules.todos import TodoMarkerRule

    return [
        SecretCredentialRule(),
        DevelopmentEndpointRule(),
        DebugConfigurationRule(),
        TodoMarkerRule(),
        GitStateRule(),
        SensitiveFileRule(),
        UnwantedArtifactRule(),
        ReleaseConfigurationRule(),
    ]


def _rule_failure_finding(rule: AuditRule, error: Exception) -> Finding:
    """Make an unexpected rule failure visible without leaking inspected content."""

    return Finding(
        rule_id="RG-SCAN-001",
        title="Audit rule could not complete",
        severity=Severity.LOW,
        category="scanner",
        file=".",
        line=None,
        evidence=rule.rule_id or rule.__class__.__name__,
        explanation=(
            f"The {rule.metadata.name} rule did not finish: "
            f"{type(error).__name__}. Other rules continued to run."
        ),
        recommendation="Review the audit environment and rerun ReleaseGuard.",
        confidence=1.0,
        metadata={"failed_rule_id": rule.rule_id, "error_type": type(error).__name__},
    )


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Keep first-seen findings in execution order, keyed by stable fingerprint."""

    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            unique.append(finding)
    return unique


def _context_metric(context: ProjectContext, name: str) -> int:
    """Read a context metric while allowing the context to remain lightweight."""

    value = getattr(context, name, 0)
    return int(value) if isinstance(value, (int, float)) else 0


def _git_snapshot(context: ProjectContext) -> GitSnapshot:
    """Translate the context's dataclass into the public result contract."""

    info = context.git_info
    return GitSnapshot(
        available=info.available,
        is_repository=info.is_repository,
        branch=info.branch,
        head_commit=info.head_commit,
        is_detached=info.is_detached,
        changed_files=list(info.changed_files),
        staged_files=list(info.staged_files),
        untracked_files=list(info.untracked_files),
        conflicted_files=list(info.conflicted_files),
        error=info.error,
    )


def audit_project(
    project_path: str | Path,
    *,
    rules: Sequence[AuditRule] | None = None,
    max_file_size: int = 1_000_000,
    ai_client: AIReviewClient | None = None,
    ai_timeout_seconds: float = 15.0,
    include_remediation_plan: bool = False,
) -> AuditResult:
    """Audit a local directory and return a complete structured result.

    This function never executes project code or modifies the target. Rule failures
    are represented as low-severity scanner diagnostics so one malformed file or
    extension cannot prevent the caller from receiving the remaining evidence.
    """

    root = Path(project_path).expanduser()
    if not root.exists():
        raise ValueError(f"Project directory does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {root}")

    started = perf_counter()
    context = ProjectContext(root, max_file_size=max_file_size)
    active_rules = list(rules) if rules is not None else default_rules()
    findings: list[Finding] = []

    for rule in active_rules:
        try:
            findings.extend(rule.check(context))
        except Exception as error:  # Defensive boundary around third-party rules.
            findings.append(_rule_failure_finding(rule, error))

    unique_findings = _deduplicate(findings)
    score, gate = score_and_gate(unique_findings)
    duration = perf_counter() - started
    summary = AuditSummary.from_findings(
        unique_findings,
        files_scanned=_context_metric(context, "files_scanned"),
        files_skipped=_context_metric(context, "files_skipped"),
        duration_seconds=duration,
        rules_executed=len(active_rules),
    )
    remediation_plan = (
        build_remediation_plan(unique_findings) if include_remediation_plan else None
    )

    ai_review = None
    if ai_client is not None:
        from .ai.request_builder import build_analysis_request
        from .ai.schemas import AIReview, ReviewStatus

        try:
            if ai_timeout_seconds <= 0:
                raise ValueError("ai_timeout_seconds must be greater than zero")
            request = build_analysis_request(context, unique_findings)
            ai_review = ai_client.review(request, timeout_seconds=ai_timeout_seconds)
        except Exception:
            # AI is advisory. Do not expose a local prompt, model error, or
            # source detail through the deterministic audit boundary.
            ai_review = AIReview.failure(
                ReviewStatus.ERROR,
                error_code="ai_review_unavailable",
                error_message="The local AI review was unavailable; deterministic findings remain authoritative.",
            )

    return AuditResult(
        project_path=str(context.root),
        project_name=context.root.name or str(context.root),
        release_score=score,
        release_gate=gate,
        summary=summary,
        findings=unique_findings,
        scanner_version=SCANNER_VERSION,
        project_types=sorted(context.project_types),
        git=_git_snapshot(context),
        ai_review=ai_review,
        remediation_plan=remediation_plan,
    )


__all__ = ["AIReviewClient", "SCANNER_VERSION", "audit_project", "default_rules"]
