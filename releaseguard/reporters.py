"""Stable human and machine report renderers for audit results."""

from __future__ import annotations

import json

from .models import AuditResult, Finding
from .remediation import FindingReference, ReAuditComparison
from .ai.redaction import redact_text


def render_json(result: AuditResult) -> str:
    """Render stable, pretty JSON for agents and automated consumers."""

    return result.to_json(indent=2) + "\n"


def _inline_code(value: str) -> str:
    """Render a short Markdown code value without allowing fence injection."""

    return value.replace("`", "'").replace("\n", " ").strip()


def _finding_markdown(finding: Finding) -> list[str]:
    severity = finding.severity.value.upper()
    location = finding.file
    if finding.line is not None:
        location = f"{location}:{finding.line}"

    safe_title = redact_text(finding.title)
    safe_evidence = redact_text(finding.evidence)
    safe_explanation = redact_text(finding.explanation)
    safe_recommendation = redact_text(finding.recommendation)

    lines = [
        f"### [{severity}] {redact_text(finding.rule_id)}",
        "",
        f"**{safe_title}**",
        "",
        f"**File:** `{_inline_code(location)}`",
    ]
    if safe_evidence:
        lines.extend(
            [
                "",
                "**Evidence:**",
                "",
                "```text",
                safe_evidence.replace("```", "'''"),
                "```",
            ]
        )
    if safe_explanation:
        lines.extend(["", f"**Reason:** {safe_explanation}"])
    if safe_recommendation:
        lines.extend(["", f"**Recommendation:** {safe_recommendation}"])
    return lines


def _reference_markdown(reference: FindingReference) -> str:
    location = reference.file
    if reference.line is not None:
        location = f"{location}:{reference.line}"
    return (
        f"- [{reference.severity.upper()}] {reference.rule_id} "
        f"at `{_inline_code(location)}` - {reference.title}"
    )


def _snapshot_markdown(label: str, score: int, gate: str, counts: dict[str, int]) -> list[str]:
    return [
        f"## {label}",
        "",
        f"- Score: {score}",
        f"- Gate: {gate}",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
    ]


def render_markdown(result: AuditResult) -> str:
    """Render a concise, readable Markdown release-audit report."""

    summary = result.summary
    lines = [
        "# ReleaseGuard Audit",
        "",
        f"**Project:** {result.project_name}",
        f"**Path:** `{_inline_code(result.project_path)}`",
        f"**Status:** {result.release_gate.value}",
        f"**Release Readiness Score:** {result.release_score}/100",
        "",
        "## Summary",
        "",
        f"- Critical: {summary.critical}",
        f"- High: {summary.high}",
        f"- Medium: {summary.medium}",
        f"- Low: {summary.low}",
        f"- Files scanned: {summary.files_scanned}",
        f"- Files skipped: {summary.files_skipped}",
        f"- Rules executed: {summary.rules_executed}",
        f"- Duration: {summary.duration_seconds:.2f}s",
    ]
    if result.git.is_repository:
        revision = result.git.head_commit or "unknown commit"
        branch = result.git.branch or "detached HEAD"
        lines.append(f"- Git: {branch} ({revision})")
    elif not result.git.available:
        lines.append("- Git: unavailable")
    else:
        lines.append("- Git: not a repository")

    if result.findings:
        lines.extend(["", "## Findings"])
        for finding in result.findings:
            lines.extend(["", *_finding_markdown(finding)])
    else:
        lines.extend(["", "## Findings", "", "No release-risk findings were detected."])

    if result.remediation_plan is not None:
        lines.extend(["", "## Remediation Plan"])
        for item in result.remediation_plan:
            lines.extend(
                [
                    "",
                    f"### [{item.fix_safety.value}] {item.finding}",
                    "",
                    f"**File:** `{_inline_code(item.target_file)}`",
                    "",
                    f"**Action:** {item.recommended_action}",
                    "",
                    f"**Verification:** {item.verification}",
                ]
            )

    if result.ai_review is not None:
        review = result.ai_review
        lines.extend(
            [
                "",
                "## Local AI Review",
                "",
                "- AI Analyzer: OpenVINO",
                f"- Status: {review.status.value}",
                f"- Model: {review.model_id or 'unavailable'}",
                f"- Device: {review.device or 'not loaded'}",
                f"- Local: {'Yes' if review.local else 'No'}",
                f"- AI Reviewed: {len(review.finding_assessments)}",
            ]
        )
        if review.is_successful:
            by_fingerprint = {finding.fingerprint: finding for finding in result.findings}
            lines.extend(["", "### OpenVINO Semantic Assessment"])
            for assessment in review.finding_assessments:
                finding = by_fingerprint.get(assessment.fingerprint)
                heading = finding.rule_id if finding is not None else assessment.fingerprint[:12]
                lines.extend(
                    [
                        "",
                        f"#### {heading}",
                        "",
                        f"- True Positive: {'Yes' if assessment.likely_true_positive else 'No'}",
                        f"- Confidence: {assessment.confidence:.2f}",
                        f"- Semantic Risk: {assessment.semantic_risk.value}",
                    ]
                )
                if assessment.rationale:
                    lines.extend(["", f"**Reason:** {assessment.rationale}"])
                if assessment.remediation:
                    lines.extend(["", f"**Recommended Fix:** {assessment.remediation}"])
            if review.release_summary:
                lines.extend(["", "### Release Summary", "", review.release_summary])
        elif review.error_message:
            lines.extend(["", f"Local AI fallback: {review.error_message}"])

    gate_text = {
        "PASS": "ReleaseGuard found no Phase 1 release blockers.",
        "WARNING": "ReleaseGuard recommends reviewing the findings before production deployment.",
        "BLOCKED": "ReleaseGuard does not recommend production deployment until blockers are remediated and re-audited.",
    }[result.release_gate.value]
    lines.extend(["", f"## Release Gate: {result.release_gate.value}", "", gate_text, ""])
    return "\n".join(lines)


def render_reaudit_json(comparison: ReAuditComparison) -> str:
    """Render a parseable comparison without loading source or model output."""

    return json.dumps(
        comparison.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def render_reaudit_markdown(comparison: ReAuditComparison) -> str:
    """Render a factual before/after report from two completed audits."""

    lines = ["# ReleaseGuard Re-Audit", ""]
    lines.extend(
        _snapshot_markdown(
            "Before",
            comparison.before.score,
            comparison.before.gate,
            comparison.before.severity_counts,
        )
    )
    lines.extend([""])
    lines.extend(
        _snapshot_markdown(
            "After",
            comparison.after.score,
            comparison.after.gate,
            comparison.after.severity_counts,
        )
    )

    lines.extend(["", "## Resolved", ""])
    if comparison.resolved_findings:
        lines.extend(_reference_markdown(reference) for reference in comparison.resolved_findings)
    else:
        lines.append("No prior findings were resolved by the later audit.")

    lines.extend(["", "## Remaining", ""])
    if comparison.remaining_findings:
        lines.extend(_reference_markdown(reference) for reference in comparison.remaining_findings)
    else:
        lines.append("No prior findings remain in the later audit.")

    if comparison.new_findings:
        lines.extend(["", "## New Findings", ""])
        lines.extend(_reference_markdown(reference) for reference in comparison.new_findings)

    remaining_rule_ids = {reference.rule_id for reference in comparison.remaining_findings}
    if "RG-SECRET-001" in remaining_rule_ids:
        lines.extend(
            [
                "",
                "## Manual Intervention",
                "",
                "**Reason:** Secret rotation requires manual intervention.",
            ]
        )
    elif remaining_rule_ids & {"RG-SENSITIVE-001", "RG-GIT-001"}:
        lines.extend(
            [
                "",
                "## Manual Intervention",
                "",
                "**Reason:** Protected material or merge state requires manual intervention.",
            ]
        )

    lines.append("")
    return "\n".join(lines)


__all__ = [
    "render_json",
    "render_markdown",
    "render_reaudit_json",
    "render_reaudit_markdown",
]
