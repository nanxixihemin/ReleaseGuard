"""Deterministic, read-only remediation guidance for ReleaseGuard findings.

The functions in this module convert deterministic scanner findings into advice for
an external agent. They never inspect AI review prose and never change a project.
"""

from __future__ import annotations

from enum import Enum
import re
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

if TYPE_CHECKING:
    from .models import AuditResult, Finding


class FixSafety(str, Enum):
    """The only safety levels an external source-modifying agent may use."""

    SAFE = "SAFE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NEVER_AUTO_FIX = "NEVER_AUTO_FIX"


class RemediationItem(BaseModel):
    """A deterministic recommendation correlated with exactly one finding."""

    model_config = ConfigDict(extra="forbid")

    finding: str = Field(min_length=1)
    auto_fix_candidate: bool
    fix_safety: FixSafety
    target_file: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    verification: str = Field(min_length=1)
    fingerprint: str = Field(min_length=1)

    @field_validator("target_file", mode="before")
    @classmethod
    def _normalise_target_file(cls, value: str) -> str:
        return str(value).replace("\\", "/")

    @model_validator(mode="after")
    def _enforce_safety_contract(self) -> "RemediationItem":
        if self.fix_safety is FixSafety.SAFE and not self.auto_fix_candidate:
            raise ValueError("SAFE remediation items must set auto_fix_candidate to true")
        if self.fix_safety is not FixSafety.SAFE and self.auto_fix_candidate:
            raise ValueError("only SAFE remediation items may set auto_fix_candidate to true")
        return self

    def to_phase4_plan(self) -> "Any":
        """Project this Phase 3 item into a bounded Phase 4 approval plan.

        The import is intentionally local: ``releaseguard.models`` already
        imports :class:`RemediationItem`, so a module-level Phase 4 import would
        create a cycle and alter the stable Phase 3 import path.
        """

        from .phase4.models import RemediationPlan

        return RemediationPlan.from_item(self)

    # Alternate spelling used by integrations that treat the item as a source
    # contract rather than a conversion operation.
    as_phase4_plan = to_phase4_plan
    to_plan = to_phase4_plan
    to_remediation_plan = to_phase4_plan


class FindingReference(BaseModel):
    """A report-safe identity used by re-audit comparison contracts."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    fingerprint: str = Field(min_length=1)

    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity(cls, value: object) -> str:
        candidate = getattr(value, "value", value)
        return str(candidate).lower()

    @field_validator("file", mode="before")
    @classmethod
    def _normalise_file(cls, value: str) -> str:
        return str(value).replace("\\", "/")

    @classmethod
    def from_finding(cls, finding: "Finding") -> "FindingReference":
        """Create a compact reference without retaining evidence or AI prose."""

        return cls(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            file=finding.file,
            line=finding.line,
            fingerprint=finding.fingerprint,
        )


class ReAuditSnapshot(BaseModel):
    """The deterministic score, gate, and severity counts from one audit."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    gate: str = Field(min_length=1)
    severity_counts: dict[str, int]

    @field_validator("gate", mode="before")
    @classmethod
    def _normalise_gate(cls, value: object) -> str:
        candidate = getattr(value, "value", value)
        normalized = str(candidate).upper()
        if normalized not in {"PASS", "WARNING", "BLOCKED"}:
            raise ValueError("gate must be PASS, WARNING, or BLOCKED")
        return normalized

    @field_validator("severity_counts", mode="before")
    @classmethod
    def _normalise_severity_counts(cls, value: object) -> dict[str, int]:
        if not isinstance(value, dict):
            raise ValueError("severity_counts must be a mapping")

        normalized: dict[str, int] = {}
        for key, count in value.items():
            name = str(getattr(key, "value", key)).lower()
            if name not in {"critical", "high", "medium", "low"}:
                raise ValueError("severity_counts keys must be ReleaseGuard severity names")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("severity_counts values must be non-negative integers")
            normalized[name] = count

        missing = {"critical", "high", "medium", "low"} - normalized.keys()
        if missing:
            raise ValueError("severity_counts must include every ReleaseGuard severity")
        return normalized

    @classmethod
    def from_audit_result(cls, result: "AuditResult") -> "ReAuditSnapshot":
        """Build a snapshot from an already-authoritative audit document."""

        return cls(
            score=result.release_score,
            gate=result.release_gate,
            severity_counts=result.summary.counts,
        )


class ReAuditComparison(BaseModel):
    """Structured before/after state derived from deterministic audit results."""

    model_config = ConfigDict(extra="forbid")

    before: ReAuditSnapshot
    after: ReAuditSnapshot
    resolved_findings: list[FindingReference] = Field(default_factory=list)
    remaining_findings: list[FindingReference] = Field(default_factory=list)
    new_findings: list[FindingReference] = Field(default_factory=list)


_MANUAL_RULE_IDS = frozenset({"RG-SECRET-001", "RG-SENSITIVE-001", "RG-GIT-001"})
_PROTECTED_RISK_RE = re.compile(
    r"\b(?:secret|credential|private[ _-]?key|password|passwd|api[ _-]?key|"
    r"access[ _-]?token|bearer[ _-]?token|database[ _-]?(?:url|password)|"
    r"merge[ _-]?conflicts?|unmerged|data[ _-]?delet(?:e|ion)|delete[ _-]?data|"
    r"(?:generate|generation)[ _-]?(?:credential|token|key)|"
    r"(?:credential|token|key)[ _-]?(?:generate|generation))\b",
    re.IGNORECASE,
)
_PRIVATE_KEY_PATH_RE = re.compile(
    r"(?:^|[\\/])(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:$|[\\/])|"
    r"\.(?:key|pem)(?:$|[\\/])",
    re.IGNORECASE,
)


def _metadata(finding: "Finding") -> dict[str, Any]:
    metadata = getattr(finding, "metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def _metadata_text(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {_metadata_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_metadata_text(item) for item in value)
    return str(value)


def _is_environment_endpoint(finding: "Finding") -> bool:
    """Recognize only the scanner's actual endpoint finding for its review exception."""

    return (
        getattr(finding, "rule_id", "") == "RG-ENV-001"
        and str(getattr(finding, "category", "")).lower() == "environment"
    )


def _requires_manual_intervention(finding: "Finding") -> bool:
    """Return true for protected material and irreversible release decisions."""

    # A production loopback can be Critical under the release gate policy, but it
    # is still a configuration choice rather than protected material. It remains
    # review-only unless a future deterministic rule supplies a narrower proof.
    if _is_environment_endpoint(finding):
        return False

    severity = str(getattr(getattr(finding, "severity", ""), "value", getattr(finding, "severity", ""))).lower()
    if severity == "critical":
        return True
    if getattr(finding, "rule_id", "") in _MANUAL_RULE_IDS:
        return True

    if _PRIVATE_KEY_PATH_RE.search(str(getattr(finding, "file", ""))):
        return True

    text = " ".join(
        str(getattr(finding, attribute, ""))
        for attribute in ("rule_id", "title", "category", "file", "explanation", "recommendation")
    )
    return bool(_PROTECTED_RISK_RE.search(f"{text} {_metadata_text(_metadata(finding))}"))


def _is_explicit_debug_off_change(finding: "Finding") -> bool:
    return (
        getattr(finding, "rule_id", "") == "RG-DEBUG-001"
        and _metadata(finding).get("debug_setting") == "debug_enabled"
    )


def classify_fix_safety(finding: "Finding") -> FixSafety:
    """Classify from deterministic finding data only, with a strict allowlist."""

    if _requires_manual_intervention(finding):
        return FixSafety.NEVER_AUTO_FIX
    if _is_explicit_debug_off_change(finding):
        return FixSafety.SAFE
    return FixSafety.REVIEW_REQUIRED


def _recommended_action(finding: "Finding", safety: FixSafety) -> str:
    if safety is FixSafety.SAFE:
        return (
            "Change the explicitly enabled debug setting from true to false. "
            "Do not change unrelated runtime configuration."
        )
    if safety is FixSafety.NEVER_AUTO_FIX:
        return (
            "Manual intervention is required. Do not automatically remove, rotate, generate, "
            "or replace protected material or release state."
        )
    if _is_environment_endpoint(finding):
        return (
            "Review the deployment endpoint with the project owner and use only an already "
            "verified production configuration; do not invent an endpoint."
        )
    recommendation = str(getattr(finding, "recommendation", "")).strip()
    return recommendation or "Review this finding with the project owner before making a change."


def _verification(finding: "Finding", safety: FixSafety) -> str:
    rule_id = str(getattr(finding, "rule_id", "the finding"))
    if safety is FixSafety.NEVER_AUTO_FIX:
        return f"Complete the manual remediation, then rerun ReleaseGuard and confirm {rule_id} is resolved."
    return f"Rerun ReleaseGuard and confirm {rule_id} no longer reports this finding."


def remediation_for(finding: "Finding") -> RemediationItem:
    """Return one safety-classified, deterministic item for ``finding``."""

    safety = classify_fix_safety(finding)
    return RemediationItem(
        finding=finding.rule_id,
        auto_fix_candidate=safety is FixSafety.SAFE,
        fix_safety=safety,
        target_file=finding.file,
        recommended_action=_recommended_action(finding, safety),
        verification=_verification(finding, safety),
        fingerprint=finding.fingerprint,
    )


def build_remediation_plan(findings: Iterable["Finding"]) -> list[RemediationItem]:
    """Convert findings in scan order without mutating them or consulting AI output."""

    return [remediation_for(finding) for finding in findings]


def build_phase4_plans(findings: Iterable["Finding"]) -> list[Any]:
    """Return Phase 4 plans while preserving ``build_remediation_plan`` output."""

    return [item.to_phase4_plan() for item in build_remediation_plan(findings)]


def remediation_plan_for(item: RemediationItem) -> Any:
    """Convert one deterministic item to its Phase 4 bounded plan."""

    return item.to_phase4_plan()


def _comparison_identity(finding: "Finding") -> tuple[str, str, str]:
    """Return a conservative identity that survives harmless line movement."""

    return (finding.rule_id, finding.file, finding.title)


def _same_finding(before: "Finding", after: "Finding") -> bool:
    """Match real scan findings without consulting model assessments.

    A fingerprint is the strongest match.  The fallback keeps a finding present
    when a safe edit merely shifts its line number, which is especially important
    for protected material such as a secret left below a removed debug flag.
    """

    return (
        before.fingerprint == after.fingerprint
        or _comparison_identity(before) == _comparison_identity(after)
    )


def compare_audits(before: "AuditResult", after: "AuditResult") -> ReAuditComparison:
    """Compare two completed deterministic audits.

    Resolution is established only by the later scan.  AI review content never
    participates, so an advisory false-positive assessment cannot erase a
    deterministic Critical or any other finding from the comparison.
    """

    unmatched_after = list(after.findings)
    resolved: list[FindingReference] = []
    remaining: list[FindingReference] = []

    for before_finding in before.findings:
        match_index = next(
            (
                index
                for index, after_finding in enumerate(unmatched_after)
                if _same_finding(before_finding, after_finding)
            ),
            None,
        )
        if match_index is None:
            resolved.append(FindingReference.from_finding(before_finding))
            continue
        remaining.append(FindingReference.from_finding(unmatched_after.pop(match_index)))

    return ReAuditComparison(
        before=ReAuditSnapshot.from_audit_result(before),
        after=ReAuditSnapshot.from_audit_result(after),
        resolved_findings=resolved,
        remaining_findings=remaining,
        new_findings=[FindingReference.from_finding(finding) for finding in unmatched_after],
    )


__all__ = [
    "FindingReference",
    "FixSafety",
    "ReAuditComparison",
    "ReAuditSnapshot",
    "RemediationItem",
    "build_remediation_plan",
    "build_phase4_plans",
    "remediation_plan_for",
    "classify_fix_safety",
    "compare_audits",
    "remediation_for",
]
