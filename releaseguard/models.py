"""Structured, serializable contracts shared by scanners, rules, and reporters."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterable

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .ai.schemas import AIReview
from .ai.redaction import REDACTED_SECRET, redact_text
from .remediation import RemediationItem


class Severity(str, Enum):
    """The fixed severity vocabulary used by ReleaseGuard policies."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReleaseGate(str, Enum):
    """The release recommendation emitted by an audit."""

    PASS = "PASS"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"


class FindingStatus(str, Enum):
    """Human disposition for a finding.

    Disposition is intentionally separate from :class:`ReleaseGate`: it is an
    audit workflow annotation and never changes the deterministic score or gate.
    In particular, ``APPROVED`` means that a remediation was authorised; only a
    later deterministic re-audit can establish ``RESOLVED``.
    """

    OPEN = "OPEN"
    AUTO_FIXED = "AUTO_FIXED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


# Compatibility spelling for integrations that call the field a disposition.
Disposition = FindingStatus


class Finding(BaseModel):
    """A single deterministic or AI-enriched release risk."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    category: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    evidence: str = ""
    explanation: str = ""
    recommendation: str = ""
    auto_fixable: bool = False
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    # This is deliberately non-authoritative.  The scanner and score/gate
    # policy continue to derive release state from actual findings.
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        validation_alias=AliasChoices("status", "disposition"),
    )

    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity(cls, value: Severity | str) -> Severity | str:
        if isinstance(value, str):
            return value.lower()
        return value

    @field_validator("file", mode="before")
    @classmethod
    def _normalise_file(cls, value: str | Path) -> str:
        # Finding paths are project-relative display paths. Use POSIX separators
        # so reports and fingerprints stay stable across Windows and POSIX hosts.
        return str(value).replace("\\", "/")

    @field_validator("status", mode="before")
    @classmethod
    def _normalise_status(cls, value: FindingStatus | str) -> FindingStatus | str:
        if isinstance(value, str):
            return value.strip().upper()
        return value

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.calculate_fingerprint())

    @classmethod
    def build_fingerprint(
        cls,
        *,
        rule_id: str,
        file: str | Path,
        line: int | None,
        evidence: str,
    ) -> str:
        """Return a stable SHA-256 identity for a finding location and evidence."""

        payload = {
            "evidence": evidence,
            "file": str(file).replace("\\", "/"),
            "line": line,
            "rule_id": rule_id,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return sha256(encoded).hexdigest()

    @classmethod
    def fingerprint_for(
        cls,
        *,
        rule_id: str,
        file: str | Path,
        line: int | None,
        evidence: str,
    ) -> str:
        """Alias for :meth:`build_fingerprint` for rule implementations."""

        return cls.build_fingerprint(
            rule_id=rule_id,
            file=file,
            line=line,
            evidence=evidence,
        )

    def calculate_fingerprint(self) -> str:
        """Calculate this finding's fingerprint without mutating the model."""

        return self.build_fingerprint(
            rule_id=self.rule_id,
            file=self.file,
            line=self.line,
            evidence=self.evidence,
        )

    @property
    def disposition(self) -> FindingStatus:
        return self.status

    def with_status(
        self,
        status: FindingStatus | str,
        *,
        reaudited: bool = False,
        verified: bool | None = None,
        resolution_verified: bool | None = None,
    ) -> "Finding":
        """Return a disposition copy without changing finding identity.

        ``RESOLVED`` is reserved for a verified re-audit.  The explicit
        ``reaudited`` flag keeps accidental AI/advisor payloads from being used
        as proof of resolution while still allowing workflow services to create
        an immutable resolved view after a fresh scan.
        """

        if verified is not None:
            reaudited = reaudited or verified
        if resolution_verified is not None:
            reaudited = reaudited or resolution_verified
        normalized = status
        if isinstance(normalized, str):
            normalized = normalized.strip().upper()
        try:
            normalized_status = FindingStatus(normalized)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unknown finding status: {status!r}") from exc
        if normalized_status is FindingStatus.RESOLVED and not reaudited:
            raise ValueError("RESOLVED requires a verified re-audit")
        return self.model_copy(update={"status": normalized_status})

    def mark_resolved_after_reaudit(self, *, audit_run_id: str) -> "Finding":
        """Return a resolved copy after a caller has completed a fresh audit.

        The run identifier is intentionally required and validated here even
        though it is not persisted on the finding itself; evidence/timeline
        records retain the binding in the Phase 4 workflow layer.
        """

        if not str(audit_run_id).strip():
            raise ValueError("audit_run_id is required to mark a finding resolved")
        return self.with_status(FindingStatus.RESOLVED, reaudited=True)

    # A class-level spelling is convenient for workflow code and keeps the
    # instance helper discoverable to callers that only have a finding object.
    @classmethod
    def resolved_after_reaudit(
        cls,
        finding: "Finding",
        *,
        audit_run_id: str,
    ) -> "Finding":
        return finding.mark_resolved_after_reaudit(audit_run_id=audit_run_id)

    resolve_after_reaudit = resolved_after_reaudit


class AuditSummary(BaseModel):
    """Aggregate audit metrics, intentionally independent from report rendering."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    critical: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("critical", "critical_count"),
    )
    high: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("high", "high_count"),
    )
    medium: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("medium", "medium_count"),
    )
    low: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("low", "low_count"),
    )
    files_scanned: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("files_scanned", "scanned_files"),
    )
    files_skipped: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("files_skipped", "skipped_files"),
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        validation_alias=AliasChoices("duration_seconds", "duration"),
    )
    rules_executed: int = Field(
        default=0,
        ge=0,
        validation_alias=AliasChoices("rules_executed", "rules"),
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_count_mapping(cls, value: Any) -> Any:
        """Accept ``counts`` as a convenience without changing the JSON schema."""

        if not isinstance(value, dict) or not isinstance(value.get("counts"), dict):
            return value

        normalized = dict(value)
        counts = value["counts"]
        for severity in Severity:
            candidates = (severity, severity.value, severity.name, severity.name.lower())
            for candidate in candidates:
                if candidate in counts and severity.value not in normalized:
                    normalized[severity.value] = counts[candidate]
                    break
        normalized.pop("counts", None)
        return normalized

    @classmethod
    def from_findings(
        cls,
        findings: Iterable[Finding],
        *,
        files_scanned: int = 0,
        files_skipped: int = 0,
        duration_seconds: float = 0.0,
        rules_executed: int = 0,
    ) -> "AuditSummary":
        counts = {severity: 0 for severity in Severity}
        for finding in findings:
            counts[finding.severity] += 1
        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            duration_seconds=duration_seconds,
            rules_executed=rules_executed,
        )

    @property
    def counts(self) -> dict[str, int]:
        """A severity-keyed representation convenient for consumers."""

        return {
            Severity.CRITICAL.value: self.critical,
            Severity.HIGH.value: self.high,
            Severity.MEDIUM.value: self.medium,
            Severity.LOW.value: self.low,
        }

    @property
    def critical_count(self) -> int:
        return self.critical

    @property
    def high_count(self) -> int:
        return self.high

    @property
    def medium_count(self) -> int:
        return self.medium

    @property
    def low_count(self) -> int:
        return self.low

    @property
    def total_findings(self) -> int:
        return self.critical + self.high + self.medium + self.low


class GitSnapshot(BaseModel):
    """JSON-safe Git state retained even when no Git finding is emitted."""

    model_config = ConfigDict(extra="forbid")

    available: bool = False
    is_repository: bool = False
    branch: str | None = None
    head_commit: str | None = None
    is_detached: bool = False
    changed_files: list[str] = Field(default_factory=list)
    staged_files: list[str] = Field(default_factory=list)
    untracked_files: list[str] = Field(default_factory=list)
    conflicted_files: list[str] = Field(default_factory=list)
    error: str | None = None


class AuditResult(BaseModel):
    """The complete, machine-readable result of one project audit."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, validate_default=True)

    project_path: str
    project_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    release_score: int = Field(ge=0, le=100)
    release_gate: ReleaseGate
    summary: AuditSummary = Field(default_factory=AuditSummary)
    findings: list[Finding] = Field(default_factory=list)
    scanner_version: str = "0.2.0"
    project_types: list[str] = Field(default_factory=list)
    git: GitSnapshot = Field(default_factory=GitSnapshot)
    ai_review: AIReview | None = None
    remediation_plan: list[RemediationItem] | None = None

    @field_validator("project_path", mode="before")
    @classmethod
    def _normalise_project_path(cls, value: str | Path) -> str:
        return str(value)

    @field_validator("release_gate", mode="before")
    @classmethod
    def _normalise_release_gate(cls, value: ReleaseGate | str) -> ReleaseGate | str:
        if isinstance(value, str):
            return value.upper()
        return value

    @field_validator("timestamp")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-safe data for reporters and Agent integrations."""

        payload = self.model_dump(mode="json")
        payload = _sanitize_report_payload(payload)
        # Preserve every existing Phase 1 key (including Git nulls) when AI is
        # off; only the absent optional enhancement key is omitted.
        if self.ai_review is None:
            payload.pop("ai_review", None)
        if self.remediation_plan is None:
            payload.pop("remediation_plan", None)
        return payload

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return deterministic JSON with stable key ordering."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )

    @property
    def phase4_remediation_plan(self) -> list[Any]:
        """Return bounded Phase 4 plans without changing the Phase 3 field."""

        from .phase4.models import RemediationPlan

        if self.remediation_plan is None:
            return []
        return [RemediationPlan.from_item(item) for item in self.remediation_plan]

    def to_phase4_plans(self) -> list[Any]:
        return self.phase4_remediation_plan


_SENSITIVE_OUTPUT_KEYS = {
    "secret",
    "password",
    "passwd",
    "credential",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "private_key",
}
_REDACTABLE_TEXT_KEYS = {
    "evidence",
    "title",
    "explanation",
    "recommendation",
    "rationale",
    "remediation",
    "release_summary",
    "reason",
    "summary",
    "error_message",
}


def _sanitize_report_payload(value: Any, *, key: str | None = None) -> Any:
    """Redact untrusted finding/AI prose at the final report boundary."""

    if key is not None and any(part in key.lower() for part in _SENSITIVE_OUTPUT_KEYS):
        if value not in (None, "", [], {}):
            return REDACTED_SECRET
    if isinstance(value, str):
        if key is not None and key.lower() in _REDACTABLE_TEXT_KEYS:
            return redact_text(value)
        # Catch a token in an otherwise structural field without redacting
        # ordinary absolute project paths or URLs.
        if re.search(r"(?i)(?:sk-(?:proj-)?|ghp_|github_pat_|AKIA[0-9A-Z]{16}|Bearer\s+)", value):
            return redact_text(value)
        return value
    if isinstance(value, dict):
        return {str(item_key): _sanitize_report_payload(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_report_payload(item, key=key) for item in value]
    return value

def __getattr__(name: str) -> Any:
    """Lazily expose Phase 4 contracts without introducing import cycles."""

    phase4_names = {
        "ApprovalAction",
        "ApprovalRecord",
        "ApprovalStatus",
        "ProjectSnapshot",
        "RemediationPlan",
        "TimelineEvent",
        "TimelineEventType",
    }
    if name in phase4_names:
        from .phase4 import models as phase4_models

        return getattr(phase4_models, name)
    raise AttributeError(name)
