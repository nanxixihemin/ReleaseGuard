"""Strict, JSON-safe contracts for the Phase 4 human approval loop."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, TYPE_CHECKING
from uuid import uuid4

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ..models import FindingStatus
from ..remediation import FixSafety, RemediationItem
from .redaction import contains_raw_secret, redact_for_persistence, redact_text, redact_value

if TYPE_CHECKING:  # pragma: no cover - imported only for static type checkers
    from ..models import Finding


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class ApprovalAction(str, Enum):
    """Actions a human may record against a finding."""

    APPROVE_REMEDIATION = "APPROVE_REMEDIATION"
    APPROVE = "APPROVE_REMEDIATION"
    REJECT = "REJECT"
    DEFER = "DEFER"
    MARK_FALSE_POSITIVE = "MARK_FALSE_POSITIVE"
    FALSE_POSITIVE = "MARK_FALSE_POSITIVE"


class AuthorizationChannel(str, Enum):
    """Trusted channel through which a human disposition was recorded."""

    DASHBOARD = "dashboard"


class ApprovalStatus(str, Enum):
    """Lifecycle state of an approval record, independent of resolution."""

    PENDING = "PENDING"
    PENDING_REVIEW = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MARKED_FALSE_POSITIVE = "FALSE_POSITIVE"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class TimelineEventType(str, Enum):
    """Append-only event vocabulary for audit and remediation evidence."""

    AUDIT_STARTED = "AUDIT_STARTED"
    AUDIT_COMPLETED = "AUDIT_COMPLETED"
    FINDING_DETECTED = "FINDING_DETECTED"
    AI_ANALYSIS_COMPLETED = "AI_ANALYSIS_COMPLETED"
    HUMAN_REVIEW_REQUESTED = "HUMAN_REVIEW_REQUESTED"
    REMEDIATION_APPROVED = "REMEDIATION_APPROVED"
    REMEDIATION_REJECTED = "REMEDIATION_REJECTED"
    REMEDIATION_DEFERRED = "REMEDIATION_DEFERRED"
    FALSE_POSITIVE_MARKED = "FALSE_POSITIVE_MARKED"
    REMEDIATION_STARTED = "REMEDIATION_STARTED"
    REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    FILE_CHANGED = "FILE_CHANGED"
    REAUDIT_STARTED = "REAUDIT_STARTED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    FINDING_STILL_PRESENT = "FINDING_STILL_PRESENT"
    GATE_CALCULATED = "GATE_CALCULATED"
    APPROVAL_RECORDED = "APPROVAL_RECORDED"


def _normalise_enum(value: object, enum_type: type[Enum]) -> object:
    """Accept common human spellings while serialising one stable value."""

    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    # ``AuditStarted``, ``audit-started`` and ``audit_started`` all map to the
    # same wire value.  Unknown values are left for Pydantic to reject.
    if not candidate.isupper():
        candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", candidate)
    candidate = re.sub(r"[\s-]+", "_", candidate).upper()
    return candidate


def _normalise_id(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    result = value.strip()
    if not result:
        raise ValueError(f"{field_name} must not be empty")
    if len(result) > 256:
        raise ValueError(f"{field_name} is too long")
    return result


def _normalise_relative_path(value: object, field_name: str = "path") -> str:
    if not isinstance(value, (str, Path)):
        raise TypeError(f"{field_name} must be a path string")
    rendered = str(value).replace("\\", "/").strip()
    if not rendered:
        raise ValueError(f"{field_name} must not be empty")
    # Evidence paths are project-relative.  Reject absolute paths and traversal
    # before they can become an approved remediation target.
    if rendered.startswith("/") or re.match(r"^[A-Za-z]:/", rendered):
        raise ValueError(f"{field_name} must be project-relative")
    path_object = PurePosixPath(rendered)
    if ".." in path_object.parts:
        raise ValueError(f"{field_name} must not escape the project")
    normalized = str(path_object)
    if normalized in {".", ""}:
        raise ValueError(f"{field_name} must not escape the project")
    return normalized


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class _Phase4Model(BaseModel):
    """Common strict model settings used at the persistence boundary."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
        use_enum_values=False,
    )


class ProjectSnapshot(_Phase4Model):
    """A content-addressed view of project files at an audit/approval point."""

    snapshot_id: str = Field(default_factory=lambda: uuid4().hex, min_length=1, max_length=256)
    project_path: str | None = Field(default=None, max_length=4096)
    files: dict[str, str] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("files", "file_hashes", "hashes"),
    )
    content_hash: str = Field(
        default="",
        validation_alias=AliasChoices(
            "content_hash",
            "snapshot_hash",
            "project_hash",
            "hash",
        ),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices("created_at", "timestamp"),
    )

    @field_validator("snapshot_id", mode="before")
    @classmethod
    def _validate_snapshot_id(cls, value: object) -> str:
        return _normalise_id(value, "snapshot_id")

    @field_validator("project_path", mode="before")
    @classmethod
    def _normalise_project_path(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, (str, Path)):
            raise TypeError("project_path must be a path string")
        return str(value)

    @field_validator("files", mode="before")
    @classmethod
    def _validate_files(cls, value: object) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("files must be a mapping of relative paths to SHA-256 hashes")
        normalized: dict[str, str] = {}
        for raw_path, raw_hash in value.items():
            path = _normalise_relative_path(raw_path, "file path")
            if contains_raw_secret(path):
                raise ValueError("snapshot file paths must not contain credential-like literals")
            if not isinstance(raw_hash, str) or not _SHA256_RE.fullmatch(raw_hash.strip()):
                raise ValueError(f"file hash for {path!r} must be a SHA-256 hex digest")
            normalized[path] = raw_hash.strip().lower()
        return dict(sorted(normalized.items()))

    @field_validator("content_hash", mode="before")
    @classmethod
    def _validate_content_hash(cls, value: object) -> str:
        if value in (None, ""):
            return ""
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.strip()):
            raise ValueError("content_hash must be a SHA-256 hex digest")
        return value.strip().lower()

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @model_validator(mode="after")
    def _derive_and_verify_hash(self) -> "ProjectSnapshot":
        calculated = self.calculate_hash()
        if self.content_hash and self.content_hash != calculated:
            raise ValueError("content_hash does not match files")
        if not self.content_hash:
            object.__setattr__(self, "content_hash", calculated)
        return self

    def calculate_hash(self) -> str:
        """Return a deterministic SHA-256 over sorted relative file hashes."""

        encoded = "".join(f"{path}\0{digest}\n" for path, digest in sorted(self.files.items()))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def from_files(
        cls,
        files: dict[str, str],
        *,
        project_path: str | Path | None = None,
        snapshot_id: str | None = None,
    ) -> "ProjectSnapshot":
        return cls(
            files=files,
            project_path=project_path,
            **({"snapshot_id": snapshot_id} if snapshot_id is not None else {}),
        )

    @property
    def snapshot_hash(self) -> str:
        return self.content_hash

    @property
    def hash(self) -> str:  # noqa: A003 - compatibility with the public contract
        return self.content_hash

    @property
    def file_hashes(self) -> dict[str, str]:
        return dict(self.files)


class RemediationPlan(_Phase4Model):
    """An explicit, bounded change scope derived from deterministic advice."""

    finding_id: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("finding_id", "finding", "rule_id"),
    )
    summary: str = Field(
        min_length=1,
        max_length=2000,
        validation_alias=AliasChoices("summary", "recommended_action"),
    )
    risk: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("risk", "severity", "fix_safety"),
    )
    allowed_files: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("allowed_files", "target_files"),
    )
    allowed_operations: list[str] = Field(default_factory=list)
    forbidden_operations: list[str] = Field(default_factory=list)
    requires_human_approval: bool = Field(
        default=True,
        validation_alias=AliasChoices("requires_human_approval", "requires_approval"),
    )
    expected_effect: str = Field(
        default="",
        max_length=2000,
        validation_alias=AliasChoices("expected_effect", "expected_result", "verification"),
    )
    rollback_possible: bool = Field(
        default=False,
        validation_alias=AliasChoices("rollback_possible", "rollback"),
    )
    fingerprint: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("finding_id", mode="before")
    @classmethod
    def _validate_finding_id(cls, value: object) -> str:
        return _normalise_id(value, "finding_id")

    @field_validator("summary", "expected_effect", mode="before")
    @classmethod
    def _redact_text_fields(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("remediation text fields must be strings")
        return redact_text(value)

    @field_validator("risk", mode="before")
    @classmethod
    def _normalise_risk(cls, value: object) -> str:
        candidate = getattr(value, "value", value)
        if not isinstance(candidate, str):
            raise TypeError("risk must be a string or safety enum")
        normalized = redact_text(candidate.strip())
        if not normalized:
            raise ValueError("risk must not be empty")
        # The deterministic safety labels are canonicalised, while the public
        # contract also permits a bounded human-readable risk description (for
        # example ``critical credential exposure`` from the workflow layer).
        compact = normalized.upper().replace("-", "_")
        known = {
            "SAFE",
            "REVIEW_REQUIRED",
            "NEVER_AUTO_FIX",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "UNKNOWN",
        }
        return compact if compact in known else normalized

    @field_validator("allowed_files", mode="before")
    @classmethod
    def _normalise_allowed_files(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (str, Path)):
            value = [value]
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise TypeError("allowed_files must be a sequence")
        result = sorted({_normalise_relative_path(item, "allowed file") for item in value})
        if any(contains_raw_secret(item) for item in result):
            raise ValueError("allowed file paths must not contain credential-like literals")
        return result

    @field_validator("allowed_operations", "forbidden_operations", mode="before")
    @classmethod
    def _normalise_operations(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise TypeError("operations must be a sequence")
        result: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("operations must contain non-empty strings")
            result.append(redact_text(item.strip()))
        return list(dict.fromkeys(result))

    @field_validator("requires_human_approval", "rollback_possible", mode="before")
    @classmethod
    def _strict_bool(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise TypeError("boolean fields must be bool")
        return value

    @field_validator("fingerprint", mode="before")
    @classmethod
    def _normalise_fingerprint(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError("fingerprint must be a non-empty string")
        return value.strip()

    @model_validator(mode="after")
    def _enforce_scope_contract(self) -> "RemediationPlan":
        if self.risk == "NEVER_AUTO_FIX" and not self.requires_human_approval:
            raise ValueError("NEVER_AUTO_FIX plans require human approval")
        overlap = set(self.allowed_operations) & set(self.forbidden_operations)
        if overlap:
            raise ValueError("an operation cannot be both allowed and forbidden")
        return self

    @classmethod
    def from_item(cls, item: RemediationItem) -> "RemediationPlan":
        """Convert a Phase 3 item without mutating or changing that output."""

        if not isinstance(item, RemediationItem):
            item = RemediationItem.model_validate(item)
        safety = item.fix_safety.value
        if item.fix_safety is FixSafety.SAFE:
            operations = ["apply the explicitly described safe setting change"]
            forbidden = [
                "modify files outside the approved scope",
                "change unrelated configuration or dependencies",
                "print or persist credentials",
            ]
        elif item.fix_safety is FixSafety.REVIEW_REQUIRED:
            operations = ["apply only the remediation approved by a human reviewer"]
            forbidden = [
                "invent production values",
                "modify files outside the approved scope",
                "print or persist credentials",
            ]
        else:
            operations = []
            forbidden = [
                "automatically change protected material",
                "generate, rotate, or print credentials",
                "modify files outside the approved scope",
            ]
        return cls(
            finding_id=item.finding,
            summary=item.recommended_action,
            risk=safety,
            allowed_files=[item.target_file],
            allowed_operations=operations,
            forbidden_operations=forbidden,
            requires_human_approval=item.fix_safety is not FixSafety.SAFE,
            expected_effect=item.verification,
            rollback_possible=item.fix_safety is FixSafety.SAFE,
            fingerprint=item.fingerprint,
        )

    @classmethod
    def from_remediation_item(cls, item: RemediationItem) -> "RemediationPlan":
        return cls.from_item(item)

    from_remediation = from_remediation_item
    from_phase3_item = from_remediation_item

    @classmethod
    def from_finding(cls, finding: "Finding") -> "RemediationPlan":
        from ..remediation import remediation_for

        return cls.from_item(remediation_for(finding))

    @property
    def finding(self) -> str:
        return self.finding_id

    @property
    def target_file(self) -> str | None:
        return self.allowed_files[0] if self.allowed_files else None

    @property
    def recommended_action(self) -> str:
        return self.summary

    @property
    def verification(self) -> str:
        return self.expected_effect

    @property
    def auto_fix_candidate(self) -> bool:
        return self.risk != "NEVER_AUTO_FIX" and not self.requires_human_approval

    @property
    def fix_safety(self) -> str:
        if self.risk in {item.value for item in FixSafety}:
            return self.risk
        return FixSafety.REVIEW_REQUIRED.value if self.requires_human_approval else FixSafety.SAFE.value

    @property
    def safety_level(self) -> FixSafety | None:
        try:
            return FixSafety(self.risk)
        except ValueError:
            return None

    def to_remediation_item(self) -> RemediationItem:
        """Best-effort compatibility projection for Phase 3 integrations."""

        safety = FixSafety(self.fix_safety)
        return RemediationItem(
            finding=self.finding_id,
            auto_fix_candidate=safety is FixSafety.SAFE,
            fix_safety=safety,
            target_file=self.target_file or ".",
            recommended_action=self.summary,
            verification=self.expected_effect or "Rerun ReleaseGuard.",
            fingerprint=self.fingerprint or ("0" * 64),
        )


class ApprovalRecord(_Phase4Model):
    """An immutable human action bound to a finding, audit, and snapshot."""

    approval_id: str = Field(
        default_factory=lambda: uuid4().hex,
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("approval_id", "id"),
    )
    finding_id: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("finding_id", "finding", "rule_id"),
    )
    action: ApprovalAction
    actor: str = Field(default="human", min_length=1, max_length=128)
    # ``actor`` is display metadata only.  The workflow treats these fields as
    # part of the authorization contract and never accepts caller-supplied
    # strings as proof of human authority.
    actor_type: str = Field(default="human", min_length=1, max_length=32)
    authorization_channel: AuthorizationChannel = Field(
        default=AuthorizationChannel.DASHBOARD,
        validation_alias=AliasChoices("authorization_channel", "channel"),
    )
    # The workflow stores a digest of a one-time dashboard action token here;
    # the raw token is never persisted in evidence or state.
    authorization_nonce: str = Field(default="", max_length=256)
    reason: str = Field(default="", max_length=4000)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices("timestamp", "created_at"),
    )
    audit_run_id: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("audit_run_id", "audit_id"),
    )
    project_snapshot: ProjectSnapshot | str = Field(
        validation_alias=AliasChoices(
            "project_snapshot",
            "project_snapshot_hash",
            "snapshot",
            "snapshot_hash",
        )
    )
    requested_remediation: RemediationPlan | dict[str, Any] | str | None = Field(
        default=None,
        validation_alias=AliasChoices("requested_remediation", "remediation_plan"),
    )
    approved_scope: dict[str, Any] | RemediationPlan | list[str] | str | None = Field(
        default=None,
        validation_alias=AliasChoices("approved_scope", "scope"),
    )
    status: ApprovalStatus | None = Field(
        default=None,
        validation_alias=AliasChoices("status", "approval_status"),
    )
    finding_fingerprint: str | None = Field(
        default=None,
        validation_alias=AliasChoices("finding_fingerprint", "fingerprint"),
        min_length=1,
        max_length=256,
    )

    @field_validator("approval_id", "finding_id", "audit_run_id", mode="before")
    @classmethod
    def _validate_ids(cls, value: object, info: Any) -> str:
        return _normalise_id(value, info.field_name)

    @field_validator("action", mode="before")
    @classmethod
    def _normalise_action(cls, value: object) -> object:
        normalized = _normalise_enum(value, ApprovalAction)
        if isinstance(normalized, str):
            normalized = {
                "APPROVE": ApprovalAction.APPROVE_REMEDIATION.value,
                "APPROVAL": ApprovalAction.APPROVE_REMEDIATION.value,
                "FALSE_POSITIVE": ApprovalAction.MARK_FALSE_POSITIVE.value,
                "MARK_FALSE_POSITIVE": ApprovalAction.MARK_FALSE_POSITIVE.value,
            }.get(normalized, normalized)
        return normalized

    @field_validator("actor", mode="before")
    @classmethod
    def _validate_actor(cls, value: object) -> str:
        actor = _normalise_id(value, "actor")
        if actor.strip().lower() in {"ai", "agent", "qoder", "model", "openvino"}:
            raise ValueError("approval actor must be a human or explicitly authorised operator")
        return actor

    @field_validator("actor_type", mode="before")
    @classmethod
    def _validate_actor_type(cls, value: object) -> str:
        actor_type = _normalise_id(value, "actor_type").lower()
        if actor_type != "human":
            raise ValueError("human dispositions must have actor_type=human")
        return actor_type

    @field_validator("authorization_channel", mode="before")
    @classmethod
    def _normalise_authorization_channel(cls, value: object) -> object:
        if isinstance(value, str) and value.strip().lower() == AuthorizationChannel.DASHBOARD.value:
            return AuthorizationChannel.DASHBOARD
        normalized = _normalise_enum(value, AuthorizationChannel)
        if normalized not in {AuthorizationChannel.DASHBOARD, AuthorizationChannel.DASHBOARD.value}:
            raise ValueError("human dispositions require the dashboard authorization channel")
        return normalized

    @field_validator("authorization_nonce", mode="before")
    @classmethod
    def _validate_authorization_nonce(cls, value: object) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise TypeError("authorization_nonce must be a string")
        return value.strip()

    @field_validator("reason", mode="before")
    @classmethod
    def _redact_reason(cls, value: object) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise TypeError("reason must be a string")
        return redact_text(value.strip())

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @field_validator("project_snapshot", mode="before")
    @classmethod
    def _validate_snapshot(cls, value: object) -> object:
        if isinstance(value, str):
            if not value.strip():
                raise ValueError("project_snapshot must not be empty")
            return value.strip()
        return value

    @field_validator("requested_remediation", mode="before")
    @classmethod
    def _redact_requested_remediation(cls, value: object) -> object:
        if isinstance(value, (str, dict, list, tuple)):
            return redact_value(value)
        return value

    @field_validator("approved_scope", mode="before")
    @classmethod
    def _redact_scope(cls, value: object) -> object:
        if isinstance(value, (dict, list, tuple, str)):
            return redact_value(value)
        return value

    @field_validator("status", mode="before")
    @classmethod
    def _normalise_status(cls, value: object) -> object:
        if value is None:
            return value
        return _normalise_enum(value, ApprovalStatus)

    @field_validator("finding_fingerprint", mode="before")
    @classmethod
    def _normalise_fingerprint(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError("finding_fingerprint must be a non-empty string")
        return value.strip()

    @model_validator(mode="after")
    def _enforce_action_contract(self) -> "ApprovalRecord":
        expected = {
            ApprovalAction.APPROVE_REMEDIATION: ApprovalStatus.APPROVED,
            ApprovalAction.REJECT: ApprovalStatus.REJECTED,
            ApprovalAction.DEFER: ApprovalStatus.DEFERRED,
            ApprovalAction.MARK_FALSE_POSITIVE: ApprovalStatus.FALSE_POSITIVE,
        }[self.action]
        if self.status is None:
            object.__setattr__(self, "status", expected)
        elif self.status not in {expected, ApprovalStatus.PENDING, ApprovalStatus.CONSUMED, ApprovalStatus.EXPIRED}:
            raise ValueError("approval status does not match action")
        if self.action is ApprovalAction.MARK_FALSE_POSITIVE and not self.reason:
            raise ValueError("a reason is required when marking a finding false positive")
        # Scope presence and exact allowed operations are enforced by the
        # workflow service at the point an approval is consumed.  Keeping these
        # fields optional here permits loading historical review records and
        # representing a pending approval before a plan is generated.
        return self

    @property
    def snapshot_hash(self) -> str:
        if isinstance(self.project_snapshot, ProjectSnapshot):
            return self.project_snapshot.content_hash
        return self.project_snapshot

    @property
    def fingerprint(self) -> str | None:
        return self.finding_fingerprint

    @property
    def approved(self) -> bool:
        return self.status in {ApprovalStatus.APPROVED, ApprovalStatus.CONSUMED}

    @property
    def human_authorized(self) -> bool:
        """Whether this record carries the minimum trusted-channel markers.

        This is deliberately not sufficient to create a record: the workflow
        additionally validates its private, one-time dashboard capability and
        the exact audit/finding/snapshot identity.
        """

        return (
            self.actor_type == "human"
            and self.authorization_channel is AuthorizationChannel.DASHBOARD
            and bool(self.authorization_nonce)
        )

    @property
    def resolved(self) -> bool:
        """Approvals never imply resolution; only a re-audit can do that."""

        return False

    def identity(self) -> tuple[str, str, str, str]:
        """Return the stable binding tuple used by workflow lookups."""

        return (
            self.finding_id,
            self.finding_fingerprint or "",
            self.audit_run_id,
            self.snapshot_hash,
        )

    def binds_to(
        self,
        *,
        finding_id: str,
        audit_run_id: str,
        snapshot_hash: str,
        fingerprint: str | None = None,
    ) -> bool:
        if self.finding_id != str(finding_id) or self.audit_run_id != str(audit_run_id):
            return False
        if self.snapshot_hash != str(snapshot_hash):
            return False
        return fingerprint is None or self.finding_fingerprint in {None, str(fingerprint)}


class TimelineEvent(_Phase4Model):
    """One append-only, redacted event in the audit timeline."""

    event_id: str = Field(
        default_factory=lambda: uuid4().hex,
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("event_id", "id"),
    )
    type: TimelineEventType = Field(
        validation_alias=AliasChoices("type", "event_type")
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices("timestamp", "created_at"),
    )
    audit_run_id: str = Field(
        min_length=1,
        max_length=256,
        validation_alias=AliasChoices("audit_run_id", "audit_id"),
    )
    finding_id: str | None = Field(default=None, max_length=256)
    actor: str = Field(default="system", min_length=1, max_length=128)
    summary: str = Field(default="", max_length=4000)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metadata", "details"),
    )

    @field_validator("event_id", "audit_run_id", mode="before")
    @classmethod
    def _validate_ids(cls, value: object, info: Any) -> str:
        return _normalise_id(value, info.field_name)

    @field_validator("finding_id", mode="before")
    @classmethod
    def _validate_finding_id(cls, value: object) -> str | None:
        if value is None:
            return None
        return _normalise_id(value, "finding_id")

    @field_validator("type", mode="before")
    @classmethod
    def _normalise_event_type(cls, value: object) -> object:
        return _normalise_enum(value, TimelineEventType)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value)

    @field_validator("actor", mode="before")
    @classmethod
    def _validate_actor(cls, value: object) -> str:
        return _normalise_id(value, "actor")

    @field_validator("summary", mode="before")
    @classmethod
    def _redact_summary(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("summary must be a string")
        return redact_text(value)

    @field_validator("metadata", mode="before")
    @classmethod
    def _redact_metadata(cls, value: object) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("metadata must be a mapping")
        result = redact_for_persistence(value)
        assert isinstance(result, dict)
        return result

    @property
    def event_type(self) -> TimelineEventType:
        return self.type


__all__ = [
    "ApprovalAction",
    "ApprovalRecord",
    "ApprovalStatus",
    "AuthorizationChannel",
    "FindingStatus",
    "ProjectSnapshot",
    "RemediationPlan",
    "TimelineEvent",
    "TimelineEventType",
]
