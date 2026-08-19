"""Human approval and fail-closed remediation workflow for ReleaseGuard Phase 4."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import re
import threading
from typing import Any, Callable, Iterable, Mapping
from uuid import uuid4

from ..models import AuditResult, Finding, Severity
from ..remediation import FixSafety, classify_fix_safety
from ..scanner import audit_project
from .models import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalStatus,
    FindingStatus,
    ProjectSnapshot,
    RemediationPlan,
)
from .redaction import redact_text
from .snapshots import (
    build_project_snapshot,
    changed_snapshot_files,
    normalize_relative_path,
    snapshot_hash,
    snapshots_match,
)
from .store import EvidenceStore
from .timeline import append_timeline


class WorkflowError(ValueError):
    """Base class for user-correctable workflow failures."""


class FindingNotFound(WorkflowError):
    pass


class InvalidDisposition(WorkflowError):
    pass


class StaleApproval(WorkflowError):
    pass


class ScopeViolation(WorkflowError):
    pass


class ApprovalRequired(WorkflowError):
    pass


HUMAN_AUTHORIZATION_MESSAGE = (
    "Human authorization required.\n"
    "Open ReleaseGuard Dashboard to review this finding."
)


class HumanAuthorizationRequired(WorkflowError):
    """Raised when a caller attempts a human disposition without the Dashboard."""


@dataclass(slots=True)
class _DashboardAuthorization:
    """Private, one-shot capability issued only for a current dashboard action."""

    key: object
    token_identifier: str
    finding_id: str
    fingerprint: str
    audit_run_id: str
    snapshot_hash: str
    action: ApprovalAction
    nonce: str
    consumed: bool = False


@dataclass(slots=True)
class AuditRun:
    audit_run_id: str
    result: AuditResult
    snapshot: ProjectSnapshot
    evidence_directory: Path

    @property
    def findings(self) -> list[Finding]:
        return self.result.findings

    @property
    def release_score(self) -> int:
        return self.result.release_score

    @property
    def release_gate(self) -> Any:
        return self.result.release_gate

    def __getattr__(self, name: str) -> Any:
        # Keeps the wrapper ergonomic for callers that previously consumed an
        # AuditResult directly.
        return getattr(self.result, name)


@dataclass(slots=True)
class RemediationOutcome:
    approval: ApprovalRecord | None
    before_snapshot: ProjectSnapshot
    after_snapshot: ProjectSnapshot
    changed_files: list[str]
    audit_run: AuditRun
    evidence_directory: Path
    resolved: bool
    diff: str

    @property
    def result(self) -> AuditResult:
        return self.audit_run.result


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _dump(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_dump(v) for v in value]
    return value


def _status_value(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()


def _normalise_action(value: str | ApprovalAction) -> ApprovalAction:
    if isinstance(value, ApprovalAction):
        return value
    normalized = str(value).strip().lower().replace("-", "_")
    aliases = {
        "approve": ApprovalAction.APPROVE_REMEDIATION,
        "approve_remediation": ApprovalAction.APPROVE_REMEDIATION,
        "approval": ApprovalAction.APPROVE_REMEDIATION,
        "reject": ApprovalAction.REJECT,
        "defer": ApprovalAction.DEFER,
        "false_positive": ApprovalAction.MARK_FALSE_POSITIVE,
        "mark_false_positive": ApprovalAction.MARK_FALSE_POSITIVE,
    }
    try:
        return aliases[normalized]
    except KeyError:
        raise InvalidDisposition(f"Unsupported review action: {value}.") from None


def _called_from_dashboard() -> bool:
    """Keep the private capability exchange out of ordinary caller APIs."""

    frame = inspect.currentframe()
    try:
        # Skip this helper and the workflow method itself, then inspect the
        # first external frame.  The Dashboard module is the only supported
        # issuer of the in-process capability.
        for _ in range(4):
            frame = frame.f_back if frame is not None else None
            if frame is None:
                return False
            module_name = str(frame.f_globals.get("__name__", ""))
            if module_name != __name__:
                return module_name == "releaseguard.phase4.dashboard"
        return False
    finally:
        del frame


def _finding_id(finding: Finding) -> str:
    """Use the human-facing rule id while retaining the fingerprint binding."""

    return str(getattr(finding, "rule_id", ""))


def _finding_fingerprint(finding: Finding) -> str:
    return str(getattr(finding, "fingerprint", ""))


def _finding_status(finding: Finding) -> str:
    return _status_value(getattr(finding, "status", FindingStatus.OPEN))


def _set_finding_status(finding: Finding, status: str) -> Finding:
    try:
        return finding.model_copy(update={"status": FindingStatus(status)})
    except (AttributeError, TypeError):
        return finding


def _plan_for_finding(finding: Finding) -> RemediationPlan:
    """Create a strict, deterministic Phase 4 scope from one finding."""

    safety = classify_fix_safety(finding)
    target = str(finding.file).replace("\\", "/")
    rule_id = str(finding.rule_id)
    if rule_id == "RG-SECRET-001":
        key_name = str(getattr(finding, "metadata", {}).get("key_name", "API_KEY"))
        key_name = _environment_key(key_name)
        allowed_files = [target]
        if ".env.example" not in allowed_files:
            allowed_files.append(".env.example")
        allowed_operations = [
            "replace the detected literal with a process.env environment reference",
            "add an empty placeholder variable to .env.example",
        ]
        forbidden = [
            "write a real secret to .env or .env.example",
            "print, rotate, or reveal the credential",
            "modify unrelated files or application logic",
        ]
        summary = "Replace the hard-coded credential with an environment variable reference."
        expected = f"The source uses process.env.{key_name}; .env.example contains {key_name}= only."
        risk = "CRITICAL"
    elif rule_id == "RG-DEBUG-001" and getattr(finding, "metadata", {}).get("debug_setting") == "debug_enabled":
        allowed_files = [target]
        allowed_operations = ["change the explicitly enabled DEBUG setting from true to false"]
        forbidden = ["modify unrelated runtime configuration or source files"]
        summary = "Disable the explicitly enabled debug setting."
        expected = "The same DEBUG assignment is false after the change."
        risk = "HIGH"
    else:
        allowed_files = [target]
        allowed_operations = ["apply only the deterministic recommendation for this finding"]
        forbidden = ["modify unrelated files, dependencies, release gate, or finding status"]
        summary = str(getattr(finding, "recommendation", "Review this finding."))
        expected = f"A fresh audit no longer reports {rule_id}."
        severity = _status_value(getattr(finding, "severity", "HIGH"))
        risk = severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "HIGH"

    values = {
        "finding_id": rule_id,
        "fingerprint": _finding_fingerprint(finding),
        "summary": summary,
        "risk": risk,
        "allowed_files": allowed_files,
        "allowed_operations": allowed_operations,
        "forbidden_operations": forbidden,
        "requires_human_approval": True if safety is not FixSafety.SAFE else False,
        "expected_effect": expected,
        "rollback_possible": True,
    }
    try:
        return RemediationPlan(**values)
    except Exception:
        values.pop("fingerprint", None)
        return RemediationPlan(**values)


def _environment_key(value: str) -> str:
    camel = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", camel).strip("_").upper()
    return normalized or "API_KEY"


class ReleaseWorkflow:
    """Single authority for Phase 4 audit, disposition, and remediation actions."""

    def __init__(
        self,
        project_path: str | Path,
        *,
        store: EvidenceStore | None = None,
        audit_function: Callable[..., AuditResult] = audit_project,
        ai_client: Any | None = None,
        ai_timeout_seconds: float = 15.0,
    ) -> None:
        self.project_path = Path(project_path).expanduser().resolve()
        if not self.project_path.exists() or not self.project_path.is_dir():
            raise ValueError(f"Project path is not a directory: {project_path}")
        self.store = store or EvidenceStore(self.project_path)
        self.audit_function = audit_function
        self.ai_client = ai_client
        self.ai_timeout_seconds = ai_timeout_seconds
        self.last_audit_run: AuditRun | None = None
        self._lock = threading.RLock()
        # This identity never crosses the CLI boundary.  DashboardContext
        # receives a short-lived capability carrying this key for one action;
        # caller-provided actor/channel strings are never accepted as proof.
        self._dashboard_capability_key = object()
        self._dashboard_token_secret: bytes | None = None

    # ---- authoritative audit -------------------------------------------------
    def audit(self, *, use_ai: bool = False) -> AuditRun:
        """Run a deterministic audit, persist it, and return its evidence identity."""

        audit_run_id = uuid4().hex
        snapshot = build_project_snapshot(self.project_path)
        kwargs: dict[str, Any] = {"include_remediation_plan": True}
        if use_ai and self.ai_client is not None:
            kwargs.update(ai_client=self.ai_client, ai_timeout_seconds=self.ai_timeout_seconds)
        result = self.audit_function(self.project_path, **kwargs)
        result = self._apply_dispositions(result)
        plans = [_plan_for_finding(finding) for finding in result.findings]
        evidence_directory = self.store.new_evidence_dir()
        payload = result.to_dict()
        payload["audit_run_id"] = audit_run_id
        payload["project_snapshot"] = _dump(snapshot)
        self.store.write_json(evidence_directory, "before.json", _dump(snapshot))
        self.store.write_json(evidence_directory, "audit.json", payload)
        self.store.write_json(evidence_directory, "remediation-plan.json", plans)
        self.store.write_json(evidence_directory, "timeline.json", [])
        record = {
            "audit_run_id": audit_run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "project_snapshot": _dump(snapshot),
            "audit": payload,
            "evidence_directory": str(evidence_directory),
        }
        state = self.store.read_state()
        audits = state.get("audits", [])
        if not isinstance(audits, list):
            audits = []
        audits.append(record)
        state["audits"] = audits
        state["latest_audit"] = record
        state["current_snapshot"] = _dump(snapshot)
        self.store.write_state(state)

        append_timeline(
            self.store,
            "AuditStarted",
            audit_run_id=audit_run_id,
            actor="system",
            summary="ReleaseGuard audit started.",
            evidence_directory=str(evidence_directory),
        )
        if result.ai_review is not None:
            review = result.ai_review
            append_timeline(
                self.store,
                "AIAnalysisCompleted",
                audit_run_id=audit_run_id,
                actor="openvino",
                summary="Advisory local analyzer completed; deterministic policy remains authoritative.",
                metadata={
                    "status": getattr(getattr(review, "status", None), "value", getattr(review, "status", "unknown")),
                    "device": getattr(review, "device", None),
                    "model_id": getattr(review, "model_id", None),
                },
                evidence_directory=str(evidence_directory),
            )
        for finding in result.findings:
            append_timeline(
                self.store,
                "FindingDetected",
                audit_run_id=audit_run_id,
                finding_id=_finding_id(finding),
                actor="system",
                summary=f"{_finding_id(finding)} detected ({finding.severity.value.upper()}).",
                metadata={"fingerprint": _finding_fingerprint(finding), "file": finding.file, "line": finding.line},
                evidence_directory=str(evidence_directory),
            )
            if _finding_status(finding) == "NEEDS_REVIEW":
                append_timeline(
                    self.store,
                    "HumanReviewRequested",
                    audit_run_id=audit_run_id,
                    finding_id=_finding_id(finding),
                    actor="policy",
                    summary=f"{_finding_id(finding)} requires human review.",
                    metadata={"severity": finding.severity.value.upper()},
                    evidence_directory=str(evidence_directory),
                )
        append_timeline(
            self.store,
            "GateCalculated",
            audit_run_id=audit_run_id,
            actor="policy",
            summary=f"Score {result.release_score}/100; gate {result.release_gate.value}.",
            metadata={"score": result.release_score, "gate": result.release_gate.value},
            evidence_directory=str(evidence_directory),
        )
        run = AuditRun(audit_run_id, result, snapshot, evidence_directory)
        self.last_audit_run = run
        return run

    audit_and_record = audit
    run_audit = audit

    def _apply_dispositions(self, result: AuditResult) -> AuditResult:
        state = self.store.read_state()
        dispositions = state.get("dispositions", {})
        if not isinstance(dispositions, dict):
            dispositions = {}
        findings: list[Finding] = []
        for finding in result.findings:
            previous = dispositions.get(_finding_fingerprint(finding))
            if previous:
                status = _status_value(previous)
                # An approval is consumed by a new audit if the issue remains.
                if status == "APPROVED":
                    status = "NEEDS_REVIEW"
            elif finding.severity is Severity.CRITICAL:
                status = "NEEDS_REVIEW"
            else:
                status = "OPEN"
            findings.append(_set_finding_status(finding, status))
        return result.model_copy(update={"findings": findings})

    # ---- finding lookup and dispositions ------------------------------------
    def latest_run(self) -> AuditRun:
        if self.last_audit_run is not None:
            return self.last_audit_run
        latest = self.store.latest_audit()
        if not latest:
            raise WorkflowError("No audit is available; run `releaseguard audit` first.")
        try:
            audit_payload = dict(latest["audit"])
            # These binding fields live beside the legacy AuditResult contract
            # in Phase 4 state and must not be fed into its extra-forbid model.
            audit_payload.pop("audit_run_id", None)
            audit_payload.pop("project_snapshot", None)
            result = AuditResult.model_validate(audit_payload)
            snapshot = ProjectSnapshot.model_validate(latest["project_snapshot"])
            return AuditRun(
                str(latest["audit_run_id"]),
                result,
                snapshot,
                Path(str(latest.get("evidence_directory", self.store.root))),
            )
        except Exception as error:
            raise WorkflowError("The latest ReleaseGuard audit evidence is invalid.") from error

    def find_finding(self, identifier: str, run: AuditRun | None = None) -> Finding:
        candidate = run or self.latest_run()
        needle = str(identifier).strip()
        matches = [
            finding
            for finding in candidate.result.findings
            if needle in {_finding_id(finding), _finding_fingerprint(finding), str(getattr(finding, "finding_id", ""))}
        ]
        if not matches:
            raise FindingNotFound(f"Finding '{needle}' was not found in the latest audit.")
        if len(matches) > 1 and needle in {_finding_id(item) for item in matches}:
            raise FindingNotFound("Finding id is ambiguous; use its fingerprint.")
        return matches[0]

    def review(self, identifier: str | None = None) -> list[Finding] | Finding:
        run = self.latest_run()
        pending = [
            finding
            for finding in run.result.findings
            if _finding_status(finding) in {"OPEN", "NEEDS_REVIEW", "DEFERRED", "REJECTED"}
        ]
        return self.find_finding(identifier, run) if identifier else pending

    def _bind_dashboard_secret(self, secret: bytes) -> None:
        """Attach the ephemeral secret owned by one loopback Dashboard server."""

        if not _called_from_dashboard():
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        with self._lock:
            # A new workflow normally gets one Dashboard session.  Refusing a
            # silent replacement prevents a shell caller from swapping in its
            # own key after a real server has been established.
            if self._dashboard_token_secret is not None and self._dashboard_token_secret != secret:
                raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
            self._dashboard_token_secret = secret

    def _authorize_dashboard_action(
        self,
        identifier: str,
        action: str,
        *,
        nonce: str,
    ) -> _DashboardAuthorization:
        """Issue a capability bound to the currently persisted audit identity.

        The method is intentionally private and is called by the loopback
        Dashboard adapter.  It does not accept an actor string as authority;
        the capability is tied to the exact finding, fingerprint, run, and
        snapshot resolved here.
        """

        if not _called_from_dashboard():
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        if not isinstance(nonce, str) or not nonce.strip():
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        normalized = _normalise_action(action)
        run = self.latest_run()
        finding = self.find_finding(identifier, run)
        if _finding_status(finding) in {"RESOLVED", "FALSE_POSITIVE"}:
            raise InvalidDisposition(f"Finding {finding.rule_id} is already {_finding_status(finding)}.")
        # A review decision must describe the source tree the reviewer saw.
        if not snapshots_match(run.snapshot, build_project_snapshot(self.project_path)):
            raise StaleApproval("The project changed after the audit; run a fresh review.")
        secret = self._dashboard_token_secret
        if secret is None:
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        message = "\x00".join(
            (
                str(identifier),
                str(action).strip().lower().replace("-", "_"),
                run.audit_run_id,
                run.snapshot.content_hash,
                _finding_fingerprint(finding),
            )
        ).encode("utf-8", errors="replace")
        expected_token = hmac.new(secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_token, nonce.strip()):
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        return _DashboardAuthorization(
            key=self._dashboard_capability_key,
            token_identifier=str(identifier),
            finding_id=_finding_id(finding),
            fingerprint=_finding_fingerprint(finding),
            audit_run_id=run.audit_run_id,
            snapshot_hash=run.snapshot.content_hash,
            action=normalized,
            nonce=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        )

    def _record_dashboard_action(
        self,
        authorization: _DashboardAuthorization,
        *,
        reason: str = "",
        approved_scope: Mapping[str, Any] | None = None,
    ) -> ApprovalRecord:
        """Consume one private Dashboard capability and create its record."""

        if not isinstance(authorization, _DashboardAuthorization):
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        with self._lock:
            record = self._record_disposition(
                authorization.finding_id,
                action=authorization.action,
                reason=reason,
                actor="human",
                approved_scope=approved_scope,
                authorization=authorization,
            )
            authorization.consumed = True
            return record

    def approve(
        self,
        identifier: str,
        *,
        reason: str = "",
        actor: str = "human",
        approved_scope: Mapping[str, Any] | None = None,
    ) -> ApprovalRecord:
        return self._record_disposition(
            identifier,
            action=ApprovalAction.APPROVE_REMEDIATION,
            reason=reason,
            actor=actor,
            approved_scope=approved_scope,
        )

    def reject(self, identifier: str, *, reason: str = "", actor: str = "human") -> ApprovalRecord:
        return self._record_disposition(identifier, action=ApprovalAction.REJECT, reason=reason, actor=actor)

    def defer(self, identifier: str, *, reason: str = "", actor: str = "human") -> ApprovalRecord:
        return self._record_disposition(identifier, action=ApprovalAction.DEFER, reason=reason, actor=actor)

    def false_positive(self, identifier: str, *, reason: str, actor: str = "human") -> ApprovalRecord:
        if not str(reason).strip():
            raise InvalidDisposition("false-positive requires a non-empty reason")
        return self._record_disposition(
            identifier,
            action=ApprovalAction.MARK_FALSE_POSITIVE,
            reason=reason,
            actor=actor,
        )

    mark_false_positive = false_positive

    def _record_disposition(
        self,
        identifier: str,
        *,
        action: ApprovalAction,
        reason: str,
        actor: str,
        approved_scope: Mapping[str, Any] | None = None,
        authorization: _DashboardAuthorization | None = None,
    ) -> ApprovalRecord:
        run = self.latest_run()
        finding = self.find_finding(identifier, run)
        if not self._valid_dashboard_authorization(authorization, finding, run, action):
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        current_status = _finding_status(finding)
        if current_status in {"RESOLVED", "FALSE_POSITIVE"}:
            raise InvalidDisposition(f"Finding {finding.rule_id} is already {current_status}.")
        state = self.store.read_state()
        used_nonces = state.get("used_authorization_nonces", [])
        if not isinstance(used_nonces, list):
            used_nonces = []
        if authorization is None or authorization.nonce in {str(item) for item in used_nonces}:
            raise HumanAuthorizationRequired(HUMAN_AUTHORIZATION_MESSAGE)
        plan = _plan_for_finding(finding)
        if action is ApprovalAction.APPROVE_REMEDIATION:
            scope = _normalize_scope(approved_scope or _plan_scope(plan))
            _validate_approved_scope(scope, plan)
        else:
            scope = {}
        target_status = {
            ApprovalAction.APPROVE_REMEDIATION: "APPROVED",
            ApprovalAction.REJECT: "REJECTED",
            ApprovalAction.DEFER: "DEFERRED",
            ApprovalAction.MARK_FALSE_POSITIVE: "FALSE_POSITIVE",
        }[action]
        approval_id = uuid4().hex
        values = {
            "approval_id": approval_id,
            "finding_id": _finding_id(finding),
            "fingerprint": _finding_fingerprint(finding),
            "action": action,
            "actor": "human",
            "actor_type": "human",
            "authorization_channel": "dashboard",
            "authorization_nonce": authorization.nonce,
            "reason": reason or "",
            "timestamp": datetime.now(timezone.utc),
            "audit_run_id": run.audit_run_id,
            "project_snapshot": run.snapshot,
            "requested_remediation": plan.summary,
            "approved_scope": scope,
            "status": target_status,
        }
        # Do not fall back to a record without its finding fingerprint.  That
        # would turn a display rule id into a reusable approval authority.
        record = ApprovalRecord(**values)

        evidence_directory = self.store.new_evidence_dir()
        self.store.write_json(evidence_directory, "before.json", _dump(run.snapshot))
        self.store.write_json(evidence_directory, "approval.json", record)
        self.store.write_json(evidence_directory, "remediation-plan.json", plan)
        self.store.write_json(evidence_directory, "audit.json", run.result)
        self.store.write_json(evidence_directory, "timeline.json", [])
        approvals = state.get("approvals", [])
        if not isinstance(approvals, list):
            approvals = []
        approval_payload = _dump(record)
        approval_payload["evidence_directory"] = str(evidence_directory)
        approval_payload["evidence_id"] = evidence_directory.name
        approvals.append(approval_payload)
        state["approvals"] = approvals
        dispositions = state.get("dispositions", {})
        if not isinstance(dispositions, dict):
            dispositions = {}
        dispositions[_finding_fingerprint(finding)] = target_status
        state["dispositions"] = dispositions
        used_nonces.append(authorization.nonce)
        state["used_authorization_nonces"] = used_nonces
        issued = state.get("issued_authorizations", {})
        if not isinstance(issued, dict):
            issued = {}
        issued[authorization.nonce] = {
            "finding_id": _finding_id(finding),
            "finding_fingerprint": _finding_fingerprint(finding),
            "audit_run_id": run.audit_run_id,
            "snapshot_hash": run.snapshot.content_hash,
            "action": action.value,
        }
        state["issued_authorizations"] = issued
        self._update_latest_finding_status(
            run,
            finding,
            target_status,
            state=state,
        )
        self.store.write_state(state)
        event_name = {
            ApprovalAction.APPROVE_REMEDIATION: "RemediationApproved",
            ApprovalAction.REJECT: "RemediationRejected",
            ApprovalAction.DEFER: "RemediationDeferred",
            ApprovalAction.MARK_FALSE_POSITIVE: "HumanReviewRequested",
        }[action]
        append_timeline(
            self.store,
            event_name,
            audit_run_id=run.audit_run_id,
            finding_id=_finding_id(finding),
            actor="human",
            summary=f"{event_name} recorded for {_finding_id(finding)}.",
            metadata={
                "approval_id": approval_id,
                "status": target_status,
                "actor_type": "human",
                "authorization_channel": "dashboard",
            },
            evidence_directory=str(evidence_directory),
        )
        return record

    def _valid_dashboard_authorization(
        self,
        authorization: _DashboardAuthorization | None,
        finding: Finding,
        run: AuditRun,
        action: ApprovalAction,
    ) -> bool:
        if not isinstance(authorization, _DashboardAuthorization):
            return False
        if authorization.key is not self._dashboard_capability_key or authorization.consumed:
            return False
        if authorization.action is not action:
            return False
        if authorization.finding_id != _finding_id(finding):
            return False
        if authorization.fingerprint != _finding_fingerprint(finding):
            return False
        if authorization.audit_run_id != run.audit_run_id:
            return False
        if authorization.snapshot_hash != run.snapshot.content_hash:
            return False
        if not authorization.nonce:
            return False
        return True

    def _update_latest_finding_status(
        self,
        run: AuditRun,
        finding: Finding,
        status: str,
        *,
        state: dict[str, Any],
    ) -> None:
        """Reflect a human disposition in the current view without touching gate."""

        updated = [_set_finding_status(item, status) if _same_finding(finding, item) else item for item in run.result.findings]
        run.result = run.result.model_copy(update={"findings": updated})
        latest = state.get("latest_audit")
        if isinstance(latest, dict) and isinstance(latest.get("audit"), dict):
            latest["audit"] = run.result.to_dict()
            state["latest_audit"] = latest
        # Keep the in-memory evidence audit safe and consistent for dashboard
        # consumers that read the latest action directory directly.
        try:
            self.store.write_json(run.evidence_directory, "audit.json", run.result)
        except (OSError, ValueError):
            pass

    # ---- bounded remediation -------------------------------------------------
    def remediate(
        self,
        identifier: str,
        *,
        executor: Callable[..., Any] | None = None,
        use_ai: bool = False,
    ) -> RemediationOutcome:
        with self._lock:
            return self._remediate_unlocked(
                identifier,
                executor=executor,
                use_ai=use_ai,
            )

    def _remediate_unlocked(
        self,
        identifier: str,
        *,
        executor: Callable[..., Any] | None = None,
        use_ai: bool = False,
    ) -> RemediationOutcome:
        run = self.latest_run()
        finding = self.find_finding(identifier, run)
        plan = _plan_for_finding(finding)
        # SAFE plans retain the Phase 3 executor path and do not fabricate a
        # human ApprovalRecord.  Every review-required plan still needs the
        # exact Dashboard-issued approval below.
        approval: ApprovalRecord | None = (
            self._bound_remediation_approval(finding, run)
            if plan.requires_human_approval
            else None
        )
        approved_snapshot = _snapshot_from_record(approval) if approval is not None else run.snapshot
        current_snapshot = build_project_snapshot(self.project_path)
        if not snapshots_match(approved_snapshot, current_snapshot):
            directory = self.store.record_action(
                artifacts={
                    "before.json": _dump(approved_snapshot),
                    "audit.json": run.result,
                    "approval.json": approval,
                    "timeline.json": [],
                    "error.json": {"error": "stale_approval", "message": "Project snapshot changed after approval."},
                }
            )
            append_timeline(
                self.store,
                "RemediationStarted",
                audit_run_id=run.audit_run_id,
                finding_id=_finding_id(finding),
                actor="system",
                summary="Remediation aborted because approval snapshot is stale.",
                metadata={"error": "stale_approval"},
                evidence_directory=str(directory),
            )
            raise StaleApproval("Approval was created for an older project snapshot; review the finding again.")

        approved_scope = getattr(approval, "approved_scope", None) if approval is not None else _plan_scope(plan)
        _validate_approved_scope(_normalize_scope(approved_scope or {}), plan)
        append_timeline(
            self.store,
            "RemediationStarted",
            audit_run_id=run.audit_run_id,
            finding_id=_finding_id(finding),
            actor="agent",
            summary=f"Bounded remediation started for {_finding_id(finding)}.",
            metadata={
                "approval_id": approval.approval_id if approval is not None else "safe-policy",
                "authorization_channel": "dashboard" if approval is not None else "safe-policy",
            },
        )
        # Capture every approved path, including an absent `.env.example`, so
        # the evidence diff records additions as well as edits.
        before_files = {
            path: (
                (self.project_path / Path(path)).read_text(encoding="utf-8", errors="replace")
                if (self.project_path / Path(path)).is_file()
                else ""
            )
            for path in _plan_files(plan)
        }
        if executor is None:
            self._execute_builtin(finding, plan)
        else:
            _invoke_executor(executor, self.project_path, finding, plan)
        after_snapshot = build_project_snapshot(self.project_path)
        changed = sorted(changed_snapshot_files(current_snapshot, after_snapshot), key=str.casefold)
        allowed_files = set(_plan_files(plan))
        if not set(changed).issubset(allowed_files):
            diff = self._diff_for_files(before_files)
            directory = self.store.record_action(
                artifacts={
                    "before.json": _dump(current_snapshot),
                    "after.json": _dump(after_snapshot),
                    "approval.json": approval,
                    "audit.json": run.result,
                    "timeline.json": [],
                    "error.json": {"error": "scope_violation", "changed_files": changed},
                },
                text_artifacts={"diff.patch": diff},
            )
            raise ScopeViolation("Remediation changed files outside the approved scope.")
        diff = self._diff_for_files(before_files)
        _validate_operations(diff, plan)

        directory = self.store.record_action(
            artifacts={
                "before.json": _dump(current_snapshot),
                "after.json": _dump(after_snapshot),
                "approval.json": approval,
                "remediation-plan.json": plan,
                "timeline.json": [],
            },
            text_artifacts={"diff.patch": diff},
        )
        append_timeline(
            self.store,
            "FileChanged",
            audit_run_id=run.audit_run_id,
            finding_id=_finding_id(finding),
            actor="agent",
            summary=f"Approved files changed: {len(changed)}.",
            metadata={"changed_files": changed},
            evidence_directory=str(directory),
        )
        append_timeline(
            self.store,
            "ReauditStarted",
            audit_run_id=run.audit_run_id,
            finding_id=_finding_id(finding),
            actor="policy",
            summary="A fresh deterministic re-audit is required after remediation.",
        )
        after_run = self.audit(use_ai=use_ai)
        if approval is not None:
            approval = self._consume_approval(approval)
        append_timeline(
            self.store,
            "RemediationCompleted",
            audit_run_id=after_run.audit_run_id,
            finding_id=_finding_id(finding),
            actor="agent",
            summary="Approved remediation completed and was re-audited.",
            metadata={"changed_files": changed},
            evidence_directory=str(directory),
        )
        resolved = not any(
            _same_finding(finding, candidate) for candidate in after_run.result.findings
        )
        if resolved:
            state = self.store.read_state()
            dispositions = state.get("dispositions", {})
            if not isinstance(dispositions, dict):
                dispositions = {}
            dispositions[_finding_fingerprint(finding)] = "RESOLVED"
            state["dispositions"] = dispositions
            self.store.write_state(state)
            append_timeline(
                self.store,
                "FindingResolved",
                audit_run_id=after_run.audit_run_id,
                finding_id=_finding_id(finding),
                actor="policy",
                summary=f"{_finding_id(finding)} resolved by a fresh deterministic re-audit.",
            )
        else:
            append_timeline(
                self.store,
                "FindingStillPresent",
                audit_run_id=after_run.audit_run_id,
                finding_id=_finding_id(finding),
                actor="policy",
                summary=f"{_finding_id(finding)} remains after re-audit.",
            )
        return RemediationOutcome(
            approval=approval,
            before_snapshot=current_snapshot,
            after_snapshot=after_snapshot,
            changed_files=changed,
            audit_run=after_run,
            evidence_directory=directory,
            resolved=resolved,
            diff=diff,
        )

    def _bound_remediation_approval(self, finding: Finding, run: AuditRun) -> ApprovalRecord:
        """Load only a fresh, dashboard-issued approval for this exact finding."""

        state = self.store.read_state()
        used_nonces = {
            str(item)
            for item in state.get("used_authorization_nonces", [])
            if isinstance(item, str)
        }
        issued = state.get("issued_authorizations", {})
        if not isinstance(issued, dict):
            issued = {}
        approvals = state.get("approvals", [])
        if not isinstance(approvals, list):
            approvals = []
        for payload in reversed(approvals):
            if not isinstance(payload, dict):
                continue
            values = dict(payload)
            values.pop("evidence_directory", None)
            evidence_id = str(values.pop("evidence_id", ""))
            try:
                approval = ApprovalRecord.model_validate(values)
            except Exception:
                continue
            if approval.action is not ApprovalAction.APPROVE_REMEDIATION:
                continue
            if approval.status is not ApprovalStatus.APPROVED:
                continue
            if not approval.human_authorized:
                continue
            if not approval.finding_fingerprint or approval.finding_fingerprint != _finding_fingerprint(finding):
                continue
            if approval.finding_id != _finding_id(finding):
                continue
            if approval.audit_run_id != run.audit_run_id:
                continue
            if not approval.authorization_nonce or approval.authorization_nonce not in used_nonces:
                continue
            issued_identity = issued.get(approval.authorization_nonce)
            if not isinstance(issued_identity, dict):
                continue
            expected_identity = {
                "finding_id": approval.finding_id,
                "finding_fingerprint": approval.finding_fingerprint,
                "audit_run_id": approval.audit_run_id,
                "snapshot_hash": approval.snapshot_hash,
                "action": approval.action.value,
            }
            if any(str(issued_identity.get(key, "")) != str(value) for key, value in expected_identity.items()):
                continue
            # A state entry is consumable only when its append-only approval
            # artifact exists and carries the same identity.  This prevents a
            # caller from hand-writing a plausible ApprovalRecord into state.
            if not re.fullmatch(r"[0-9a-fA-F]{32}", evidence_id):
                continue
            try:
                artifact = self.store.read_json(self.store.root / evidence_id / "approval.json")
                if not isinstance(artifact, dict):
                    continue
                artifact_values = dict(artifact)
                artifact_values.pop("evidence_directory", None)
                artifact_values.pop("evidence_id", None)
                artifact_record = ApprovalRecord.model_validate(artifact_values)
                if artifact_record.identity() != approval.identity():
                    continue
            except Exception:
                continue
            try:
                approved_snapshot = _snapshot_from_record(approval)
            except Exception:
                continue
            if not snapshots_match(approved_snapshot, run.snapshot):
                continue
            return approval
        raise ApprovalRequired(f"Finding {finding.rule_id} has no valid human remediation approval.")

    def _consume_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        """Mark a remediation authorization consumed after successful re-audit."""

        consumed = approval.model_copy(update={"status": ApprovalStatus.CONSUMED})
        state = self.store.read_state()
        approvals = state.get("approvals", [])
        if isinstance(approvals, list):
            for index, payload in enumerate(approvals):
                if not isinstance(payload, dict):
                    continue
                if str(payload.get("approval_id", "")) == approval.approval_id:
                    updated = dict(payload)
                    updated["status"] = ApprovalStatus.CONSUMED.value
                    approvals[index] = updated
                    break
            state["approvals"] = approvals
        self.store.write_state(state)
        return consumed

    execute_remediation = remediate

    def _execute_builtin(self, finding: Finding, plan: RemediationPlan) -> None:
        rule_id = str(finding.rule_id)
        # Path construction is followed by a strict relative check so a malformed
        # finding cannot escape the project root.
        target = self.project_path / Path(str(finding.file).replace("/", "\\"))
        try:
            target = target.resolve(strict=True)
            target.relative_to(self.project_path)
        except (OSError, ValueError):
            raise ScopeViolation("Finding target is outside the project root.") from None
        if rule_id == "RG-DEBUG-001":
            original = target.read_text(encoding="utf-8")
            updated, count = re.subn(r"(\bDEBUG\s*=\s*)true\b", r"\1false", original, count=1, flags=re.IGNORECASE)
            if count != 1:
                raise WorkflowError("The approved DEBUG assignment is no longer present.")
            target.write_text(updated, encoding="utf-8")
            return
        if rule_id == "RG-SECRET-001":
            self._migrate_secret(target, finding, plan)
            return
        raise WorkflowError(f"No deterministic remediation is registered for {rule_id}.")

    def _migrate_secret(self, target: Path, finding: Finding, plan: RemediationPlan) -> None:
        original = target.read_text(encoding="utf-8")
        key_hint = str(getattr(finding, "metadata", {}).get("key_name", "API_KEY"))
        pattern = re.compile(
            r"(?P<prefix>(?:(?:export|const|let|var)\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(?P<quote>[\"'`])(?P<value>[^\"'`\r\n]+)(?P=quote)"
        )
        matches = list(pattern.finditer(original))
        selected = None
        for match in matches:
            key = match.group("key")
            if key.casefold() == key_hint.casefold() or _looks_secret_literal(match.group("value")):
                selected = match
                break
        if selected is None:
            raise WorkflowError("The approved credential literal is no longer present.")
        key = _environment_key(key_hint if key_hint else selected.group("key"))
        replacement = f"{selected.group('prefix')}process.env.{key}"
        updated = original[: selected.start()] + replacement + original[selected.end() :]
        target.write_text(updated, encoding="utf-8")
        example = self.project_path / ".env.example"
        if ".env.example" in _plan_files(plan):
            existing = example.read_text(encoding="utf-8") if example.exists() else ""
            if not re.search(rf"(?m)^\s*{re.escape(key)}\s*=", existing):
                suffix = "" if not existing or existing.endswith("\n") else "\n"
                example.write_text(existing + suffix + f"{key}=\n", encoding="utf-8")

    def _diff_for_files(self, before_files: Mapping[str, str]) -> str:
        chunks: list[str] = []
        paths = set(before_files)
        for path in sorted(paths, key=str.casefold):
            before = before_files.get(path, "")
            target = self.project_path / Path(path)
            after = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
            if before == after:
                continue
            chunks.extend(
                difflib.unified_diff(
                    before.splitlines(keepends=True),
                    after.splitlines(keepends=True),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                )
            )
        return redact_text("".join(chunks))


def _snapshot_from_record(record: ApprovalRecord) -> ProjectSnapshot:
    value = getattr(record, "project_snapshot", None)
    if isinstance(value, ProjectSnapshot):
        return value
    return ProjectSnapshot.model_validate(value)


def _plan_scope(plan: RemediationPlan) -> dict[str, Any]:
    return {
        "allowed_files": list(getattr(plan, "allowed_files", [])),
        "allowed_operations": list(getattr(plan, "allowed_operations", [])),
        "forbidden_operations": list(getattr(plan, "forbidden_operations", [])),
    }


def _normalize_scope(scope: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(scope)
    files = normalized.get("allowed_files", [])
    if isinstance(files, str):
        files = [files]
    normalized["allowed_files"] = [normalize_relative_path(item) for item in files]
    for key in ("allowed_operations", "forbidden_operations"):
        value = normalized.get(key, [])
        normalized[key] = [str(item) for item in ([value] if isinstance(value, str) else value)]
    return normalized


def _validate_approved_scope(scope: Mapping[str, Any], plan: RemediationPlan) -> None:
    expected = _normalize_scope(_plan_scope(plan))
    actual = _normalize_scope(scope)
    if not set(actual["allowed_files"]).issubset(set(expected["allowed_files"])):
        raise ScopeViolation("Approved files exceed the remediation plan scope.")
    if not set(actual["allowed_operations"]).issubset(set(expected["allowed_operations"])):
        raise ScopeViolation("Approved operations exceed the remediation plan scope.")
    if set(actual["forbidden_operations"]) != set(expected["forbidden_operations"]):
        raise ScopeViolation("Forbidden operations cannot be weakened.")


def _plan_files(plan: RemediationPlan) -> list[str]:
    return [normalize_relative_path(item) for item in getattr(plan, "allowed_files", [])]


def _validate_operations(diff: str, plan: RemediationPlan) -> None:
    lowered = diff.lower()
    forbidden = [str(item).lower() for item in getattr(plan, "forbidden_operations", [])]
    if ".env" in lowered and "real secret" in lowered:
        raise ScopeViolation("Diff attempts to write a real secret into environment files.")
    if any(token in lowered for token in ("package.json", "pyproject.toml", "readme.md", "releaseguard")):
        raise ScopeViolation("Diff contains an unrelated project operation.")
    # A raw credential should have been redacted before this point; reject a
    # suspicious high-entropy assignment as an additional fail-closed guard.
    if re.search(r"(?i)(?:api[_-]?key|token|secret|password)\s*=\s*['\"][^'\"]{12,}['\"]", diff):
        raise ScopeViolation("Diff contains a credential literal.")
    if any("delete" in item and ("delete" in lowered or "remove" in lowered) for item in forbidden):
        raise ScopeViolation("Diff contains a forbidden deletion operation.")


def _invoke_executor(executor: Callable[..., Any], project: Path, finding: Finding, plan: RemediationPlan) -> Any:
    for args in ((project, finding, plan), (project, plan), (plan,), ()):
        try:
            return executor(*args)
        except TypeError:
            continue
    raise WorkflowError("The remediation executor has an unsupported signature.")


def _all_relative_files(root: Path) -> Iterable[str]:
    for path in root.rglob("*"):
        if not path.is_file() or ".releaseguard" in path.parts:
            continue
        try:
            yield path.relative_to(root).as_posix()
        except ValueError:
            continue


def _looks_secret_literal(value: str) -> bool:
    if len(value) < 8:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in ("example", "placeholder", "changeme", "your_")):
        return False
    return bool(re.search(r"[A-Za-z]", value) and re.search(r"[0-9_\-]", value))


def _same_finding(before: Finding, after: Finding) -> bool:
    if _finding_fingerprint(before) == _finding_fingerprint(after):
        return True
    return (
        str(before.rule_id) == str(after.rule_id)
        and str(before.file).replace("\\", "/") == str(after.file).replace("\\", "/")
        and before.line == after.line
    )


def plan_for_finding(finding: Finding) -> RemediationPlan:
    return _plan_for_finding(finding)


__all__ = [
    "ApprovalRequired",
    "AuditRun",
    "FindingNotFound",
    "HUMAN_AUTHORIZATION_MESSAGE",
    "HumanAuthorizationRequired",
    "InvalidDisposition",
    "ReleaseWorkflow",
    "RemediationOutcome",
    "ScopeViolation",
    "StaleApproval",
    "WorkflowError",
    "plan_for_finding",
]
