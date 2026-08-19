"""Small local dashboard for the Phase 4 human-in-the-loop workflow.

The dashboard deliberately has very few assumptions about the Phase 4 workflow
and evidence store.  Those modules are optional at import time so the existing
Phase 1-3 package remains usable while Phase 4 is assembled.  A context object
adapts common read-only provider method names and keeps all mutations behind the
workflow service.

Only the standard library is used here.  The HTTP server is always bound to the
loopback address by :func:`create_server`; callers must opt in to a different
networking design outside this module rather than accidentally exposing audit
evidence on a LAN.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, is_dataclass, asdict
from enum import Enum
import hashlib
import hmac
import html
import inspect
import json
from pathlib import Path
import re
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

try:  # Optional at import time for lightweight/stubbed test environments.
    from ..ai.service import LocalServerManager as LocalServerManager
except Exception:  # pragma: no cover - exercised only in minimal installs
    LocalServerManager = None  # type: ignore[assignment,misc]


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_PREVIEW_LENGTH = 320
MAX_RESPONSE_BYTES = 2_000_000


class DashboardActionError(ValueError):
    """A safe, client-facing error raised while handling a review action."""

    def __init__(self, message: str, *, status: int = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(message)
        self.status = int(status)


def _jsonable(value: Any) -> Any:
    """Convert common model/container values to JSON-compatible primitives."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _jsonable(model_dump(mode="json"))
        except TypeError:
            try:
                return _jsonable(model_dump())
            except Exception:
                pass
        except Exception:
            pass
    if is_dataclass(value):
        try:
            return _jsonable(asdict(value))
        except Exception:
            pass
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    # A small fallback for SimpleNamespace-style test doubles and provider
    # objects.  Private attributes are intentionally excluded.
    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        return {
            str(key): _jsonable(item)
            for key, item in attributes.items()
            if not str(key).startswith("_")
        }
    return str(value)


_TOKEN_RE = re.compile(
    r"(?i)\b(?:sk|rk|pk|ghp|gho|ghs|glpat|xox[baprs])-[A-Za-z0-9_\-]{8,}\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:.|\n)*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|credential)\b\s*[:=]\s*[\"']?)([^\s\"'`,;}\]]{6,})"
)
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:secret|password|passwd|credential|token|api[_-]?key|private[_-]?key)"
)


def _mask_literal(match: re.Match[str]) -> str:
    value = match.group(0)
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[: max(2, len(value) // 4)]}****{value[-4:]}"


def _redact_text(value: Any) -> str:
    """Return bounded display text with credential-like literals removed.

    Phase 4's central redaction helper is used when it is available.  The local
    fallback is intentionally conservative so dashboard import and rendering do
    not fail while that optional module is being developed.
    """

    text = str(value)
    # ReleaseGuard rule/audit identifiers are safe metadata, not credentials.
    # The generic Phase 4 assignment redactor intentionally errs on the side
    # of masking strings such as ``SECRET-001``; preserve these bounded IDs so
    # reviewers can still correlate a dashboard action with a finding.
    if re.fullmatch(r"RG-[A-Za-z0-9_.:-]{1,255}", text) or re.fullmatch(
        r"[0-9a-fA-F]{64}", text
    ):
        return text
    try:
        from .redaction import redact_text  # type: ignore

        redacted = redact_text(text)
        if isinstance(redacted, str):
            return redacted
    except Exception:
        pass
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _TOKEN_RE.sub(_mask_literal, text)
    text = _ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return text


def _safe_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact provider payloads before they reach HTML or JSON."""

    if key is not None and key.lower() in {
        "rule_id",
        "finding_id",
        "action_id",
        "fingerprint",
        "audit_run_id",
        "approval_id",
        "event_id",
    }:
        return value if value is None else str(value)
    if key is not None and _SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): _safe_value(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_value(item) for item in value]
    if isinstance(value, (str, Path)):
        rendered = _redact_text(value)
        # Evidence/preview fields are untrusted source excerpts.  If a compact
        # credential-like literal survives format redaction (for example a
        # project-specific fixture token), hide the whole literal rather than
        # risk displaying it as a dashboard preview.
        if key is not None and key.lower() in {"evidence", "preview", "safe_preview"}:
            if rendered == str(value) and re.fullmatch(r"[A-Za-z0-9_\-]{12,}", rendered):
                return "[REDACTED_SECRET]"
        return rendered
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_value(_jsonable(value), key=key)


def _safe_json(value: Any) -> str:
    return json.dumps(_safe_value(_jsonable(value)), ensure_ascii=False, sort_keys=True)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return _redact_text(value)


def _first(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _mapping(value: Any) -> dict[str, Any]:
    converted = _jsonable(value)
    return dict(converted) if isinstance(converted, Mapping) else {}


def _unwrap_audit(value: Any) -> Any:
    """Unwrap workflow/store records to the actual audit result payload."""

    # ReleaseWorkflow.latest_run() returns an AuditRun whose authoritative
    # result is exposed as ``result``.  EvidenceStore.latest_audit() returns a
    # state record with an ``audit`` member.  Accept both shapes (and one level
    # of nested wrappers) without coupling the dashboard to either class.
    current = value
    for _ in range(2):
        mapping = _mapping(current)
        if "audit" in mapping and isinstance(mapping["audit"], (Mapping, list, tuple)):
            current = mapping["audit"]
            continue
        if "result" in mapping and isinstance(mapping["result"], (Mapping, list, tuple)):
            current = mapping["result"]
            continue
        result = getattr(current, "result", None)
        if result is not None and result is not current:
            current = result
            continue
        break
    return current


def _call_read(provider: Any, names: Sequence[str], project_path: Path) -> Any:
    """Call one of a provider's conventional read-only methods.

    Providers in early Phase 4 iterations used both ``latest_audit()`` and
    ``load_latest_audit(project_path)``.  Signature inspection keeps this
    adapter tolerant without invoking arbitrary methods or swallowing provider
    errors as successful data.
    """

    if provider is None:
        return None
    for name in names:
        candidate = getattr(provider, name, None)
        if not callable(candidate):
            continue
        try:
            signature = inspect.signature(candidate)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind
                in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            required = [
                parameter
                for parameter in positional
                if parameter.default is inspect.Parameter.empty
            ]
            if required:
                result = candidate(project_path)
            else:
                result = candidate()
            return result
        except (TypeError, ValueError):
            # Some C-extension/test doubles do not expose a signature.  A
            # no-argument call is the least surprising fallback.
            try:
                return candidate()
            except Exception:
                continue
        except Exception:
            continue
    return None


def _call_mutation(
    provider: Any,
    action: str,
    finding_id: str,
    reason: str,
    *,
    authorization_nonce: str = "",
) -> Any:
    """Route a review action through a workflow service only."""

    if provider is None:
        raise DashboardActionError(
            "The Phase 4 workflow service is unavailable.",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )
    # The real Phase 4 workflow exposes a private capability exchange.  Use it
    # before considering legacy provider methods so an ``actor='human'``
    # argument can never authenticate a direct CLI/agent call.
    issue_capability = getattr(provider, "_authorize_dashboard_action", None)
    record_capability = getattr(provider, "_record_dashboard_action", None)
    if callable(issue_capability) and callable(record_capability):
        if not authorization_nonce:
            raise DashboardActionError(
                "Invalid or expired review action token.",
                status=HTTPStatus.FORBIDDEN,
            )
        try:
            capability = issue_capability(
                finding_id,
                action,
                nonce=authorization_nonce,
            )
            return record_capability(capability, reason=reason)
        except DashboardActionError:
            raise
        except Exception as error:
            message = str(error) or "Review action failed"
            raise DashboardActionError(message) from error
    aliases = {
        "approve": ("approve", "approve_remediation", "review"),
        "reject": ("reject", "review"),
        "defer": ("defer", "review"),
        "false_positive": ("false_positive", "mark_false_positive", "review"),
    }
    names = aliases.get(action, (action,))
    for name in names:
        method = getattr(provider, name, None)
        if not callable(method):
            continue
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            signature = None
        if signature is not None:
            parameters = signature.parameters
            kwargs: dict[str, Any] = {}
            for parameter_name in parameters:
                lowered = parameter_name.lower()
                if lowered in {
                    "finding_id",
                    "finding",
                    "rule_id",
                    "id",
                    "identifier",
                    "finding_identifier",
                }:
                    kwargs[parameter_name] = finding_id
                elif lowered in {"action", "approval_action", "disposition"}:
                    kwargs[parameter_name] = action
                elif lowered in {"reason", "approval_reason", "note"}:
                    kwargs[parameter_name] = reason
                elif lowered in {"actor", "user"}:
                    kwargs[parameter_name] = "human"
            try:
                # Generic `review` methods often require positional values but
                # have no discoverable parameter names.  Keep a bounded
                # fallback only for that explicitly generic method.
                if name == "review" and not kwargs:
                    return method(finding_id, action, reason)
                return method(**kwargs)
            except DashboardActionError:
                raise
            except Exception as error:
                message = str(error) or "Review action failed"
                raise DashboardActionError(message) from error
        # A few callable test doubles (or extension methods) do not expose a
        # signature.  Their invocation shape is necessarily best effort.
        try:
            if name == "review":
                return method(finding_id, action, reason)
            return method(finding_id, reason)
        except DashboardActionError:
            raise
        except Exception as error:
            raise DashboardActionError(str(error) or "Review action failed") from error
    raise DashboardActionError(
        "The Phase 4 workflow service does not support this review action.",
        status=HTTPStatus.NOT_IMPLEMENTED,
    )


@dataclass
class DashboardContext:
    """Provider-backed state and token boundary for one dashboard server."""

    project_path: Path | str = "."
    workflow: Any = None
    store: Any = None
    state_provider: Callable[[], Mapping[str, Any]] | None = None
    status_provider: Callable[[], Mapping[str, Any]] | None = None
    audit_provider: Callable[[], Any] | None = None
    token_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _used_action_tokens: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        self.project_path = Path(self.project_path).expanduser()
        if not isinstance(self.token_secret, bytes):
            self.token_secret = str(self.token_secret).encode("utf-8")
        # ReleaseWorkflow owns its EvidenceStore.  Inferring that dependency
        # keeps ``create_server(workflow=workflow)`` useful without forcing
        # callers to pass the same store twice.
        if self.store is None:
            candidate = getattr(self.workflow, "store", None)
            if candidate is not None:
                self.store = candidate
        bind_secret = getattr(self.workflow, "_bind_dashboard_secret", None)
        if callable(bind_secret):
            existing_secret = getattr(self.workflow, "_dashboard_token_secret", None)
            if isinstance(existing_secret, bytes):
                # Multiple handlers/embedded views for one server share the
                # server's session key; a fresh key would invalidate rendered
                # forms and is not a new trust boundary.
                self.token_secret = existing_secret
            else:
                bind_secret(self.token_secret)

    def _action_binding(self, finding_id: str, action: str) -> tuple[str, str, str]:
        """Return ``(audit_run_id, snapshot_hash, fingerprint)`` for a finding."""

        audit_run_id = ""
        snapshot_hash = ""
        fingerprint = ""
        state: Mapping[str, Any] = {}
        provided_audit: Mapping[str, Any] | None = None
        if self.state_provider is not None:
            try:
                candidate = self.state_provider()
                if isinstance(candidate, Mapping):
                    state = candidate
            except Exception:
                pass
        if self.audit_provider is not None:
            try:
                candidate = self.audit_provider()
                if isinstance(candidate, Mapping):
                    provided_audit = candidate
            except Exception:
                pass
        # EvidenceStore's state index is authoritative when available and does
        # not require reading project source files.
        if not state:
            for provider in (self.store, self.workflow):
                candidate = _call_read(provider, ("read_state",), self.project_path)
                if isinstance(candidate, Mapping):
                    state = candidate
                    break
        if not state and provided_audit is not None:
            state = provided_audit
        latest = state.get("latest_audit") if isinstance(state, Mapping) else None
        if latest is None and provided_audit is not None:
            latest = provided_audit.get("latest_audit")
            if latest is None and any(
                key in provided_audit
                for key in ("audit_run_id", "project_snapshot", "snapshot_hash", "findings")
            ):
                latest = provided_audit
        if isinstance(latest, Mapping):
            audit_run_id = str(latest.get("audit_run_id", ""))
            snapshot = latest.get("project_snapshot")
            snapshot_map = _mapping(snapshot)
            snapshot_hash = str(
                _first(snapshot_map, "content_hash", "snapshot_hash", "project_hash", "hash", default="")
            )
            audit_payload = _mapping(latest.get("audit", {}))
            candidates = audit_payload.get("findings", []) or latest.get("findings", [])
        else:
            candidates = state.get("findings", []) if isinstance(state, Mapping) else []
        if not isinstance(candidates, (list, tuple)):
            candidates = []
        for item in candidates:
            mapped = _mapping(item)
            ids = {
                str(_first(mapped, "finding_id", "rule_id", "finding", "id", default="")),
                str(_first(mapped, "action_id", default="")),
                str(_first(mapped, "fingerprint", default="")),
            }
            if str(finding_id) in ids:
                fingerprint = str(_first(mapped, "fingerprint", default=""))
                break
        # A workflow object can expose the richer in-memory AuditRun even when
        # its state index is unavailable (notably while a dashboard is starting).
        if not audit_run_id or not snapshot_hash or not fingerprint:
            try:
                run = self.workflow.latest_run() if self.workflow is not None else None
                if run is not None:
                    audit_run_id = audit_run_id or str(getattr(run, "audit_run_id", ""))
                    snapshot = getattr(run, "snapshot", None)
                    snapshot_map = _mapping(snapshot)
                    snapshot_hash = snapshot_hash or str(
                        _first(snapshot_map, "content_hash", "snapshot_hash", "project_hash", "hash", default="")
                    )
                    result = getattr(run, "result", run)
                    for item in getattr(result, "findings", []) or []:
                        mapped = _mapping(item)
                        ids = {
                            str(_first(mapped, "finding_id", "rule_id", "finding", "id", default="")),
                            str(_first(mapped, "action_id", default="")),
                            str(_first(mapped, "fingerprint", default="")),
                        }
                        if str(finding_id) in ids:
                            fingerprint = fingerprint or str(_first(mapped, "fingerprint", default=""))
                            break
            except Exception:
                pass
        return audit_run_id, snapshot_hash, fingerprint

    def action_token(self, finding_id: str, action: str) -> str:
        """Return a token tied to the current audit/finding/action identity."""

        normalized_action = str(action).strip().lower().replace("-", "_")
        normalized_action = {
            "approve_remediation": "approve",
            "mark_false_positive": "false_positive",
        }.get(normalized_action, normalized_action)
        audit_run_id, snapshot_hash, fingerprint = self._action_binding(finding_id, action)
        message = "\x00".join(
            (str(finding_id), normalized_action, audit_run_id, snapshot_hash, fingerprint)
        ).encode("utf-8", errors="replace")
        return hmac.new(self.token_secret, message, hashlib.sha256).hexdigest()

    def validate_action_token(self, finding_id: str, action: str, token: str) -> bool:
        expected = self.action_token(finding_id, action)
        return bool(token) and hmac.compare_digest(expected, str(token))

    def _latest_audit(self) -> Any:
        if self.audit_provider is not None:
            try:
                value = self.audit_provider()
                if value is not None:
                    return value
            except Exception:
                pass
        names = (
            "latest_audit",
            "get_latest_audit",
            "load_latest_audit",
            "latest_audit_result",
            "get_latest_result",
            "load_latest_result",
            "latest_run",
            "current_run",
        )
        for provider in (self.workflow, self.store):
            value = _call_read(provider, names, self.project_path)
            if value is not None:
                return _unwrap_audit(value)
        # Read an existing evidence artifact if a store has not yet exposed a
        # Python API.  The newest valid JSON is used and still redacted before
        # rendering; no source file is read here.
        evidence_root = self.project_path / ".releaseguard" / "evidence"
        candidates: list[Path] = []
        try:
            candidates = sorted(
                (path for path in evidence_root.glob("*/after.json") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            candidates += sorted(
                (path for path in evidence_root.glob("*/audit.json") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            candidates = []
        for path in candidates:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
        # Last-resort read-only deterministic audit.  Import lazily so this
        # module remains importable in minimal test environments.
        try:
            from ..scanner import audit_project

            return audit_project(self.project_path, include_remediation_plan=True)
        except Exception:
            return None

    def _provider_payload(self, names: Sequence[str]) -> Any:
        for provider in (self.workflow, self.store):
            value = _call_read(provider, names, self.project_path)
            if value is not None:
                return value
        return None

    def ai_status(self) -> Mapping[str, Any]:
        if self.status_provider is not None:
            try:
                value = self.status_provider()
                if isinstance(value, Mapping):
                    return _safe_value(dict(value))
            except Exception:
                pass
        try:
            manager_class = LocalServerManager
            if manager_class is None:
                from ..ai.service import LocalServerManager as manager_class

            value = manager_class().status()  # type: ignore[operator]
            if isinstance(value, Mapping):
                return _safe_value(dict(value))
        except Exception:
            pass
        return {"ok": False, "state": "disabled", "local": True}

    def state(self) -> dict[str, Any]:
        """Build a JSON-safe dashboard state from read-only providers."""

        with self._lock:
            provided = None
            if self.state_provider is not None:
                try:
                    provided = self.state_provider()
                except Exception:
                    provided = None
            if provided is None:
                provided = self._provider_payload(
                    (
                        "dashboard_state",
                        "get_dashboard_state",
                        "load_dashboard_state",
                        # EvidenceStore exposes a redacted state index rather
                        # than a dashboard-specific method.
                        "read_state",
                    )
                )
            state = _mapping(provided)
            audit = state.get("audit") or state.get("latest_audit")
            if audit is None:
                audit = self._latest_audit()
            audit = _unwrap_audit(audit)
            audit_map = _mapping(audit)
            # An injected audit provider is often a convenient test/embedding
            # seam and may return a complete dashboard-shaped mapping rather
            # than an AuditResult.  Preserve those top-level fields while still
            # accepting the normal project_name/release_score contract.
            if not state and any(
                key in audit_map
                for key in ("project", "score", "gate", "timeline", "approvals", "audit_history")
            ):
                state = audit_map
                nested_audit = state.get("audit")
                audit_map = _mapping(nested_audit) if nested_audit is not None else audit_map

            summary = _mapping(_first(audit_map, "summary", default={}))
            counts = _mapping(_first(summary, "counts", default={}))
            if not counts and any(key in summary for key in ("critical", "high", "medium", "low")):
                counts = summary.copy()
            for severity in ("critical", "high", "medium", "low"):
                if severity not in counts:
                    counts[severity] = _first(
                        summary,
                        severity,
                        f"{severity}_count",
                        default=0,
                    )
                try:
                    counts[severity] = int(counts[severity] or 0)
                except (TypeError, ValueError):
                    counts[severity] = 0

            score = _first(state, "score", "release_score", default=None)
            if score is None:
                score = _first(audit_map, "release_score", "score", default=None)
            try:
                score = int(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            gate = _first(state, "gate", "release_gate", default=None)
            if gate is None:
                gate = _first(audit_map, "release_gate", "gate", default="UNKNOWN")
            gate = str(getattr(gate, "value", gate)).upper()

            findings = _first(state, "findings", default=None)
            if findings is None:
                findings = _first(audit_map, "findings", default=[])
            if isinstance(findings, Mapping):
                findings = list(findings.values())
            if not isinstance(findings, (list, tuple)):
                findings = []
            normalized_findings = [self._normalize_finding(item) for item in findings]
            # Rule IDs are the friendliest display labels but can repeat (for
            # example several TODO markers).  Use the stable fingerprint as the
            # action/detail identity for duplicates so a review cannot target
            # an ambiguous finding.
            id_counts: dict[str, int] = {}
            for item in normalized_findings:
                key = str(item.get("finding_id", ""))
                id_counts[key] = id_counts.get(key, 0) + 1
            for item in normalized_findings:
                display_id = str(item.get("finding_id", ""))
                fingerprint = str(item.get("fingerprint", ""))
                item["action_id"] = (
                    fingerprint
                    if id_counts.get(display_id, 0) > 1 and fingerprint
                    else display_id
                )

            plan = _first(state, "remediation_plan", "plan", default=None)
            if plan is None:
                plan = _first(audit_map, "remediation_plan", "plan", default=[])
            if isinstance(plan, Mapping):
                plan = [plan]
            if not isinstance(plan, (list, tuple)):
                plan = []

            approvals = _first(state, "approvals", "approval_history", default=None)
            if approvals is None:
                approvals = self._provider_payload(
                    (
                        "approval_history",
                        "list_approvals",
                        "approvals",
                        "load_approvals",
                        "all_approvals",
                    )
                )
            audits = _first(state, "audit_history", "audits", default=None)
            if audits is None:
                audits = self._provider_payload(
                    ("audit_history", "list_audits", "audits", "load_audits", "all_audits")
                )
            timeline = _first(state, "timeline", "events", default=None)
            if timeline is None:
                timeline = self._provider_payload(
                    (
                        "timeline",
                        "load_timeline",
                        "list_timeline",
                        "events",
                        "load_events",
                        "all_timeline",
                    )
                )

            # ``read_state`` already contains these lists; retain them even
            # when a provider does not expose the convenience all_* methods.
            if (approvals is None or approvals == []) and isinstance(state.get("approvals"), list):
                approvals = state["approvals"]
            if (audits is None or audits == []) and isinstance(state.get("audits"), list):
                audits = state["audits"]
            if (timeline is None or timeline == []) and isinstance(state.get("timeline"), list):
                timeline = state["timeline"]

            project_mapping = _mapping(_first(state, "project", default={}))
            project_name = _first(
                state,
                "project_name",
                default=_first(
                    project_mapping,
                    "name",
                    "project_name",
                    default=_first(audit_map, "project_name", default=self.project_path.name),
                ),
            )
            project_display_path = _first(
                state,
                "project_path",
                default=_first(
                    project_mapping,
                    "path",
                    "project_path",
                    default=_first(audit_map, "project_path", default=self.project_path),
                ),
            )

            result = {
                "project": {
                    "name": project_name,
                    "path": str(project_display_path),
                },
                "score": score,
                "gate": gate,
                "summary": {"counts": counts, **{key: value for key, value in summary.items() if key != "counts"}},
                "findings": normalized_findings,
                "remediation_plan": [_safe_value(_jsonable(item)) for item in plan],
                "approvals": [_safe_value(_jsonable(item)) for item in (approvals or [])]
                if isinstance(approvals, (list, tuple))
                else [],
                "audit_history": [_safe_value(_jsonable(item)) for item in (audits or [])]
                if isinstance(audits, (list, tuple))
                else [],
                "timeline": [_safe_value(_jsonable(item)) for item in (timeline or [])]
                if isinstance(timeline, (list, tuple))
                else [],
                "ai_status": self.ai_status(),
            }
            # Include useful top-level identifiers without copying untrusted
            # payloads wholesale.
            for key in ("audit_run_id", "timestamp", "scanner_version"):
                value = _first(state, key, default=_first(audit_map, key, default=None))
                if value is not None:
                    result[key] = _safe_value(value)
            return _safe_value(result)

    @staticmethod
    def _normalize_finding(value: Any) -> dict[str, Any]:
        finding = _mapping(value)
        finding_id = _first(finding, "finding_id", "id", "rule_id", "finding", default="unknown")
        finding["finding_id"] = _text(finding_id, "unknown")
        finding["rule_id"] = _text(_first(finding, "rule_id", default=finding["finding_id"]))
        finding["title"] = _text(_first(finding, "title", "message", default="Release finding"))
        finding["severity"] = str(
            getattr(_first(finding, "severity", default="low"), "value", _first(finding, "severity", default="low"))
        ).upper()
        finding["status"] = str(
            getattr(_first(finding, "status", "disposition", default="OPEN"), "value", _first(finding, "status", "disposition", default="OPEN"))
        ).upper()
        finding["file"] = _text(_first(finding, "file", "target_file", default="."))
        line = _first(finding, "line", default=None)
        finding["line"] = line if isinstance(line, int) else None
        evidence = _text(_first(finding, "evidence", "preview", "safe_preview", default=""))
        finding["safe_preview"] = evidence[:MAX_PREVIEW_LENGTH]
        finding["explanation"] = _text(_first(finding, "explanation", "reason", default=""))
        finding["recommendation"] = _text(_first(finding, "recommendation", "recommended_action", default=""))
        finding["fingerprint"] = _text(_first(finding, "fingerprint", default=""))
        return _safe_value(finding)

    def review_action(
        self,
        finding_id: str,
        action: str,
        *,
        reason: str = "",
        token: str = "",
    ) -> Any:
        normalized_action = action.strip().lower().replace("-", "_")
        aliases = {
            "approve_remediation": "approve",
            "approve": "approve",
            "reject": "reject",
            "defer": "defer",
            "mark_false_positive": "false_positive",
            "false_positive": "false_positive",
        }
        normalized_action = aliases.get(normalized_action, normalized_action)
        if normalized_action not in {"approve", "reject", "defer", "false_positive"}:
            raise DashboardActionError("Unsupported review action.")
        if not self.validate_action_token(finding_id, normalized_action, token):
            raise DashboardActionError(
                "Invalid or expired review action token.", status=HTTPStatus.FORBIDDEN
            )
        if normalized_action == "false_positive" and not reason.strip():
            raise DashboardActionError(
                "A reason is required when marking a finding false positive."
            )
        token_key = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        with self._lock:
            if token_key in self._used_action_tokens:
                raise DashboardActionError(
                    "Invalid or expired review action token.",
                    status=HTTPStatus.FORBIDDEN,
                )
            result = _call_mutation(
                self.workflow,
                normalized_action,
                finding_id,
                _redact_text(reason.strip()),
                authorization_nonce=token,
            )
            # Mark only after the workflow has durably created the record.  A
            # failed/stale action can therefore be reviewed again with a fresh
            # page token, while a successful token cannot be replayed.
            self._used_action_tokens.add(token_key)
        return _safe_value(_jsonable(result))


class DashboardHTTPServer(ThreadingHTTPServer):
    """Threading server carrying a :class:`DashboardContext`."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler_class: type[BaseHTTPRequestHandler], *, context: DashboardContext | None = None) -> None:
        super().__init__(server_address, handler_class)
        self.dashboard_context = context or DashboardContext()


DashboardServer = DashboardHTTPServer


def _page_styles() -> str:
    return """
    :root { color-scheme: light; font-family: system-ui, -apple-system, Segoe UI, sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #15202b; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:baseline; flex-wrap:wrap; }
    h1 { margin:0; font-size:clamp(1.5rem, 3vw, 2.25rem); }
    h2 { margin-top: 28px; font-size: 1.2rem; }
    .muted { color:#5b6875; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
    .card { background:#fff; border:1px solid #d9e0e6; border-radius:8px; padding:16px; box-shadow:0 1px 2px #15202b12; }
    .metric { font-size:1.8rem; font-weight:700; }
    .gate { font-weight:700; letter-spacing:.04em; }
    .gate-BLOCKED { color:#a4262c; } .gate-WARNING { color:#9a6700; } .gate-PASS { color:#137333; }
    .finding { margin:12px 0; }
    .finding-head { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .badge { display:inline-block; padding:3px 7px; border-radius:999px; background:#e8edf2; font-size:.75rem; font-weight:700; }
    .badge-CRITICAL { background:#f9d7d9; color:#8b1e24; } .badge-HIGH { background:#fde7c2; color:#734b00; }
    .badge-MEDIUM { background:#fff3bf; color:#6d5b00; } .badge-LOW { background:#dceeff; color:#174a73; }
    pre { white-space:pre-wrap; overflow-wrap:anywhere; background:#f6f8fa; padding:10px; border-radius:5px; }
    a, button { color:#0b57d0; } button { border:1px solid #9aa8b5; background:#fff; border-radius:5px; padding:6px 9px; cursor:pointer; }
    form { display:inline-flex; gap:6px; align-items:center; flex-wrap:wrap; margin:4px 4px 4px 0; }
    input[type=text] { border:1px solid #9aa8b5; border-radius:4px; padding:6px; min-width:180px; }
    table { width:100%; border-collapse:collapse; background:#fff; } th,td { border-bottom:1px solid #e2e7eb; text-align:left; padding:8px; vertical-align:top; }
    @media (max-width:620px) { main { padding:14px; } table { display:block; overflow:auto; } }
    """


def _esc(value: Any) -> str:
    return html.escape(_redact_text(value), quote=True)


def _finding_token_forms(context: DashboardContext, finding: Mapping[str, Any], *, detail: bool = False) -> str:
    finding_id = str(
        finding.get("action_id", finding.get("finding_id", finding.get("rule_id", "")))
    )
    forms: list[str] = ['<span class="muted">Review:</span>']
    for action, label in (("approve", "Approve Remediation"), ("reject", "Reject"), ("defer", "Defer"), ("false_positive", "Mark False Positive")):
        token = context.action_token(finding_id, action)
        reason = "" if action != "false_positive" else '<input type="text" name="reason" required placeholder="Reason">'
        forms.append(
            f'<form method="post" action="/api/review/{_esc(finding_id)}">'
            f'<input type="hidden" name="action" value="{action}">'
            f'<input type="hidden" name="token" value="{token}">'
            f'<input type="hidden" name="csrf_token" value="{token}">'
            f'{reason}<button type="submit">{label}</button></form>'
        )
    return "".join(forms)


def render_dashboard(state: Mapping[str, Any], *, context: DashboardContext | None = None) -> str:
    """Render the dashboard home page from a safe state mapping."""

    context = context or DashboardContext()
    safe_state = _safe_value(_jsonable(state))
    project = _mapping(safe_state.get("project", {}))
    score = safe_state.get("score")
    gate = str(safe_state.get("gate", "UNKNOWN")).upper()
    summary = _mapping(safe_state.get("summary", {}))
    counts = _mapping(summary.get("counts", {}))
    findings = safe_state.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    lines = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>ReleaseGuard Dashboard</title>",
        f"<style>{_page_styles()}</style></head><body><main>",
        "<header><h1>ReleaseGuard</h1><span class=\"muted\">Human-in-the-loop release gate</span></header>",
        f"<p class=\"muted\">Project: {_esc(project.get('name', 'project'))} &middot; {_esc(project.get('path', ''))}</p>",
        '<section class="grid" aria-label="Release summary">',
        f'<div class="card"><div class="muted">Score</div><div class="metric">{_esc(score if score is not None else "-")} / 100</div></div>',
        f'<div class="card"><div class="muted">Gate</div><div class="metric gate gate-{_esc(gate)}">{_esc(gate)}</div></div>',
    ]
    for severity in ("critical", "high", "medium", "low"):
        lines.append(
            f'<div class="card"><div class="muted">{severity.upper()}</div><div class="metric">{_esc(counts.get(severity, 0))}</div></div>'
        )
    lines.append("</section>")

    lines.extend(["<h2>Findings</h2>"])
    if findings:
        for finding in findings:
            item = _mapping(finding)
            finding_id = _first(item, "finding_id", "rule_id", default="unknown")
            action_id = _first(item, "action_id", default=finding_id)
            severity = str(_first(item, "severity", default="LOW")).upper()
            location = str(_first(item, "file", default="."))
            line = _first(item, "line", default=None)
            if isinstance(line, int):
                location += f":{line}"
            actions_html = (
                _finding_token_forms(context, item)
                if str(_first(item, "status", default="OPEN")).upper()
                not in {"RESOLVED", "FALSE_POSITIVE"}
                else '<p class="muted">No review actions are available for a completed disposition.</p>'
            )
            lines.append(
                '<article class="card finding">'
                f'<div class="finding-head"><strong>{_esc(finding_id)}</strong><span class="badge badge-{_esc(severity)}">{_esc(severity)}</span></div>'
                f'<p><strong>{_esc(_first(item, "title", default="Release finding"))}</strong><br><span class="muted">{_esc(location)}</span></p>'
                f'<p>Status: <strong>{_esc(_first(item, "status", default="OPEN"))}</strong></p>'
                f'<pre>{_esc(_first(item, "safe_preview", "evidence", default="No preview available."))}</pre>'
                f'<p><a href="/finding/{_esc(action_id)}">Details</a></p>'
                + actions_html
                + "</article>"
            )
    else:
        lines.append('<div class="card">No findings are available for this audit.</div>')

    plan = safe_state.get("remediation_plan", [])
    if not isinstance(plan, list):
        plan = []
    lines.append("<h2>Remediation Plan</h2>")
    if plan:
        lines.append('<div class="card"><table><thead><tr><th>Finding</th><th>Risk</th><th>Summary</th><th>Human approval</th></tr></thead><tbody>')
        for raw_item in plan:
            item = _mapping(raw_item)
            lines.append(
                "<tr>"
                f"<td>{_esc(_first(item, 'finding_id', 'finding', 'rule_id', default=''))}</td>"
                f"<td>{_esc(_first(item, 'risk', 'fix_safety', default=''))}</td>"
                f"<td>{_esc(_first(item, 'summary', 'recommended_action', default=''))}</td>"
                f"<td>{_esc(_first(item, 'requires_human_approval', default=''))}</td>"
                "</tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No remediation plan recorded.</div>')

    approvals = safe_state.get("approvals", [])
    lines.append("<h2>Approval History</h2>")
    if isinstance(approvals, list) and approvals:
        lines.append('<div class="card"><table><thead><tr><th>Finding</th><th>Action</th><th>Actor</th><th>Reason</th></tr></thead><tbody>')
        for raw_item in approvals:
            item = _mapping(raw_item)
            lines.append(
                "<tr>"
                f"<td>{_esc(_first(item, 'finding_id', 'finding', default=''))}</td>"
                f"<td>{_esc(_first(item, 'action', default=''))}</td>"
                f"<td>{_esc(_first(item, 'actor', default=''))}</td>"
                f"<td>{_esc(_first(item, 'reason', default=''))}</td>"
                "</tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No approval history recorded.</div>')

    audits = safe_state.get("audit_history", [])
    lines.append("<h2>Audit History</h2>")
    if isinstance(audits, list) and audits:
        lines.append('<div class="card"><table><thead><tr><th>Run</th><th>Score</th><th>Gate</th><th>Time</th></tr></thead><tbody>')
        for raw_item in audits:
            item = _mapping(raw_item)
            nested = _mapping(_first(item, "audit", default={}))
            lines.append(
                "<tr>"
                f"<td>{_esc(_first(item, 'audit_run_id', 'run_id', default=''))}</td>"
                f"<td>{_esc(_first(nested, 'release_score', 'score', default=_first(item, 'score', default='')))}</td>"
                f"<td>{_esc(_first(nested, 'release_gate', 'gate', default=_first(item, 'gate', default='')))}</td>"
                f"<td>{_esc(_first(item, 'timestamp', default=''))}</td>"
                "</tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No audit history recorded.</div>')

    ai_status = _mapping(safe_state.get("ai_status", {}))
    lines.extend([
        "<h2>AI Analyzer</h2>",
        '<div class="card">',
        f"<strong>Status:</strong> {_esc(ai_status.get('state', 'disabled'))} &middot; Backend: {_esc(ai_status.get('backend', ai_status.get('analyzer', 'OpenVINO')))}",
        f"<br>Device: {_esc(ai_status.get('device', 'not loaded'))} &middot; Model: {_esc(ai_status.get('model_id', 'not loaded'))}",
        "</div>",
        "<h2>Audit Timeline</h2>",
    ])
    timeline = safe_state.get("timeline", [])
    if isinstance(timeline, list) and timeline:
        lines.append('<div class="card"><table><thead><tr><th>Time</th><th>Event</th><th>Finding</th><th>Summary</th></tr></thead><tbody>')
        for event in timeline:
            row = _mapping(event)
            lines.append(
                "<tr>"
                f"<td>{_esc(_first(row, 'timestamp', 'time', default=''))}</td>"
                f"<td>{_esc(_first(row, 'type', 'event_type', default=''))}</td>"
                f"<td>{_esc(_first(row, 'finding_id', 'finding', default=''))}</td>"
                f"<td>{_esc(_first(row, 'summary', 'message', default=''))}</td>"
                "</tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No timeline events recorded.</div>')
    lines.extend(["</main></body></html>"])
    return "".join(lines)


def render_finding_detail(state: Mapping[str, Any], finding_id: str, *, context: DashboardContext | None = None) -> str | None:
    """Render one finding detail page, or ``None`` when it is not present."""

    context = context or DashboardContext()
    findings = state.get("findings", []) if isinstance(state, Mapping) else []
    if not isinstance(findings, list):
        return None
    selected = next(
        (
            _mapping(item)
            for item in findings
            if str(_first(_mapping(item), "action_id", "finding_id", "fingerprint", "rule_id", "id", default="")) == str(finding_id)
            or str(_first(_mapping(item), "finding_id", "fingerprint", "rule_id", "id", default="")) == str(finding_id)
        ),
        None,
    )
    if selected is None:
        return None
    action_identity = selected.get("action_id")
    selected = DashboardContext._normalize_finding(selected)
    if action_identity:
        selected["action_id"] = action_identity
    display_finding_id = str(selected.get("finding_id", finding_id))
    plan = state.get("remediation_plan", []) if isinstance(state, Mapping) else []
    if not isinstance(plan, list):
        plan = []
    related_plan = [
        _mapping(item)
        for item in plan
        if str(_first(_mapping(item), "finding", "finding_id", "rule_id", default=""))
        in {str(finding_id), display_finding_id}
    ]
    lines = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{_esc(finding_id)} - ReleaseGuard</title>",
        f"<style>{_page_styles()}</style></head><body><main><p><a href=\"/\">&larr; Dashboard</a></p>",
        f"<h1>{_esc(finding_id)}</h1>",
        '<div class="card">',
        f"<p><strong>Rule ID:</strong> {_esc(selected.get('rule_id', finding_id))}</p>",
        f"<p><strong>Severity:</strong> {_esc(selected.get('severity', ''))}</p>",
        f"<p><strong>Status:</strong> {_esc(selected.get('status', 'OPEN'))}</p>",
        f"<p><strong>File:</strong> {_esc(selected.get('file', '.'))}"
        + (f":{_esc(selected['line'])}" if isinstance(selected.get("line"), int) else "")
        + "</p>",
        f"<p><strong>Safe preview:</strong></p><pre>{_esc(selected.get('safe_preview', ''))}</pre>",
        f"<p><strong>Explanation:</strong> {_esc(selected.get('explanation', ''))}</p>",
        f"<p><strong>Recommendation:</strong> {_esc(selected.get('recommendation', ''))}</p>",
        (
            _finding_token_forms(context, selected, detail=True)
            if str(selected.get("status", "OPEN")).upper() not in {"RESOLVED", "FALSE_POSITIVE"}
            else '<p class="muted">No review actions are available for a completed disposition.</p>'
        ),
        "</div><h2>Remediation Plan</h2>",
    ]
    if related_plan:
        for item in related_plan:
            lines.append('<div class="card"><dl>')
            for label, key in (("Risk", "risk"), ("Summary", "summary"), ("Action", "recommended_action"), ("Expected effect", "expected_effect")):
                if key in item:
                    lines.append(f"<dt><strong>{_esc(label)}</strong></dt><dd>{_esc(item[key])}</dd>")
            for label, key in (("Allowed files", "allowed_files"), ("Allowed operations", "allowed_operations"), ("Forbidden operations", "forbidden_operations")):
                values = item.get(key)
                if isinstance(values, list):
                    lines.append(f"<dt><strong>{_esc(label)}</strong></dt><dd>{_esc(', '.join(map(str, values)))}</dd>")
            lines.append("</dl></div>")
    else:
        lines.append('<div class="card muted">No remediation plan recorded.</div>')
    lines.extend(["<h2>Approval History</h2>"])
    approvals = state.get("approvals", []) if isinstance(state, Mapping) else []
    related_approvals = []
    if isinstance(approvals, list):
        related_approvals = [
            _mapping(item)
            for item in approvals
            if str(_first(_mapping(item), "finding_id", "finding", default=""))
            in {str(finding_id), display_finding_id}
        ]
    if related_approvals:
        lines.append('<div class="card"><table><thead><tr><th>Action</th><th>Actor</th><th>Reason</th><th>Time</th></tr></thead><tbody>')
        for row in related_approvals:
            lines.append(
                f"<tr><td>{_esc(_first(row, 'action', default=''))}</td><td>{_esc(_first(row, 'actor', default=''))}</td><td>{_esc(_first(row, 'reason', default=''))}</td><td>{_esc(_first(row, 'timestamp', default=''))}</td></tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No approval history recorded.</div>')
    lines.extend(["<h2>Audit History</h2>"])
    audits = state.get("audit_history", []) if isinstance(state, Mapping) else []
    related_audits = audits if isinstance(audits, list) else []
    if related_audits:
        lines.append('<div class="card"><table><thead><tr><th>Run</th><th>Score</th><th>Gate</th><th>Time</th></tr></thead><tbody>')
        for raw_audit in related_audits:
            row = _mapping(raw_audit)
            nested = _mapping(_first(row, "audit", default={}))
            lines.append(
                "<tr>"
                f"<td>{_esc(_first(row, 'audit_run_id', 'run_id', default=''))}</td>"
                f"<td>{_esc(_first(nested, 'release_score', 'score', default=_first(row, 'score', default='')))}</td>"
                f"<td>{_esc(_first(nested, 'release_gate', 'gate', default=_first(row, 'gate', default='')))}</td>"
                f"<td>{_esc(_first(row, 'timestamp', default=''))}</td>"
                "</tr>"
            )
        lines.append("</tbody></table></div>")
    else:
        lines.append('<div class="card muted">No audit history recorded.</div>')
    lines.append("</main></body></html>")
    return "".join(lines)


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for dashboard HTML and JSON endpoints."""

    server_version = "ReleaseGuardDashboard/0.2.0"
    sys_version = ""

    @property
    def context(self) -> DashboardContext:
        context = getattr(self.server, "dashboard_context", None)
        if not isinstance(context, DashboardContext):
            context = DashboardContext()
            setattr(self.server, "dashboard_context", context)
        return context

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        if len(body) > MAX_RESPONSE_BYTES:
            body = body[:MAX_RESPONSE_BYTES]
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, _safe_json(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _html(self, status: int, payload: str) -> None:
        self._send(status, payload.encode("utf-8"), "text/html; charset=utf-8")

    def _not_found(self, message: str = "Not found") -> None:
        self._json(HTTPStatus.NOT_FOUND, {"error": message})

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path in {"/", "/dashboard"}:
            self._html(HTTPStatus.OK, render_dashboard(self.context.state(), context=self.context))
            return
        if path in {"/api/state", "/api/dashboard"}:
            self._json(HTTPStatus.OK, self.context.state())
            return
        if path in {"/api/findings", "/api/audit/findings"}:
            self._json(HTTPStatus.OK, {"findings": self.context.state().get("findings", [])})
            return
        if path in {"/api/timeline", "/api/audit/timeline"}:
            self._json(HTTPStatus.OK, {"timeline": self.context.state().get("timeline", [])})
            return
        if path in {"/api/approvals", "/api/audit/approvals"}:
            self._json(HTTPStatus.OK, {"approvals": self.context.state().get("approvals", [])})
            return
        if path in {"/api/audits", "/api/audit/history"}:
            self._json(HTTPStatus.OK, {"audits": self.context.state().get("audit_history", [])})
            return
        if path in {"/api/status", "/api/ai-status"}:
            self._json(HTTPStatus.OK, self.context.ai_status())
            return
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"ok": True, "service": "releaseguard-dashboard"})
            return
        if path.startswith("/finding/"):
            finding_id = path[len("/finding/"):]
            if not finding_id or "/" in finding_id:
                self._not_found()
                return
            page = render_finding_detail(self.context.state(), finding_id, context=self.context)
            if page is None:
                self._not_found("Finding not found")
            else:
                self._html(HTTPStatus.OK, page)
            return
        for prefix in ("/api/findings/", "/api/finding/"):
            if path.startswith(prefix):
                finding_id = path[len(prefix):]
                if not finding_id or "/" in finding_id:
                    self._not_found()
                    return
                state = self.context.state()
                findings = state.get("findings", [])
                if not isinstance(findings, list):
                    findings = []
                selected = next(
                    (
                        item
                        for item in findings
                        if str(
                            _first(
                                _mapping(item),
                                "action_id",
                                "finding_id",
                                "fingerprint",
                                "rule_id",
                                default="",
                            )
                        )
                        == finding_id
                    ),
                    None,
                )
                if selected is None:
                    self._not_found("Finding not found")
                else:
                    self._json(HTTPStatus.OK, {"finding": _safe_value(_jsonable(selected))})
                return
        self._not_found()

    def _request_data(self) -> dict[str, str]:
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError as error:
            raise DashboardActionError("Invalid request body.") from error
        if length < 0 or length > 64_000:
            raise DashboardActionError("Request body is too large.")
        raw = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, ValueError) as error:
                raise DashboardActionError("Invalid JSON request body.") from error
            return {str(key): str(value) for key, value in payload.items()} if isinstance(payload, Mapping) else {}
        parsed = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        try:
            data = self._request_data()
            finding_id = data.get("finding_id", "")
            if path.startswith("/api/review/"):
                suffix = path[len("/api/review/"):]
                parts = [part for part in suffix.split("/") if part]
                finding_id = parts[0] if parts else ""
                if not data.get("action") and len(parts) > 1:
                    data["action"] = parts[1]
            elif path.startswith("/review/"):
                suffix = path[len("/review/"):]
                parts = [part for part in suffix.split("/") if part]
                finding_id = parts[0] if parts else ""
                if not data.get("action") and len(parts) > 1:
                    data["action"] = parts[1]
            elif path.startswith("/finding/") and path.endswith("/review"):
                finding_id = path[len("/finding/"):-len("/review")].strip("/")
            action = data.get("action", "")
            token = data.get("token", data.get("action_token", data.get("csrf_token", "")))
            if not finding_id or not action:
                raise DashboardActionError("finding_id and action are required.")
            result = self.context.review_action(
                finding_id,
                action,
                reason=data.get("reason", ""),
                token=token,
            )
            response = {"ok": True, "finding_id": finding_id, "action": action, "result": result}
            if path.startswith("/api/"):
                self._json(HTTPStatus.OK, response)
            else:
                # Keep browser workflows dependency-free.  A small JSON body is
                # easier to test and does not hide a mutation behind a redirect.
                self._json(HTTPStatus.OK, response)
        except DashboardActionError as error:
            self._json(error.status, {"ok": False, "error": _redact_text(str(error))})
        except Exception:
            # Never expose provider tracebacks or request contents to a browser.
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "Dashboard action failed."})

    def log_message(self, format: str, *args: Any) -> None:
        # Request paths can contain finding identifiers supplied by a user.  Do
        # not write them, or POST bodies, to the process stderr by default.
        return None


def create_server(
    project_path: str | Path = ".",
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    workflow: Any = None,
    store: Any = None,
    state_provider: Callable[[], Mapping[str, Any]] | None = None,
    status_provider: Callable[[], Mapping[str, Any]] | None = None,
    audit_provider: Callable[[], Any] | None = None,
    server_factory: Callable[..., Any] | None = None,
    handler_class: type[BaseHTTPRequestHandler] = DashboardHandler,
    token_secret: bytes | None = None,
) -> Any:
    """Create (but do not start) a loopback-only dashboard server.

    ``server_factory`` is injectable for tests and embedding.  It receives the
    conventional ``(address, handler_class)`` pair; keyword fallback supports
    tiny test doubles that expose a named signature instead.
    """

    if host != DEFAULT_HOST:
        raise ValueError(f"ReleaseGuard Dashboard must bind to {DEFAULT_HOST}.")
    if not isinstance(port, int) or isinstance(port, bool) or not (0 <= port <= 65_535):
        raise ValueError("Dashboard port must be an integer from 0 through 65535.")
    if workflow is None and state_provider is None and audit_provider is None:
        # The production CLI does not need to assemble the service graph
        # itself; a real project dashboard gets the same persisted workflow
        # authority as ``review``/``remediate``.  Injected providers remain
        # read-only test/embedding seams unless they supply their own workflow.
        from .store import EvidenceStore as _EvidenceStore
        from .workflow import ReleaseWorkflow as _ReleaseWorkflow

        store = store or _EvidenceStore(project_path)
        workflow = _ReleaseWorkflow(project_path, store=store)
    context = DashboardContext(
        project_path=project_path,
        workflow=workflow,
        store=store,
        state_provider=state_provider,
        status_provider=status_provider,
        audit_provider=audit_provider,
        token_secret=token_secret or secrets.token_bytes(32),
    )
    factory = server_factory or DashboardHTTPServer
    try:
        server = factory((DEFAULT_HOST, port), handler_class, context=context)
    except TypeError:
        try:
            server = factory((DEFAULT_HOST, port), handler_class, context)
        except TypeError:
            try:
                server = factory((DEFAULT_HOST, port), handler_class)
            except TypeError:
                server = factory(server_address=(DEFAULT_HOST, port), handler_class=handler_class)
    if not hasattr(server, "dashboard_context"):
        setattr(server, "dashboard_context", context)
    return server


create_dashboard_server = create_server


def run_dashboard(
    project_path: str | Path = ".",
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    workflow: Any = None,
    store: Any = None,
    state_provider: Callable[[], Mapping[str, Any]] | None = None,
    status_provider: Callable[[], Mapping[str, Any]] | None = None,
    audit_provider: Callable[[], Any] | None = None,
    server_factory: Callable[..., Any] | None = None,
) -> Any:
    """Start the dashboard until interrupted and return its server object."""

    server = create_server(
        project_path,
        host=host,
        port=port,
        workflow=workflow,
        store=store,
        state_provider=state_provider,
        status_provider=status_provider,
        audit_provider=audit_provider,
        server_factory=server_factory,
    )
    print("ReleaseGuard Dashboard")
    address = getattr(server, "server_address", (DEFAULT_HOST, port))
    print(f"http://{address[0]}:{address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        close = getattr(server, "server_close", None)
        if callable(close):
            close()
    return server


serve_dashboard = run_dashboard
start_dashboard = run_dashboard


__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DashboardActionError",
    "DashboardContext",
    "DashboardHandler",
    "DashboardHTTPServer",
    "DashboardServer",
    "create_server",
    "create_dashboard_server",
    "render_dashboard",
    "render_finding_detail",
    "run_dashboard",
    "serve_dashboard",
    "start_dashboard",
]
