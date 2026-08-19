"""Centralised redaction helpers for Phase 4 evidence and workflow payloads.

Phase 1--3 already have conservative text redaction for AI requests.  Phase 4
uses the same primitives at the persistence boundary and extends them to
structured values.  Callers should pass untrusted values through
``redact_value`` (or ``redact_for_persistence``) before writing JSON, logs, or
timeline metadata.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from ..ai.redaction import (
    REDACTED_FRAGMENT,
    REDACTED_PATH,
    REDACTED_PRIVATE_KEY,
    REDACTED_QUERY,
    REDACTED_SECRET,
    REDACTED_TOKEN,
    REDACTED_URL,
    redact_text as _redact_ai_text,
    truncate_text as _truncate_text,
)


# A stable marker is preferable to an empty value: reviewers can see that a
# field existed without receiving the credential itself.
REDACTION_MARKER = REDACTED_SECRET


class RawSecretError(ValueError):
    """Raised when a persistence payload still contains a raw credential."""


SecretPersistenceError = RawSecretError

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{8,}|"
    r"ghp_[A-Za-z0-9]{12,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"
    r")(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_URL_CREDENTIAL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,31}://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_GENERIC_SECRET_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_\-[\]])(?:(?:[A-Za-z0-9]+[-_])*(?:secret|password|credential))"
    r"(?:[-_](?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]+)+(?![A-Za-z0-9_\-\[])",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<prefix>\b(?:[A-Za-z][A-Za-z0-9_.-]*[_-])?"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"access[_-]?key|client[_-]?secret|secret(?:[_-]?(?:access|signing|encryption))?[_-]?key|"
    r"database[_-]?(?:url|password)|credential(?:[_-]?value)?|"
    r"secret(?:[_-]?value)?|database[_-]?(?:url|password)|"
    r"db[_-]?(?:url|password)|password|passwd|private[_-]?key|secret|token)"
    r"\b\s*(?:=|:)\s*)"
    r"(?P<value>(?:[\"'`][^\r\n\"'`]*[\"'`])|"
    r"(?:\[[^\r\n\]]+\])|(?:[^\s,;#}\]]+))"
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"access[_-]?key|client[_-]?secret|secret(?:[_-]?(?:access|signing|encryption))?[_-]?key|"
    r"password|passwd|credential(?:[_-]?value)?|secret(?:[_-]?value)?|private[_-]?key|"
    r"bearer[_-]?token|database[_-]?(?:url|password)|db[_-]?(?:url|password)|token)$",
    re.IGNORECASE,
)
_REDACTION_MARKER_RE = re.compile(r"^\[REDACTED(?:_[A-Z0-9]+)?\]$")


def _replace_private_key(match: re.Match[str]) -> str:
    # Keep line count for safe evidence previews that retain source locations.
    return REDACTED_PRIVATE_KEY + ("\n" * match.group(0).count("\n"))


def _replace_credential_assignment(match: re.Match[str]) -> str:
    raw = match.group("value").strip("\"'`")
    # Runtime indirections are safe to retain and are useful evidence of a
    # bounded remediation.  Only literal values are replaced.
    if raw.startswith("[REDACTED_") or _REDACTION_MARKER_RE.match(raw) or re.match(
        r"(?i)^(?:process\.env\.|import\.meta\.env\.|os\.environ(?:\.get)?\(|getenv\(|system\.getenv\(|\$\{[A-Za-z_])",
        raw,
    ):
        # The unquoted marker regex intentionally stops before a closing ``]``;
        # leave that source character for the surrounding text rather than
        # manufacturing a second bracket.
        return f"{match.group('prefix')}{raw}"
    return f"{match.group('prefix')}{REDACTION_MARKER}"


def redact_text(
    value: str,
    *,
    secrets: Iterable[str] | None = None,
    max_length: int | None = None,
) -> str:
    """Return a bounded-context text value with credential-like literals removed.

    ``secrets`` is an optional exact-value list for project-specific values that
    cannot be recognised by a format heuristic.  It is applied before the
    generic patterns and is never retained by this function.
    """

    if not isinstance(value, str):
        raise TypeError("redact_text expects a string")

    redacted = value
    exact = sorted(
        {item for item in (secrets or ()) if isinstance(item, str) and item},
        key=len,
        reverse=True,
    )
    for secret in exact:
        redacted = redacted.replace(secret, REDACTION_MARKER)

    # Reuse the Phase 2/3 implementation first, then cover generic credential
    # assignments and token forms that may occur in JSON/YAML evidence.
    redacted = _redact_ai_text(redacted)
    redacted = _PRIVATE_KEY_RE.sub(_replace_private_key, redacted)
    redacted = _BEARER_RE.sub(f"Bearer {REDACTED_TOKEN}", redacted)
    redacted = _TOKEN_RE.sub(REDACTED_TOKEN, redacted)
    # Apply the broad word-pattern only in an assignment/structured-value
    # context; rule ids such as ``RG-SECRET-001`` are safe identifiers.
    if re.search(r"[=:]", redacted):
        redacted = _GENERIC_SECRET_LITERAL_RE.sub(REDACTION_MARKER, redacted)
    redacted = _CREDENTIAL_ASSIGNMENT_RE.sub(_replace_credential_assignment, redacted)
    if max_length is not None:
        redacted = _truncate_text(redacted, max_length=max_length)
    return redacted


def _is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and bool(_SENSITIVE_KEY_RE.search(key.strip()))


def redact_value(value: Any, *, secrets: Iterable[str] | None = None) -> Any:
    """Recursively redact mappings, sequences, and free-form text.

    The input object is never mutated.  Mapping keys are retained for audit
    readability while values under credential-like keys are replaced by a
    stable marker.  Tuples/sets become lists so the result is JSON-safe.
    """

    if isinstance(value, str):
        return redact_text(value, secrets=secrets)
    if isinstance(value, bytes | bytearray):
        return REDACTION_MARKER
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            result[key] = (
                REDACTION_MARKER
                if _is_sensitive_key(key) and item not in (None, "")
                else redact_value(item, secrets=secrets)
            )
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item, secrets=secrets) for item in value]
    return value


def redact_mapping(value: Mapping[str, Any], *, secrets: Iterable[str] | None = None) -> dict[Any, Any]:
    """Typed convenience wrapper for recursive mapping redaction."""

    if not isinstance(value, Mapping):
        raise TypeError("redact_mapping expects a mapping")
    result = redact_value(value, secrets=secrets)
    assert isinstance(result, dict)
    return result


def redact_evidence(value: str, *, secrets: Iterable[str] | None = None) -> str:
    """Redact free-form finding evidence before it is displayed or persisted."""

    return redact_text(value, secrets=secrets)


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            # Mapping keys are labels/identifiers.  Inspect only values here;
            # structured sensitive-key validation below handles key/value pairs.
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_strings(item)


def contains_raw_secret(value: Any, *, secrets: Iterable[str] | None = None) -> bool:
    """Return whether a value still contains a recognisable raw credential."""

    exact = [item for item in (secrets or ()) if isinstance(item, str) and item]
    for text in _iter_strings(value):
        if any(secret in text for secret in exact):
            return True
        if (
            _PRIVATE_KEY_RE.search(text)
            or _BEARER_RE.search(text)
            or _TOKEN_RE.search(text)
            or _URL_CREDENTIAL_RE.search(text)
            or (bool(re.search(r"[=:]", text)) and _GENERIC_SECRET_LITERAL_RE.search(text))
        ):
            return True
        # Assignment values are unsafe unless already replaced by a marker.
        for match in _CREDENTIAL_ASSIGNMENT_RE.finditer(text):
            candidate = match.group("value").strip("\"'`")
            if candidate.startswith("[REDACTED_") or _REDACTION_MARKER_RE.match(candidate) or re.match(
                r"(?i)^(?:process\.env\.|import\.meta\.env\.|os\.environ(?:\.get)?\(|getenv\(|system\.getenv\(|\$\{[A-Za-z_])",
                candidate,
            ):
                continue
            if candidate:
                return True
    # Structured payloads do not necessarily contain the key and value in one
    # text string (``{"password": "value"}``), so inspect that relationship
    # explicitly as well.
    def _mapping_has_raw_secret(item: Any) -> bool:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if _is_sensitive_key(key) and nested not in (None, ""):
                    if isinstance(nested, str) and _REDACTION_MARKER_RE.match(nested):
                        pass
                    else:
                        return True
                if _mapping_has_raw_secret(nested):
                    return True
        elif isinstance(item, (list, tuple, set, frozenset)):
            return any(_mapping_has_raw_secret(nested) for nested in item)
        return False

    if _mapping_has_raw_secret(value):
        return True
    return False


def assert_no_raw_secrets(value: Any, *, secrets: Iterable[str] | None = None) -> Any:
    """Reject a payload that still carries a raw credential.

    The original value is returned for ergonomic use in persistence pipelines;
    callers can use ``redact_for_persistence`` when they want a sanitized copy.
    """

    if contains_raw_secret(value, secrets=secrets):
        raise RawSecretError("raw secret detected in persistence payload")
    return value


def redact_for_persistence(value: Any, *, secrets: Iterable[str] | None = None) -> Any:
    """Create a JSON-safe redacted copy and fail closed if anything remains."""

    redacted = redact_value(value, secrets=secrets)
    return assert_no_raw_secrets(redacted, secrets=secrets)


# Friendly aliases used by evidence/store integrations and external adapters.
redact_payload = redact_for_persistence
sanitize_for_persistence = redact_for_persistence
redact = redact_value
redact_recursive = redact_value
redact_json = redact_for_persistence
assert_redacted = assert_no_raw_secrets
contains_secret = contains_raw_secret


def redact_finding(finding: Any, *, secrets: Iterable[str] | None = None) -> dict[str, Any]:
    """Return a safe JSON mapping for a Finding-like Pydantic object."""

    if hasattr(finding, "model_dump"):
        payload = finding.model_dump(mode="json")
    elif isinstance(finding, Mapping):
        payload = dict(finding)
    else:
        raise TypeError("redact_finding expects a Pydantic model or mapping")
    result = redact_for_persistence(payload, secrets=secrets)
    assert isinstance(result, dict)
    return result


__all__ = [
    "REDACTION_MARKER",
    "REDACTED_FRAGMENT",
    "REDACTED_PATH",
    "REDACTED_PRIVATE_KEY",
    "REDACTED_QUERY",
    "REDACTED_SECRET",
    "REDACTED_TOKEN",
    "REDACTED_URL",
    "RawSecretError",
    "SecretPersistenceError",
    "assert_no_raw_secrets",
    "assert_redacted",
    "contains_secret",
    "contains_raw_secret",
    "redact_evidence",
    "redact_finding",
    "redact_for_persistence",
    "redact_mapping",
    "redact_payload",
    "redact",
    "redact_json",
    "redact_recursive",
    "redact_text",
    "redact_value",
    "sanitize_for_persistence",
]
