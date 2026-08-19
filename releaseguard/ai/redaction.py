"""Conservative local redaction utilities for AI-bound text."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"
REDACTED_URL = "[REDACTED_URL]"
REDACTED_PATH = "[REDACTED_PATH]"
REDACTED_PRIVATE_KEY = "[REDACTED_PRIVATE_KEY]"
REDACTED_QUERY = "[REDACTED_QUERY]"
REDACTED_FRAGMENT = "[REDACTED_FRAGMENT]"
TRUNCATION_MARKER = "...[truncated]"


_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}(?![A-Za-z0-9_-])"
)
_KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{12,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}"
    r")(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,31}://[^\s<>\"'`]+",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<prefix>\b(?:[A-Za-z][A-Za-z0-9_.-]*[_-])?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"bearer[_-]?token|client[_-]?secret|database[_-]?url|db[_-]?(?:url|password)|"
    r"password|passwd|private[_-]?key|secret|token)\b\s*(?:=|:)\s*)"
    r"(?P<value>(?:[\"'`][^\r\n\"'`]*[\"'`])|(?:[^\s,;#]+))"
)
_WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s<>\"'`]*")
_UNC_PATH_RE = re.compile(r"(?<![\\/])\\\\[^\s<>\"'`]+")
_POSIX_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.:/-])/(?!/)[^\s<>\"'`]+")
_HOME_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])~[\\/][^\s<>\"'`]+")
_SAFE_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _replace_private_key(match: re.Match[str]) -> str:
    # Preserve line count so excerpt line ranges remain meaningful after redaction.
    return REDACTED_PRIVATE_KEY + ("\n" * match.group(0).count("\n"))


def _replace_assignment(match: re.Match[str]) -> str:
    raw_value = match.group("value").strip("\"'`")
    # Environment indirections are safe context and are useful when reviewing
    # an approved migration.  Literal values remain redacted.
    if raw_value.startswith("[REDACTED_") or re.match(
        r"(?i)^(?:process\.env\.|import\.meta\.env\.|os\.environ(?:\.get)?\(|getenv\(|system\.getenv\(|\$\{[A-Za-z_])",
        raw_value,
    ):
        return f"{match.group('prefix')}{raw_value}"
    url_match = _URL_RE.fullmatch(raw_value)
    if url_match is not None:
        return f"{match.group('prefix')}{_redact_url(url_match)}"
    return f"{match.group('prefix')}{REDACTED_SECRET}"


def _redact_url(match: re.Match[str]) -> str:
    """Retain only a safe loopback endpoint shape; hide all other URLs."""

    try:
        parsed = urlsplit(match.group(0))
        host = (parsed.hostname or "").lower()
        if host not in _SAFE_LOCAL_HOSTS:
            return REDACTED_URL
        try:
            port = parsed.port
        except ValueError:
            return REDACTED_URL

        rendered_host = f"[{host}]" if ":" in host else host
        endpoint = f"{parsed.scheme.lower()}://{rendered_host}"
        if port is not None:
            endpoint += f":{port}"
        endpoint += parsed.path
        if parsed.query:
            endpoint += "?" + _redact_query(parsed.query)
        if parsed.fragment:
            endpoint += f"#{REDACTED_FRAGMENT}"
        return endpoint
    except (TypeError, ValueError):
        return REDACTED_URL


def _redact_query(query: str) -> str:
    """Keep query names for context while discarding every query value."""

    parts: list[str] = []
    for item in re.split(r"[&;]", query):
        key = item.split("=", maxsplit=1)[0]
        parts.append(f"{key}={REDACTED_QUERY}" if key else REDACTED_QUERY)
    return "&".join(parts)


def redact_text(value: str) -> str:
    """Remove common credential, URL, and absolute-path values from text.

    The function is intentionally conservative: AI receives less context rather
    than an accidental token, URL query, userinfo segment, or local filesystem
    path. It is deterministic and does not inspect any files or network state.
    """

    redacted = _PEM_PRIVATE_KEY_RE.sub(_replace_private_key, value)
    redacted = _BEARER_RE.sub(f"Bearer {REDACTED_TOKEN}", redacted)
    redacted = _JWT_RE.sub(REDACTED_TOKEN, redacted)
    redacted = _KNOWN_TOKEN_RE.sub(REDACTED_TOKEN, redacted)
    redacted = _URL_RE.sub(_redact_url, redacted)
    redacted = _SECRET_ASSIGNMENT_RE.sub(_replace_assignment, redacted)
    redacted = _WINDOWS_PATH_RE.sub(REDACTED_PATH, redacted)
    redacted = _UNC_PATH_RE.sub(REDACTED_PATH, redacted)
    redacted = _HOME_PATH_RE.sub(REDACTED_PATH, redacted)
    return _POSIX_PATH_RE.sub(REDACTED_PATH, redacted)


def truncate_text(value: str, *, max_length: int) -> str:
    """Bound a string without exceeding ``max_length``."""

    if max_length < len(TRUNCATION_MARKER):
        raise ValueError("max_length must fit the truncation marker")
    if len(value) <= max_length:
        return value
    return value[: max_length - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def redact_and_truncate(value: str, *, max_length: int) -> str:
    """Redact first, then enforce a deterministic payload-size limit."""

    return truncate_text(redact_text(value), max_length=max_length)


__all__ = [
    "REDACTED_PATH",
    "REDACTED_PRIVATE_KEY",
    "REDACTED_FRAGMENT",
    "REDACTED_QUERY",
    "REDACTED_SECRET",
    "REDACTED_TOKEN",
    "REDACTED_URL",
    "TRUNCATION_MARKER",
    "redact_and_truncate",
    "redact_text",
    "truncate_text",
]
