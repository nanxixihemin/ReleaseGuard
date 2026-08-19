"""Detection of likely committed credentials with report-safe evidence."""

from __future__ import annotations

from math import log2
from pathlib import Path
import re
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._utils import (
    is_documentation_path,
    is_test_path,
    iter_text_files,
    iter_text_lines,
    make_finding,
)
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_OPENAI_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>sk-(?:proj-)?[A-Za-z0-9_-]{12,})(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_GITHUB_CLASSIC_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<token>ghp_[A-Za-z0-9]{20,255})(?![A-Za-z0-9_])"
)
_GITHUB_FINE_GRAINED_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<token>github_pat_[A-Za-z0-9_]{20,255})(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_RE = re.compile(
    r"(?<![A-Z0-9])(?P<token>AKIA[0-9A-Z]{16})(?![A-Z0-9])"
)
_GOOGLE_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>AIza[0-9A-Za-z_-]{30,})(?![A-Za-z0-9_-])"
)
_SLACK_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>xox[baprs]-[A-Za-z0-9-]{12,})(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<token>eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+(?P<kind>(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE\s+KEY-----",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(
    r"\bBearer\s+(?P<token>[A-Za-z0-9._~+/=-]{12,})", re.IGNORECASE
)
_DATABASE_URL_RE = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://"
    r"(?P<user>[^:/\s]+):(?P<password>[^@/\s]+)@(?P<host>[^/\s'\"`]+)",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    r"""
    (?P<key>[\"'`]?[A-Za-z_][A-Za-z0-9_.-]*[\"'`]?)
    \s*(?:=|:)\s*
    (?:
        (?P<quote>[\"'`])(?P<quoted>[^\"'`\r\n]{1,1024})(?P=quote)
        |
        (?P<bare>[^\s,;#]+)
    )
    """,
    re.VERBOSE,
)

_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI-style API key", _OPENAI_KEY_RE),
    ("GitHub personal access token", _GITHUB_CLASSIC_RE),
    ("GitHub fine-grained personal access token", _GITHUB_FINE_GRAINED_RE),
    ("AWS access key ID", _AWS_ACCESS_KEY_RE),
    ("Google API key", _GOOGLE_API_KEY_RE),
    ("Slack token", _SLACK_TOKEN_RE),
    ("JSON Web Token", _JWT_RE),
)

_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "your_",
    "your-",
    "replace",
    "changeme",
    "change-me",
    "dummy",
    "sample",
    "redacted",
    "not-set",
    "not_set",
)
_EXACT_PLACEHOLDERS = {
    "",
    "none",
    "null",
    "undefined",
    "false",
    "true",
    "secret",
    "password",
    "token",
    "api_key",
}


def mask_secret(value: str) -> str:
    """Mask a credential while retaining enough shape for an operator to recognize it.

    The original value is never returned.  Prefixes such as ``sk-`` and ``ghp_``
    are deliberately retained because they help users identify which integration
    needs remediation without revealing authentication material.
    """

    token = value.strip().strip("\"'`")
    if not token:
        return "***"

    lower_token = token.lower()
    prefix_length = 3
    for prefix in ("github_pat_", "sk-proj-", "ghp_", "akia", "aiza", "xox", "sk-"):
        if lower_token.startswith(prefix):
            prefix_length = len(prefix)
            break

    if len(token) <= prefix_length + 3:
        # Never show a complete short credential. This also covers short
        # database passwords, which do not have one of the known prefixes.
        return "***"

    suffix_length = 4 if len(token) > prefix_length + 8 else 2
    visible_prefix = token[:prefix_length]
    visible_suffix = token[-suffix_length:]
    masked_length = max(4, min(12, len(token) - prefix_length - suffix_length))
    return f"{visible_prefix}{'*' * masked_length}{visible_suffix}"


def is_placeholder(value: str) -> bool:
    """Identify explicit sample values so generic assignments do not over-report."""

    normalized = value.strip().strip("\"'`").lower()
    if normalized in _EXACT_PLACEHOLDERS:
        return True
    if normalized.startswith(("${", "{{", "<")) or normalized.endswith(("}", ">")):
        return True
    return any(marker in normalized for marker in _PLACEHOLDER_MARKERS)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / length) * log2(count / length) for count in counts.values())


def _is_secret_assignment_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    secret_names = (
        "apikey",
        "accesskey",
        "accesstoken",
        "authtoken",
        "bearertoken",
        "clientsecret",
        "databaseurl",
        "dbconnection",
        "dbpassword",
        "dburl",
        "password",
        "passwd",
        "secret",
        "token",
    )
    return any(normalized == name or normalized.endswith(name) for name in secret_names)


def _is_high_entropy_secret(value: str) -> bool:
    candidate = value.strip().strip("\"'`")
    if len(candidate) < 16 or is_placeholder(candidate):
        return False
    # Tokens are usually mixed alphabet/digit values.  The entropy threshold keeps
    # plain wording such as ``password = development`` out of the report.
    character_classes = sum(
        (
            any(character.islower() for character in candidate),
            any(character.isupper() for character in candidate),
            any(character.isdigit() for character in candidate),
            any(not character.isalnum() for character in candidate),
        )
    )
    return character_classes >= 2 and _entropy(candidate) >= 3.0


def _is_likely_password_literal(key: str, value: str) -> bool:
    """Detect short, mixed password literals without matching ordinary prose."""

    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    if not (normalized_key == "password" or normalized_key.endswith(("password", "passwd"))):
        return False
    candidate = value.strip().strip("\"'`")
    if len(candidate) < 8 or is_placeholder(candidate):
        return False
    has_letter = any(character.isalpha() for character in candidate)
    has_non_letter = any(character.isdigit() or not character.isalnum() for character in candidate)
    return has_letter and has_non_letter


def _is_literal_config_assignment(path: Path | str, line: str, match: re.Match[str]) -> bool:
    """Accept simple literals while rejecting expressions such as ``token = call()``.

    Generic secret names are common local variables.  A quoted literal is a
    useful signal in source code, while bare values are accepted only for
    configuration files where ``KEY=value`` / ``key: value`` is normal syntax.
    """

    if match.group("quoted") is not None:
        return True
    candidate = Path(path)
    bare_config_suffixes = {".env", ".ini", ".properties", ".toml", ".yaml", ".yml"}
    if not (candidate.name.lower().startswith(".env") or candidate.suffix.lower() in bare_config_suffixes):
        return False
    prefix = line[: match.start("key")].strip()
    return prefix in {"", "export", "ENV"}


def _path_severity(path: Path | str) -> Severity:
    name = Path(path).name.lower()
    if is_documentation_path(path) or is_test_path(path) or name.endswith((".example", ".sample")):
        return Severity.MEDIUM
    return Severity.CRITICAL


def _overlaps(span: tuple[int, int], reported_spans: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in reported_spans)


def _assignment_evidence(key: str, value: str) -> str:
    return f"{key.strip(chr(34) + chr(39) + '`')}={mask_secret(value)}"


class SecretRule(AuditRule):
    """Find high-confidence credentials without emitting raw secret values."""

    rule_id = "RG-SECRET-001"
    name = "Possible credential in project files"
    category = "secrets"
    description = "Detects common credential formats and high-entropy secret assignments."
    default_severity = Severity.CRITICAL

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_text_files(context):
            severity = _path_severity(path)
            for line_number, line in iter_text_lines(context, path):
                reported_spans: list[tuple[int, int]] = []

                for secret_type, pattern in _TOKEN_PATTERNS:
                    for match in pattern.finditer(line):
                        token = match.group("token")
                        if is_placeholder(token) or _overlaps(match.span("token"), reported_spans):
                            continue
                        evidence = mask_secret(token)
                        findings.append(
                            make_finding(
                                rule_id=self.rule_id,
                                title=f"Possible {secret_type} detected",
                                severity=severity,
                                category=self.category,
                                context=context,
                                path=path,
                                line=line_number,
                                evidence=evidence,
                                explanation=(
                                    "A credential-like value appears in a file that may be included "
                                    "in the release artifact or source repository."
                                ),
                                recommendation=(
                                    "Remove the value from source control, rotate the credential, and "
                                    "load it from a secrets manager or protected runtime environment."
                                ),
                                confidence=0.98,
                                metadata={"secret_type": secret_type},
                            )
                        )
                        reported_spans.append(match.span("token"))

                for match in _PRIVATE_KEY_RE.finditer(line):
                    if _overlaps(match.span(), reported_spans):
                        continue
                    key_kind = (match.group("kind") or "").strip().upper()
                    label = f"{key_kind} private key".strip()
                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title="Private key material detected",
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=f"-----BEGIN {label}-----",
                            explanation=(
                                "A private key header is present. Private key material must not be "
                                "stored in a release repository or artifact."
                            ),
                            recommendation=(
                                "Remove the key from the project, revoke or rotate it if exposed, and "
                                "provision it through a protected key-management workflow."
                            ),
                            confidence=1.0,
                            metadata={"secret_type": "private_key"},
                        )
                    )
                    reported_spans.append(match.span())

                for match in _BEARER_RE.finditer(line):
                    token = match.group("token")
                    if is_placeholder(token) or _overlaps(match.span("token"), reported_spans):
                        continue
                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title="Bearer token detected",
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=f"Bearer {mask_secret(token)}",
                            explanation=(
                                "A bearer credential can authorize requests and should not be embedded "
                                "in a distributable project file."
                            ),
                            recommendation=(
                                "Remove and rotate the token, then inject it through a protected runtime "
                                "credential store."
                            ),
                            confidence=0.97,
                            metadata={"secret_type": "bearer_token"},
                        )
                    )
                    reported_spans.append(match.span("token"))

                for match in _DATABASE_URL_RE.finditer(line):
                    password = match.group("password")
                    if is_placeholder(password) or _overlaps(match.span(), reported_spans):
                        continue
                    evidence = (
                        f"{match.group('scheme').lower()}://***:{mask_secret(password)}"
                        f"@{match.group('host')}"
                    )
                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title="Database URL contains credentials",
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=evidence,
                            explanation=(
                                "A database connection string includes inline authentication material."
                            ),
                            recommendation=(
                                "Move the connection secret into protected configuration and rotate the "
                                "database password if this file was shared."
                            ),
                            confidence=0.99,
                            metadata={"secret_type": "database_url"},
                        )
                    )
                    reported_spans.append(match.span())

                for match in _ASSIGNMENT_RE.finditer(line):
                    key = match.group("key").strip("\"'`")
                    value = match.group("quoted") or match.group("bare") or ""
                    value_span = match.span("quoted") if match.group("quoted") is not None else match.span("bare")
                    high_entropy = _is_high_entropy_secret(value)
                    password_literal = _is_likely_password_literal(key, value)
                    if (
                        not _is_secret_assignment_key(key)
                        or not (high_entropy or password_literal)
                        or not _is_literal_config_assignment(path, line, match)
                        or _overlaps(value_span, reported_spans)
                    ):
                        continue

                    title = (
                        "Potential password assignment detected"
                        if password_literal and not high_entropy
                        else "High-entropy credential assignment detected"
                    )
                    secret_type = "password_literal" if password_literal and not high_entropy else "high_entropy_assignment"

                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title=title,
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=_assignment_evidence(key, value),
                            explanation=(
                                "A credential-named setting contains a literal rather than a protected "
                                "runtime reference."
                            ),
                            recommendation=(
                                "Replace the literal with a protected environment or secrets-manager "
                                "reference and rotate the exposed value."
                            ),
                            confidence=0.9,
                            metadata={"secret_type": secret_type, "key_name": key},
                        )
                    )
                    reported_spans.append(value_span)

        return findings


# A plural alias keeps registration ergonomic for integrations that use filenames.
SecretsRule = SecretRule
SecretCredentialRule = SecretRule


__all__ = [
    "SecretCredentialRule",
    "SecretRule",
    "SecretsRule",
    "is_placeholder",
    "mask_secret",
]
