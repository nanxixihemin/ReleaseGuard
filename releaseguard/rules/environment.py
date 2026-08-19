"""Detection of development and non-production runtime endpoints."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from ..models import Finding, Severity
from ._utils import (
    is_comment_line,
    is_config_path,
    is_documentation_path,
    is_source_path,
    is_test_path,
    iter_text_files,
    iter_text_lines,
    make_finding,
)
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_LOOPBACK_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<endpoint>(?:https?://(?:[^/\s@]+@)?)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)"
    r"(?::\d{1,5})?(?:/[^\s'\"`\]\[(){}<>]*)?)",
    re.IGNORECASE,
)
_HTTP_URL_RE = re.compile(
    r"(?P<endpoint>https?://[^\s'\"`\]\[(){}<>]+)", re.IGNORECASE
)
_NONPRODUCTION_LABELS = {
    "debug",
    "dev",
    "development",
    "mock",
    "stage",
    "staging",
    "test",
    "testing",
}
_PRODUCTION_RE = re.compile(r"(?<![a-z])prod(?:uction)?(?![a-z])", re.IGNORECASE)
_SENSITIVE_QUERY_KEY_RE = re.compile(
    r"(?:token|api[_-]?key|secret|pass(?:word|wd)?|auth(?:orization)?|"
    r"credential|access[_-]?key)",
    re.IGNORECASE,
)
_SECRET_LIKE_QUERY_VALUE_RE = re.compile(
    r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,})$",
    re.IGNORECASE,
)


def _is_nonproduction_url(endpoint: str) -> bool:
    """Return whether an HTTP URL host contains an explicit non-production label."""

    try:
        host = urlsplit(endpoint).hostname or ""
    except ValueError:
        return False
    labels = re.split(r"[.-]", host.lower())
    return any(label in _NONPRODUCTION_LABELS for label in labels)


def _is_pattern_definition(line: str) -> bool:
    """Avoid treating the scanner's own endpoint regexes as configured URLs."""

    normalized = line.lower()
    return "re.compile" in normalized or "regexp(" in normalized


def _safe_endpoint_evidence(endpoint: str) -> str:
    """Remove credentials and sensitive query values before rendering an endpoint."""

    without_fragment = endpoint.split("#", maxsplit=1)[0]
    without_userinfo = re.sub(r"(?<=://)[^/\s@]*@", "***@", without_fragment)

    def redact_query_value(match: re.Match[str]) -> str:
        key = match.group("key")
        value = match.group("value")
        if _SENSITIVE_QUERY_KEY_RE.search(key) or _SECRET_LIKE_QUERY_VALUE_RE.fullmatch(value):
            return f"{match.group('prefix')}{key}=***"
        return match.group(0)

    return re.sub(
        r"(?P<prefix>[?&])(?P<key>[^=&?#]+)=(?P<value>[^&#\s]*)",
        redact_query_value,
        without_userinfo,
    )


def _is_endpoint_assignment(line: str, start: int) -> bool:
    """Prefer concrete URL/config assignments over incidental prose mentions."""

    prefix = line[:start]
    return bool(
        re.search(
            r"(?i)(?:api|url|uri|endpoint|backend|server|host|origin|proxy|base|service)"
            r"[A-Za-z0-9_.-]*\s*(?:=|:)",
            prefix,
        )
    )


def _is_production_context(path: Path | str, line: str) -> bool:
    path_text = Path(path).as_posix()
    return bool(_PRODUCTION_RE.search(path_text) or _PRODUCTION_RE.search(line))


def _severity_for(
    path: Path | str,
    line: str,
    *,
    loopback: bool,
    assignment: bool,
) -> Severity:
    if is_documentation_path(path) or is_test_path(path) or is_comment_line(line):
        return Severity.LOW
    if loopback and _is_production_context(path, line):
        return Severity.CRITICAL
    if assignment or is_config_path(path):
        return Severity.HIGH
    if is_source_path(path):
        return Severity.MEDIUM
    return Severity.LOW


def _title_for(*, loopback: bool, severity: Severity) -> str:
    if loopback and severity is Severity.CRITICAL:
        return "Production endpoint points to a loopback address"
    if loopback:
        return "Development endpoint points to a loopback address"
    return "Non-production endpoint configured"


class EnvironmentRule(AuditRule):
    """Find URLs that commonly work in development but fail or expose risk in release."""

    rule_id = "RG-ENV-001"
    name = "Development endpoint configuration"
    category = "environment"
    description = "Detects loopback and explicitly non-production HTTP endpoints."
    default_severity = Severity.HIGH

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_text_files(context):
            for line_number, line in iter_text_lines(context, path):
                if _is_pattern_definition(line):
                    continue
                reported_spans: list[tuple[int, int]] = []

                for match in _LOOPBACK_RE.finditer(line):
                    endpoint = match.group("endpoint").rstrip(".,;:")
                    assignment = _is_endpoint_assignment(line, match.start("endpoint"))
                    severity = _severity_for(
                        path,
                        line,
                        loopback=True,
                        assignment=assignment,
                    )
                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title=_title_for(loopback=True, severity=severity),
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=_safe_endpoint_evidence(endpoint),
                            explanation=(
                                "Loopback addresses are reachable only from the local machine and are "
                                "not a valid production service endpoint."
                            ),
                            recommendation=(
                                "Replace this value with a deployment-specific service URL supplied by "
                                "protected production configuration."
                            ),
                            confidence=0.96 if assignment else 0.82,
                            metadata={
                                "endpoint_kind": "loopback",
                                "assignment_context": assignment,
                            },
                        )
                    )
                    reported_spans.append(match.span("endpoint"))

                for match in _HTTP_URL_RE.finditer(line):
                    span = match.span("endpoint")
                    if any(span[0] < end and start < span[1] for start, end in reported_spans):
                        continue
                    endpoint = match.group("endpoint").rstrip(".,;:")
                    if not _is_nonproduction_url(endpoint):
                        continue
                    assignment = _is_endpoint_assignment(line, span[0])
                    severity = _severity_for(
                        path,
                        line,
                        loopback=False,
                        assignment=assignment,
                    )
                    findings.append(
                        make_finding(
                            rule_id=self.rule_id,
                            title=_title_for(loopback=False, severity=severity),
                            severity=severity,
                            category=self.category,
                            context=context,
                            path=path,
                            line=line_number,
                            evidence=_safe_endpoint_evidence(endpoint),
                            explanation=(
                                "The endpoint host is explicitly labelled as a development, test, staging, "
                                "mock, or debug environment."
                            ),
                            recommendation=(
                                "Select the production service endpoint through release configuration and "
                                "keep non-production URLs out of deployable defaults."
                            ),
                            confidence=0.91 if assignment else 0.74,
                            metadata={
                                "endpoint_kind": "non_production",
                                "assignment_context": assignment,
                            },
                        )
                    )
                    reported_spans.append(span)

        return findings


DevelopmentEndpointRule = EnvironmentRule


__all__ = ["DevelopmentEndpointRule", "EnvironmentRule"]
