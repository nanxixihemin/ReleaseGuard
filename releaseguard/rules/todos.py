"""Heuristic release-risk scoring for TODO, FIXME, HACK, and XXX markers."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._utils import (
    compact_evidence,
    is_documentation_path,
    is_test_path,
    iter_text_files,
    iter_text_lines,
    make_finding,
)
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_MARKER_RE = re.compile(r"\b(?P<marker>TODO|FIXME|HACK|XXX)\b(?:\s*[:\-]?\s*(?P<detail>.*))?", re.IGNORECASE)
_SECURITY_RE = re.compile(
    r"\b(?:auth(?:entication|orization)?|permission|access[ _-]?control|security|"
    r"payment|billing|checkout|credential|secret|token|password|encrypt(?:ion)?|"
    r"crypto(?:graphy)?|injection|sanitize|validation)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[\\/_.-])(?:auth|security|payment|billing|checkout|identity|permission|access)(?:[\\/_.-]|$)",
    re.IGNORECASE,
)
_LEADING_COMMENT_PREFIXES = {"#", "//", "/*", "*", "<!--", ";"}


def _is_sensitive_todo(path: Path | str, detail: str) -> bool:
    return bool(_SECURITY_RE.search(detail) or _SENSITIVE_PATH_RE.search(Path(path).as_posix()))


def _is_actionable_marker(path: Path | str, line: str, match: re.Match[str]) -> bool:
    """Require a comment-style marker and ignore documentation prose.

    Strings such as a rule description or regex source mention the marker names,
    but do not represent unfinished work.  Real source comments remain language
    agnostic across the common single-line forms.
    """

    if is_documentation_path(path):
        return False
    prefix = line[: match.start()]
    if prefix.strip() in _LEADING_COMMENT_PREFIXES:
        return True

    # Permit normal trailing comments while ignoring marker names embedded in
    # quoted source strings. This intentionally implements only the common
    # comment forms shared by the Phase 1 language-agnostic rules.
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(prefix):
        character = prefix[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if prefix.startswith("//", index) or prefix.startswith("/*", index) or prefix.startswith("<!--", index):
            return True
        if character == "#":
            return True
        index += 1
    return False


def _severity_for(
    *,
    path: Path | str,
    marker: str,
    detail: str,
    production_marker_count: int,
) -> Severity:
    sensitive = _is_sensitive_todo(path, detail)
    if is_documentation_path(path) or is_test_path(path):
        return Severity.MEDIUM if sensitive else Severity.LOW
    if sensitive:
        return Severity.HIGH
    if production_marker_count >= 10:
        return Severity.HIGH
    if production_marker_count >= 4 or marker in {"FIXME", "HACK", "XXX"}:
        return Severity.MEDIUM
    return Severity.LOW


def _title_for(marker: str, sensitive: bool) -> str:
    if sensitive:
        return f"Security-relevant {marker} remains in release code"
    return f"Unresolved {marker} marker"


class TodoRule(AuditRule):
    """Surface incomplete work without treating every comment as a release block."""

    rule_id = "RG-TODO-001"
    name = "Unresolved implementation markers"
    category = "todo"
    description = "Scores TODO, FIXME, HACK, and XXX markers by location, context, and count."
    default_severity = Severity.LOW

    def check(self, context: "ProjectContext") -> list[Finding]:
        entries: list[tuple[Path, int, str, str]] = []
        production_marker_count = 0

        for path in iter_text_files(context):
            is_nonproduction_path = is_documentation_path(path) or is_test_path(path)
            for line_number, line in iter_text_lines(context, path):
                for match in _MARKER_RE.finditer(line):
                    if not _is_actionable_marker(path, line, match):
                        continue
                    marker = match.group("marker").upper()
                    detail = (match.group("detail") or "").strip()
                    entries.append((path, line_number, marker, detail))
                    if not is_nonproduction_path:
                        production_marker_count += 1

        findings: list[Finding] = []
        for path, line_number, marker, detail in entries:
            sensitive = _is_sensitive_todo(path, detail)
            severity = _severity_for(
                path=path,
                marker=marker,
                detail=detail,
                production_marker_count=production_marker_count,
            )
            # Details can accidentally contain a copied credential. The original
            # detail remains local to severity classification but never reaches
            # a Finding, JSON report, or Markdown report.
            evidence = f"{marker} marker"
            findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=_title_for(marker, sensitive),
                    severity=severity,
                    category=self.category,
                    context=context,
                    path=path,
                    line=line_number,
                    evidence=compact_evidence(evidence),
                    explanation=(
                        "The marker indicates incomplete work that should be reviewed before a release. "
                        "Severity is raised for security-sensitive work, risky locations, or a high count."
                    ),
                    recommendation=(
                        "Resolve the outstanding work, record an explicit release decision, or move "
                        "non-release notes to tracked planning documentation."
                    ),
                    confidence=0.93 if sensitive else 0.8,
                    metadata={
                        "marker": marker,
                        "security_relevant": sensitive,
                        "production_marker_count": production_marker_count,
                    },
                )
            )

        return findings


TodosRule = TodoRule
TodoMarkerRule = TodoRule


__all__ = ["TodoMarkerRule", "TodoRule", "TodosRule"]
