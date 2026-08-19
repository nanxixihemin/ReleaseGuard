"""Release-time checks for debug, development, and verbose logging settings."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._utils import (
    is_comment_line,
    is_documentation_path,
    is_test_path,
    iter_text_files,
    iter_text_lines,
    make_finding,
)
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_DEBUG_ENABLED_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?debug[\"']?\s*(?:=|:)\s*"
    r"(?:true|1|[\"']true[\"']?|[\"']1[\"']?)(?![A-Za-z0-9_])"
)
_NODE_DEVELOPMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?node_env[\"']?\s*(?:=|:)\s*"
    r"(?:[\"']?development[\"']?|[\"']?dev[\"']?)(?![A-Za-z0-9_])"
)
_FLASK_DEBUG_RE = re.compile(
    r"(?i)(?:\b(?:app|application)\.debug\s*=\s*true|\b(?:app|application)\.run\s*\([^\n)]*\bdebug\s*=\s*true)"
)
_LOGGING_DEBUG_RE = re.compile(
    r"(?i)(?:\blogging\.basicConfig\s*\([^\n)]*\b(?:logging\.)?DEBUG\b|"
    r"\b(?:logger|logging)\.setLevel\s*\(\s*(?:logging\.)?DEBUG\s*\))"
)
_VERBOSE_LOGGING_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?(?:log|logging)[_-]?level[\"']?\s*(?:=|:)\s*"
    r"(?:[\"']?(?:debug|verbose|trace)[\"']?)(?![A-Za-z0-9_])"
)
_SOURCE_MAP_RE = re.compile(
    r"(?i)(?:\bproductionSourceMap\b|\bsourcemap\b)\s*(?:=|:)\s*"
    r"(?:true|[\"']true[\"']?)|\bdevtool\b\s*(?:=|:)\s*[\"']source-map[\"']"
)
_DEVELOPMENT_PROFILE_RE = re.compile(
    r"(?i)(?:\bspring\.profiles\.active\b|[\"']?(?:profile|environment)[\"']?)\s*(?:=|:)\s*"
    r"[\"']?(?:dev|development)[\"']?(?![A-Za-z0-9_])"
)
_BUILD_MODE_DEBUG_RE = re.compile(
    r"(?i)\bbuildMode\b\s*(?:=|:)\s*[\"']?debug[\"']?"
)
_ANDROID_DEBUGGABLE_RE = re.compile(
    r"(?i)\bdebuggable\b\s*(?:=\s*)?(?:true|1)\b"
)
_PRODUCTION_RE = re.compile(r"(?<![a-z])prod(?:uction)?(?![a-z])", re.IGNORECASE)

_MATCHERS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("debug_enabled", "Debug mode enabled", _DEBUG_ENABLED_RE),
    ("node_development", "Node environment set to development", _NODE_DEVELOPMENT_RE),
    ("flask_debug", "Flask debug mode enabled", _FLASK_DEBUG_RE),
    ("logging_debug", "Debug logging enabled", _LOGGING_DEBUG_RE),
    ("verbose_logging", "Verbose logging enabled", _VERBOSE_LOGGING_RE),
    ("source_maps", "Production source maps enabled", _SOURCE_MAP_RE),
    ("development_profile", "Development profile enabled", _DEVELOPMENT_PROFILE_RE),
    ("build_mode_debug", "Debug build mode configured", _BUILD_MODE_DEBUG_RE),
    ("android_debuggable", "Android debug build enabled", _ANDROID_DEBUGGABLE_RE),
)


def _severity_for(kind: str, path: Path | str, line: str) -> Severity:
    if is_documentation_path(path) or is_test_path(path) or is_comment_line(line):
        return Severity.LOW
    if kind in {
        "debug_enabled",
        "node_development",
        "flask_debug",
        "development_profile",
        "build_mode_debug",
        "android_debuggable",
    }:
        return Severity.HIGH
    if kind == "source_maps" and _PRODUCTION_RE.search(Path(path).as_posix() + " " + line):
        return Severity.HIGH
    return Severity.MEDIUM


def _explanation_for(kind: str) -> str:
    explanations = {
        "debug_enabled": "Debug mode can expose diagnostic detail and unsafe behavior in a production release.",
        "node_development": "A deployable Node configuration selects development behavior rather than production behavior.",
        "flask_debug": "Flask debug mode can expose an interactive debugger and should never be enabled in production.",
        "logging_debug": "Debug logging can expose implementation detail or sensitive operational data at release time.",
        "verbose_logging": "Verbose logging may disclose operational or request data beyond the intended production level.",
        "source_maps": "Production source maps can reveal source structure and should be an explicit release decision.",
        "development_profile": "A development profile can select local services, debug logging, or non-production credentials.",
        "build_mode_debug": "A release configuration declares a debug build mode instead of a production build mode.",
        "android_debuggable": "Android debugging is enabled and can expose non-production behavior in a release build.",
    }
    return explanations[kind]


class DebugRule(AuditRule):
    """Detect debugging configuration that should be removed or consciously gated."""

    rule_id = "RG-DEBUG-001"
    name = "Debug or development configuration"
    category = "debug"
    description = "Detects enabled debug modes, development profiles, and verbose production settings."
    default_severity = Severity.HIGH

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_text_files(context):
            for line_number, line in iter_text_lines(context, path):
                for kind, title, pattern in _MATCHERS:
                    for match in pattern.finditer(line):
                        severity = _severity_for(kind, path, line)
                        # Evidence is a stable label instead of the full source line,
                        # which can contain unrelated configuration values.
                        evidence = title
                        findings.append(
                            make_finding(
                                rule_id=self.rule_id,
                                title=title,
                                severity=severity,
                                category=self.category,
                                context=context,
                                path=path,
                                line=line_number,
                                evidence=evidence,
                                explanation=_explanation_for(kind),
                                recommendation=(
                                    "Set an explicit production-safe value for this setting and keep "
                                    "development-only behavior in non-release configuration."
                                ),
                                confidence=0.95 if severity is Severity.HIGH else 0.84,
                                metadata={"debug_setting": kind, "match_start": match.start()},
                            )
                        )

        return findings


DebugConfigurationRule = DebugRule


__all__ = ["DebugConfigurationRule", "DebugRule"]
