"""Minimal release configuration checks that complement, rather than duplicate, rules."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

from ..models import Finding, Severity
from ._utils import iter_files, iter_text_lines, make_finding, read_text
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_DOCKER_RELOAD_RE = re.compile(r"\b(?:uvicorn|flask|django-admin|python\s+-m\s+flask)\b.*\b(?:--reload|--debug)\b|\b--reload\b", re.IGNORECASE)
_DJANGO_RUNSERVER_RE = re.compile(r"\b(?:manage\.py|django-admin)\s+runserver\b", re.IGNORECASE)


def _root_files(context: "ProjectContext") -> dict[str, Path]:
    root = Path(context.root)
    return {
        path.name.lower(): path
        for path in iter_files(context)
        if path.parent == root
    }


def _missing_package_fields(payload: dict[str, Any]) -> list[str]:
    missing = [field for field in ("name", "version") if not isinstance(payload.get(field), str) or not payload[field].strip()]
    return missing


def _pyproject_metadata(text: str) -> tuple[list[str], bool]:
    """Return missing fields and whether TOML parsing was possible enough to inspect."""

    try:
        import tomllib

        payload = tomllib.loads(text)
    except (ModuleNotFoundError, ValueError):
        # Python 3.10 has no tomllib. Use only conservative section-local matching.
        project_section = re.search(r"(?ms)^\[project\]\s*(.*?)(?=^\[|\Z)", text)
        poetry_section = re.search(r"(?ms)^\[tool\.poetry\]\s*(.*?)(?=^\[|\Z)", text)
        section = project_section.group(1) if project_section else poetry_section.group(1) if poetry_section else ""
        if not section:
            return ["name", "version"], True
        has_name = bool(re.search(r"(?m)^\s*name\s*=\s*['\"]\S+", section))
        has_version = bool(re.search(r"(?m)^\s*version\s*=\s*['\"]\S+", section))
        dynamic_version = bool(re.search(r"(?i)dynamic\s*=\s*\[[^\]]*['\"]version['\"]", section))
        missing = ([] if has_name else ["name"]) + ([] if has_version or dynamic_version else ["version"])
        return missing, True

    if not isinstance(payload, dict):
        return ["name", "version"], True
    project = payload.get("project")
    if isinstance(project, dict):
        dynamic = project.get("dynamic")
        dynamic_version = isinstance(dynamic, list) and "version" in dynamic
        missing = [
            field
            for field in ("name", "version")
            if field not in project or not project.get(field) and not (field == "version" and dynamic_version)
        ]
        return missing, True

    tool = payload.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        return _missing_package_fields(poetry), True
    return ["name", "version"], True


def _docker_uses_dev_command(line: str) -> bool:
    normalized = re.sub(r"[\[\],\"']", " ", line.lower())
    return bool(
        re.search(r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?dev\b", normalized)
        or _DOCKER_RELOAD_RE.search(normalized)
        or _DJANGO_RUNSERVER_RE.search(normalized)
    )


class ReleaseConfigRule(AuditRule):
    """Find missing package metadata and obvious development Docker commands."""

    rule_id = "RG-CONFIG-001"
    name = "Release configuration readiness"
    category = "release_config"
    description = "Checks package metadata and development commands embedded in Dockerfiles."
    default_severity = Severity.MEDIUM

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []
        root_files = _root_files(context)

        package_json = root_files.get("package.json")
        if package_json is not None:
            text = read_text(context, package_json)
            if text is not None:
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    findings.append(
                        make_finding(
                            rule_id="RG-CONFIG-001",
                            title="package.json is not valid JSON",
                            severity=Severity.HIGH,
                            category=self.category,
                            context=context,
                            path=package_json,
                            evidence="package.json cannot be parsed",
                            explanation=(
                                "A release package manifest must be valid JSON so tooling can identify "
                                "the package and execute a deterministic build."
                            ),
                            recommendation="Fix the JSON syntax and validate the package manifest before release.",
                            confidence=1.0,
                            metadata={"manifest": "package.json"},
                        )
                    )
                else:
                    if not isinstance(payload, dict):
                        missing = ["name", "version"]
                    else:
                        missing = _missing_package_fields(payload)
                    if missing:
                        findings.append(
                            make_finding(
                                rule_id="RG-CONFIG-001",
                                title="package.json release metadata is incomplete",
                                severity=Severity.MEDIUM,
                                category=self.category,
                                context=context,
                                path=package_json,
                                evidence=f"Missing package metadata: {', '.join(missing)}",
                                explanation=(
                                    "Release package metadata is incomplete, making artifact identity and "
                                    "version traceability harder to establish."
                                ),
                                recommendation="Provide a stable package name and version before creating a release artifact.",
                                confidence=0.98,
                                metadata={"manifest": "package.json", "missing_fields": missing},
                            )
                        )

        pyproject = root_files.get("pyproject.toml")
        if pyproject is not None:
            text = read_text(context, pyproject)
            if text is not None:
                missing, inspectable = _pyproject_metadata(text)
                if inspectable and missing:
                    findings.append(
                        make_finding(
                            rule_id="RG-CONFIG-001",
                            title="pyproject.toml release metadata is incomplete",
                            severity=Severity.MEDIUM,
                            category=self.category,
                            context=context,
                            path=pyproject,
                            evidence=f"Missing project metadata: {', '.join(missing)}",
                            explanation=(
                                "Python release metadata is incomplete, making package identity and "
                                "version traceability harder to establish."
                            ),
                            recommendation="Provide a stable project name and version, or declare a supported dynamic version.",
                            confidence=0.94,
                            metadata={"manifest": "pyproject.toml", "missing_fields": missing},
                        )
                    )

        dockerfiles = [path for name, path in root_files.items() if name == "dockerfile" or name.startswith("dockerfile.")]
        for dockerfile in dockerfiles:
            for line_number, line in iter_text_lines(context, dockerfile):
                if not _docker_uses_dev_command(line):
                    continue
                findings.append(
                    make_finding(
                        rule_id="RG-CONFIG-002",
                        title="Dockerfile starts a development server",
                        severity=Severity.HIGH,
                        category=self.category,
                        context=context,
                        path=dockerfile,
                        line=line_number,
                        evidence="Development server command in Dockerfile",
                        explanation=(
                            "A container build that starts a development server may enable reload behavior "
                            "or omit production process settings."
                        ),
                        recommendation=(
                            "Use the production build and serving command in the final Docker image, "
                            "with development commands kept in local-only tooling."
                        ),
                        confidence=0.95,
                        metadata={"manifest": dockerfile.name},
                    )
                )

        return findings


ReleaseConfigurationRule = ReleaseConfigRule


__all__ = ["ReleaseConfigRule", "ReleaseConfigurationRule"]
