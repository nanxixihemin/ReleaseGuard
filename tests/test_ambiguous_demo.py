from __future__ import annotations

from pathlib import Path

from releaseguard.context import ProjectContext
from releaseguard.models import Severity
from releaseguard.rules.environment import EnvironmentRule


FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "examples" / "ambiguous_environment_project"


def _findings():
    return EnvironmentRule().check(ProjectContext(FIXTURE_ROOT))


def test_ambiguous_environment_fixture_locks_deterministic_severity_baseline() -> None:
    findings = _findings()
    severities = {finding.file: finding.severity for finding in findings}

    assert len(findings) == 5
    assert severities == {
        ".env.example": Severity.HIGH,
        "README.md": Severity.LOW,
        "deploy/production.env": Severity.CRITICAL,
        "src/runtime.ts": Severity.HIGH,
        "vite.config.ts": Severity.HIGH,
    }
    assert {finding.rule_id for finding in findings} == {"RG-ENV-001"}


def test_ambiguous_environment_fixture_preserves_context_signals_for_future_ai() -> None:
    findings = {finding.file: finding for finding in _findings()}

    assert findings["README.md"].metadata["assignment_context"] is False
    assert findings[".env.example"].metadata["assignment_context"] is True
    assert findings["vite.config.ts"].metadata["assignment_context"] is False
    assert findings["src/runtime.ts"].metadata["assignment_context"] is True
    assert findings["deploy/production.env"].metadata["assignment_context"] is True
    assert findings["deploy/production.env"].title == "Production endpoint points to a loopback address"
