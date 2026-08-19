from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from releaseguard.models import ReleaseGate, Severity
from releaseguard.scanner import audit_project


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BLOCKED_DEMO = PROJECT_ROOT / "demos" / "qoder-release-demo"
SAFE_DEMO = PROJECT_ROOT / "demos" / "safe-auto-fix-demo"
SKILL_RELATIVE_PATH = Path(".qoder/skills/releaseguard/SKILL.md")
ADAPTER_RELATIVE_PATH = Path(".qoder/skills/releaseguard/scripts/run-releaseguard.ps1")
FAKE_DEMO_CREDENTIAL = "sk-TEST_ONLY_RELEASEGUARD_1234567890"
WINDOWS_POWERSHELL_AVAILABLE = os.name == "nt" and shutil.which("powershell") is not None


def _audit_with_plan(project_path: Path):
    return audit_project(project_path, include_remediation_plan=True)


def _safety_value(item: object) -> str:
    value = getattr(item, "fix_safety")
    return str(getattr(value, "value", value))


def _items_for_rule(result: object, rule_id: str) -> list[object]:
    plan = getattr(result, "remediation_plan")
    assert isinstance(plan, list)
    return [item for item in plan if getattr(item, "finding") == rule_id]


def _copy_demo(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def _frontmatter_keys(skill_text: str) -> list[str]:
    assert skill_text.startswith("---\n")
    _, frontmatter, _ = skill_text.split("---", maxsplit=2)
    return [
        line.split(":", maxsplit=1)[0]
        for line in frontmatter.splitlines()
        if line and not line[0].isspace()
    ]


def test_project_level_qoder_skills_use_official_focused_frontmatter() -> None:
    absolute_windows_path = "D:" + "\\"
    user_windows_path = "C:" + "\\"
    for demo in (BLOCKED_DEMO, SAFE_DEMO):
        skill_path = demo / SKILL_RELATIVE_PATH
        skill_text = skill_path.read_text(encoding="utf-8")

        assert _frontmatter_keys(skill_text) == ["name", "description"]
        assert "name: releaseguard" in skill_text
        assert "/releaseguard" in skill_text
        assert "release-readiness" in skill_text
        assert "ordinary UI" in skill_text
        assert "--remediation-plan" in skill_text
        assert "--ai --ai-timeout 600" in skill_text
        assert "Never quote, copy, or save raw credential" in skill_text
        assert "[guid]::NewGuid()" in skill_text
        assert "Run exactly one" in skill_text
        assert "run-releaseguard.ps1" in skill_text
        assert absolute_windows_path not in skill_text
        assert user_windows_path not in skill_text

        adapter_text = (demo / ADAPTER_RELATIVE_PATH).read_text(encoding="utf-8")
        assert "$PSScriptRoot" in adapter_text
        assert "-lt 6" in adapter_text
        assert "@ReleaseGuardArguments" in adapter_text
        assert absolute_windows_path not in adapter_text


@pytest.mark.skipif(
    not WINDOWS_POWERSHELL_AVAILABLE,
    reason="Qoder adapter installation is a Windows PowerShell workflow.",
)
def test_installer_creates_a_project_local_adapter_without_copying_core(tmp_path: Path) -> None:
    destination_project = tmp_path / "qoder-project"
    destination_project.mkdir()
    installer = PROJECT_ROOT / "scripts" / "install_qoder_skill.ps1"

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer),
            "-ProjectPath",
            str(destination_project),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert (destination_project / SKILL_RELATIVE_PATH).read_text(encoding="utf-8") == (
        BLOCKED_DEMO / SKILL_RELATIVE_PATH
    ).read_text(encoding="utf-8")

    adapter = destination_project / ADAPTER_RELATIVE_PATH
    adapter_text = adapter.read_text(encoding="utf-8")
    assert "scripts\\run.ps1" in adapter_text
    assert "$releaseGuardRoot" in adapter_text
    assert not (destination_project / "releaseguard").exists()
    assert not (destination_project / "scripts" / "run.ps1").exists()

    adapter_run = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(adapter),
            "version",
        ],
        cwd=destination_project,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert adapter_run.returncode == 0, adapter_run.stderr
    assert "ReleaseGuard" in adapter_run.stdout


@pytest.mark.skipif(
    not WINDOWS_POWERSHELL_AVAILABLE,
    reason="Qoder adapter installation is a Windows PowerShell workflow.",
)
def test_installer_rejects_a_missing_destination(tmp_path: Path) -> None:
    installer = PROJECT_ROOT / "scripts" / "install_qoder_skill.ps1"
    missing_project = tmp_path / "does-not-exist"

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer),
            "-ProjectPath",
            str(missing_project),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "Project directory does not exist" in completed.stderr


def test_blocked_demo_has_fake_only_critical_secret_and_one_safe_debug_item() -> None:
    result = _audit_with_plan(BLOCKED_DEMO)

    assert result.release_score == 38
    assert result.release_gate is ReleaseGate.BLOCKED
    assert [(finding.rule_id, finding.severity) for finding in result.findings] == [
        ("RG-SECRET-001", Severity.CRITICAL),
        ("RG-ENV-001", Severity.CRITICAL),
        ("RG-DEBUG-001", Severity.HIGH),
    ]
    assert FAKE_DEMO_CREDENTIAL not in result.to_json()

    secret_items = _items_for_rule(result, "RG-SECRET-001")
    assert len(secret_items) == 1
    assert _safety_value(secret_items[0]) == "NEVER_AUTO_FIX"
    assert getattr(secret_items[0], "auto_fix_candidate") is False

    environment_items = _items_for_rule(result, "RG-ENV-001")
    assert len(environment_items) == 1
    assert _safety_value(environment_items[0]) == "REVIEW_REQUIRED"
    assert getattr(environment_items[0], "auto_fix_candidate") is False

    debug_items = _items_for_rule(result, "RG-DEBUG-001")
    assert len(debug_items) == 1
    assert _safety_value(debug_items[0]) == "SAFE"
    assert getattr(debug_items[0], "auto_fix_candidate") is True


def test_blocked_demo_stays_blocked_after_the_only_safe_edit(tmp_path: Path) -> None:
    project = _copy_demo(BLOCKED_DEMO, tmp_path / "blocked-demo")
    before = _audit_with_plan(project)
    config_path = project / "src" / "config.ts"
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace("DEBUG = true", "DEBUG = false", 1),
        encoding="utf-8",
    )
    after = _audit_with_plan(project)

    assert before.release_gate is ReleaseGate.BLOCKED
    assert after.release_score == 50
    assert after.release_gate is ReleaseGate.BLOCKED
    assert any(
        finding.rule_id == "RG-SECRET-001" and finding.severity is Severity.CRITICAL
        for finding in after.findings
    )
    assert not _items_for_rule(after, "RG-DEBUG-001")


def test_safe_demo_reaches_pass_after_its_bounded_debug_edit(tmp_path: Path) -> None:
    project = _copy_demo(SAFE_DEMO, tmp_path / "safe-demo")
    before = _audit_with_plan(project)
    debug_items = _items_for_rule(before, "RG-DEBUG-001")

    assert before.release_score == 83
    assert before.release_gate is ReleaseGate.WARNING
    assert len(debug_items) == 1
    assert _safety_value(debug_items[0]) == "SAFE"
    assert getattr(debug_items[0], "auto_fix_candidate") is True
    assert _safety_value(_items_for_rule(before, "RG-TODO-001")[0]) == "REVIEW_REQUIRED"

    config_path = project / "src" / "config.ts"
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace("DEBUG = true", "DEBUG = false", 1),
        encoding="utf-8",
    )
    after = _audit_with_plan(project)

    assert after.release_score == 95
    assert after.release_gate is ReleaseGate.PASS
    assert not _items_for_rule(after, "RG-DEBUG-001")
    assert len(_items_for_rule(after, "RG-TODO-001")) == 1
