from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from releaseguard.context import ProjectContext
from releaseguard.models import ReleaseGate
from releaseguard.rules.git import GitRule
from releaseguard.scanner import audit_project


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.fixture()
def git_project(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is unavailable")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "releaseguard@example.invalid")
    _git(tmp_path, "config", "user.name", "ReleaseGuard Test")
    tracked_file = tmp_path / "tracked.txt"
    tracked_file.write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "add", "tracked.txt")
    _git(tmp_path, "commit", "-m", "initial")
    return tmp_path


def test_git_rule_reports_no_findings_for_clean_repository(git_project: Path) -> None:
    assert GitRule().check(ProjectContext(git_project)) == []


def test_git_rule_reports_dirty_and_untracked_state(git_project: Path) -> None:
    (git_project / "tracked.txt").write_text("changed\n", encoding="utf-8")
    (git_project / "scratch.txt").write_text("untracked\n", encoding="utf-8")

    findings = GitRule().check(ProjectContext(git_project))

    assert {finding.rule_id for finding in findings} >= {"RG-GIT-004", "RG-GIT-005"}
    assert all(finding.file == ".git" for finding in findings)


def test_git_rule_reports_staged_changes(git_project: Path) -> None:
    (git_project / "prepared.txt").write_text("ready\n", encoding="utf-8")
    _git(git_project, "add", "prepared.txt")

    findings = GitRule().check(ProjectContext(git_project))

    assert any(finding.rule_id == "RG-GIT-003" for finding in findings)


def test_merge_conflict_blocks_audit_and_is_exposed_in_git_snapshot(git_project: Path) -> None:
    branch = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=git_project,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    _git(git_project, "checkout", "-b", "releaseguard-conflict")
    (git_project / "tracked.txt").write_text("feature\n", encoding="utf-8")
    _git(git_project, "add", "tracked.txt")
    _git(git_project, "commit", "-m", "feature change")
    _git(git_project, "checkout", branch)
    (git_project / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(git_project, "add", "tracked.txt")
    _git(git_project, "commit", "-m", "base change")

    merge = subprocess.run(
        ["git", "merge", "releaseguard-conflict"],
        cwd=git_project,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert merge.returncode != 0

    result = audit_project(git_project)

    assert result.release_gate is ReleaseGate.BLOCKED
    assert result.git.conflicted_files == ["tracked.txt"]
    assert any(finding.rule_id == "RG-GIT-001" for finding in result.findings)
