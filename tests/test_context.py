from __future__ import annotations

from pathlib import Path

import pytest

from releaseguard.context import ProjectContext


def test_context_honors_builtin_and_releaseguard_ignore_patterns(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "ignored").mkdir()
    (tmp_path / "node_modules" / "dependency.js").write_text("ignored", encoding="utf-8")
    (tmp_path / "ignored" / "nested.txt").write_text("ignored", encoding="utf-8")
    (tmp_path / "visible.txt").write_text("first\nsecond\n", encoding="utf-8")
    (tmp_path / "drop.tmp").write_text("ignored", encoding="utf-8")
    (tmp_path / "keep.tmp").write_text("kept", encoding="utf-8")
    (tmp_path / ".releaseguardignore").write_text(
        "ignored/\n*.tmp\n!keep.tmp\n",
        encoding="utf-8",
    )

    context = ProjectContext(tmp_path)
    names = {context.relative_path(path) for path in context.files()}

    assert "visible.txt" in names
    assert "keep.tmp" in names
    assert "drop.tmp" not in names
    assert "ignored/nested.txt" not in names
    assert "node_modules/dependency.js" not in names
    assert list(context.iter_text_lines("visible.txt")) == [(1, "first"), (2, "second")]


def test_context_ignores_root_git_file_for_linked_worktrees(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text("gitdir: ../shared-worktree\n", encoding="utf-8")

    context = ProjectContext(tmp_path)

    assert context.is_ignored(tmp_path / ".git", is_dir=False)
    assert ".git" not in {context.relative_path(path) for path in context.files()}


def test_context_skips_binary_and_oversized_files_with_accounting(tmp_path: Path) -> None:
    (tmp_path / "small.txt").write_text("small", encoding="utf-8")
    (tmp_path / "binary.dat").write_bytes(b"prefix\x00suffix")
    (tmp_path / "large.txt").write_text("x" * 64, encoding="utf-8")

    context = ProjectContext(tmp_path, max_file_size=32)
    scanned = {context.relative_path(path) for path in context.iter_text_files()}

    assert scanned == {"small.txt"}
    assert list(context.iter_text_lines("binary.dat")) == []
    assert context.files_scanned == 1
    assert context.files_skipped >= 2
    assert context.skipped_by_reason["binary"] == 1
    assert context.skipped_by_reason["oversize"] == 1


def test_context_detects_known_manifests_and_nonrepository_git_gracefully(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")

    context = ProjectContext(tmp_path)
    git_info = context.git_info

    assert {"python", "node"}.issubset(context.project_types)
    assert "python" in context.find_known_project_manifests()
    assert git_info.is_repository is False
    assert context.is_git_tracked(tmp_path / "pyproject.toml") is None


def test_context_degrades_cleanly_when_git_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("releaseguard.context.GIT_EXECUTABLE", None)

    git_info = ProjectContext(tmp_path).git_info

    assert git_info.available is False
    assert git_info.is_repository is False
    assert git_info.error == "git executable is unavailable"


def test_context_rejects_files_reached_through_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "safe.txt").write_text("safe", encoding="utf-8")
    link = tmp_path / "loop"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("This Windows environment does not permit symlink creation")

    context = ProjectContext(tmp_path)
    names = {context.relative_path(path) for path in context.files()}

    assert "loop/safe.txt" not in names
    assert list(context.iter_text_lines(link / "safe.txt")) == []
    assert context.files_skipped >= 1
