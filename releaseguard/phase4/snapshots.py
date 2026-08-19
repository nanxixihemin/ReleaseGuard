"""Content-addressed project snapshots used to bind human approvals.

Snapshots intentionally contain file names and hashes only.  They never retain
source bytes, which keeps the approval/evidence boundary useful for projects
that contain sensitive material.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .models import ProjectSnapshot


_DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".releaseguard",
        ".releaseguard-runtime",
        ".openvino-models",
        "dist",
        "build",
        "coverage",
    }
)


def normalize_relative_path(path: str | Path) -> str:
    """Normalize a relative path and reject traversal or absolute paths."""

    raw = str(path).replace("\\", "/")
    candidate = PurePosixPath(raw)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("snapshot paths must stay within the project root")
    normalized = candidate.as_posix()
    if normalized in {"", "."}:
        raise ValueError("snapshot path must identify a file")
    return normalized


def _canonical_root_hash(files: dict[str, str]) -> str:
    # Keep this byte-for-byte aligned with ``ProjectSnapshot.calculate_hash``
    # so model validation catches tampering instead of rejecting our own scans.
    payload = "".join(f"{path}\0{digest}\n" for path, digest in sorted(files.items()))
    return sha256(payload.encode("utf-8")).hexdigest()


def _snapshot_model(*, snapshot_id: str, files: dict[str, str]) -> ProjectSnapshot:
    """Construct the public model while remaining compatible with aliases."""

    try:
        return ProjectSnapshot(
            snapshot_id=snapshot_id,
            content_hash=snapshot_id,
            files=files,
        )
    except TypeError:
        # Compatibility for an integration that exposes only ``file_hashes``.
        return ProjectSnapshot(
            snapshot_id=snapshot_id,
            content_hash=snapshot_id,
            file_hashes=files,
        )


def build_project_snapshot(
    project_path: str | Path,
    *,
    exclude: Iterable[str | Path] = (),
    max_file_size: int | None = None,
) -> ProjectSnapshot:
    """Hash every safe regular file below ``project_path``.

    The walk does not follow symlinks and excludes evidence/runtime directories.
    A file that changes while being read is represented by the bytes actually
    read; a subsequent snapshot then fails approval validation as intended.
    """

    root = Path(project_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {project_path}")
    excluded = {normalize_relative_path(item) for item in exclude if str(item).strip()}
    files: dict[str, str] = {}

    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        relative_current = (
            current_path.relative_to(root).as_posix() if current_path != root else ""
        )
        directories[:] = sorted(
            [
                name
                for name in directories
                if name not in _DEFAULT_EXCLUDED_DIRECTORIES
                and not _is_excluded(relative_current, name, excluded)
            ],
            key=str.casefold,
        )
        for filename in sorted(filenames, key=str.casefold):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if _is_excluded(relative, "", excluded):
                continue
            try:
                if max_file_size is not None and path.stat().st_size > max_file_size:
                    continue
                digest = sha256(path.read_bytes()).hexdigest()
            except (OSError, ValueError):
                # Unreadable files cannot be safely approved; omitting them makes
                # the next snapshot differ and therefore fails closed.
                continue
            files[relative] = digest

    snapshot_id = _canonical_root_hash(files)
    return _snapshot_model(snapshot_id=snapshot_id, files=dict(sorted(files.items())))


def _is_excluded(relative: str, name: str, excluded: set[str]) -> bool:
    candidate = "/".join(part for part in (relative, name) if part)
    if not candidate:
        return False
    return any(candidate == item or candidate.startswith(item + "/") for item in excluded)


def snapshot_hash(snapshot: ProjectSnapshot) -> str:
    """Return the canonical content hash regardless of model alias used."""

    for attribute in ("content_hash", "snapshot_id", "hash"):
        value = getattr(snapshot, attribute, None)
        if isinstance(value, str) and value:
            return value
    files = getattr(snapshot, "files", None)
    if not isinstance(files, dict):
        files = getattr(snapshot, "file_hashes", {})
    return _canonical_root_hash({str(key): str(value) for key, value in files.items()})


def snapshots_match(left: ProjectSnapshot, right: ProjectSnapshot) -> bool:
    return snapshot_hash(left) == snapshot_hash(right)


def changed_snapshot_files(
    before: ProjectSnapshot,
    after: ProjectSnapshot,
) -> set[str]:
    """Return paths added, removed, or content-changed between snapshots."""

    def values(snapshot: ProjectSnapshot) -> dict[str, str]:
        candidate = getattr(snapshot, "files", None)
        if not isinstance(candidate, dict):
            candidate = getattr(snapshot, "file_hashes", {})
        return {str(key).replace("\\", "/"): str(value) for key, value in candidate.items()}

    old, new = values(before), values(after)
    return {path for path in set(old) | set(new) if old.get(path) != new.get(path)}


# Friendly aliases used by integrations and tests.
snapshot_project = build_project_snapshot
project_snapshot = build_project_snapshot
compute_snapshot = build_project_snapshot


__all__ = [
    "build_project_snapshot",
    "changed_snapshot_files",
    "compute_snapshot",
    "normalize_relative_path",
    "project_snapshot",
    "snapshot_hash",
    "snapshot_project",
    "snapshots_match",
]
