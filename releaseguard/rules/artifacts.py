"""Detection of development artifacts that commonly do not belong in a release tree."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._utils import iter_files, make_finding
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


_DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_LOG_SUFFIXES = {".log"}
_CRASH_SUFFIXES = {".crash", ".dmp", ".dump", ".mdmp"}
_TEMP_SUFFIXES = {".bak", ".swp", ".temp", ".tmp"}
_DEBUG_DATA_SUFFIXES = {".cpuprofile", ".har", ".heapprofile", ".heapsnapshot", ".prof", ".trace"}
_TOP_LEVEL_TOOL_DIRECTORIES = (".idea", ".vscode", "__pycache__")
_BUILD_TEMP_DIRECTORIES = (
    Path("build") / "temp",
    Path("build") / "tmp",
    Path("dist") / "temp",
    Path("dist") / "tmp",
    Path("target") / "temp",
    Path("target") / "tmp",
)


def _classify_file(path: Path) -> tuple[str, Severity] | None:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == ".ds_store":
        return "macOS Finder metadata", Severity.LOW
    if suffix in _DATABASE_SUFFIXES:
        return "local database file", Severity.MEDIUM
    if suffix in _CRASH_SUFFIXES or name.startswith("hs_err_pid"):
        return "crash dump", Severity.MEDIUM
    if suffix in _DEBUG_DATA_SUFFIXES:
        return "debug profiling data", Severity.MEDIUM
    if suffix in _LOG_SUFFIXES:
        return "log file", Severity.LOW
    if suffix in _TEMP_SUFFIXES or name.startswith("~$"):
        return "temporary or editor backup file", Severity.LOW
    return None


class ArtifactRule(AuditRule):
    """Report common files and top-level directories that add release noise or risk."""

    rule_id = "RG-ARTIFACT-001"
    name = "Unwanted release artifacts"
    category = "artifacts"
    description = "Detects logs, crash dumps, local databases, temporary files, and IDE/cache directories."
    default_severity = Severity.LOW

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_files(context):
            classified = _classify_file(path)
            if classified is None:
                continue
            artifact_kind, severity = classified
            findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title="Unwanted release artifact present",
                    severity=severity,
                    category=self.category,
                    context=context,
                    path=path,
                    evidence=artifact_kind,
                    explanation=(
                        "This file commonly contains local state, diagnostics, or editor residue and can "
                        "make a release artifact noisy, oversized, or harder to reproduce."
                    ),
                    recommendation=(
                        "Remove it from the release tree or add it to the appropriate ignore and packaging "
                        "exclusion rules if it is only needed locally."
                    ),
                    confidence=0.9,
                    metadata={"artifact_kind": artifact_kind},
                )
            )

        # ProjectContext deliberately does not recurse into these default-ignored
        # directories. Check only their top-level existence so we can report them
        # without bypassing the context's bounded traversal policy.
        for directory_name in _TOP_LEVEL_TOOL_DIRECTORIES:
            directory = Path(context.root) / directory_name
            try:
                if directory.is_symlink() or not directory.is_dir():
                    continue
            except OSError:
                continue
            findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title="Development tool directory present",
                    severity=Severity.LOW,
                    category=self.category,
                    context=context,
                    path=directory,
                    evidence=f"Development directory: {directory_name}",
                    explanation=(
                        "This IDE or interpreter cache directory is local development state rather than "
                        "release source. Its contents were not traversed."
                    ),
                    recommendation=(
                        "Exclude this directory from source and release packaging unless a deliberate "
                        "team policy requires a curated subset."
                    ),
                    confidence=0.98,
                    metadata={"artifact_kind": "development_directory", "directory": directory_name},
                )
            )

        for relative_directory in _BUILD_TEMP_DIRECTORIES:
            directory = Path(context.root) / relative_directory
            try:
                if directory.is_symlink() or not directory.is_dir():
                    continue
            except OSError:
                continue
            findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title="Build temporary directory present",
                    severity=Severity.LOW,
                    category=self.category,
                    context=context,
                    path=directory,
                    evidence=f"Build temporary directory: {relative_directory.as_posix()}",
                    explanation=(
                        "A temporary subdirectory exists inside a generated build output tree. Its "
                        "contents were not traversed."
                    ),
                    recommendation=(
                        "Clean generated temporary build data before packaging, or exclude it from the "
                        "release artifact."
                    ),
                    confidence=0.95,
                    metadata={"artifact_kind": "build_temporary_directory"},
                )
            )

        return findings


UnwantedArtifactRule = ArtifactRule
UnwantedArtifactsRule = ArtifactRule


__all__ = ["ArtifactRule", "UnwantedArtifactRule", "UnwantedArtifactsRule"]
