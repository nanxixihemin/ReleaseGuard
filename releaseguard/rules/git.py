"""Read-only Git working-tree release checks."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ..models import Finding, Severity
from ._utils import make_finding
from .base import AuditRule

if TYPE_CHECKING:
    from ..context import ProjectContext


def _as_paths(values: Iterable[object]) -> tuple[str, ...]:
    """Normalize Git's project-relative paths for deterministic metadata."""

    return tuple(sorted({str(value).replace("\\", "/") for value in values if str(value)}, key=str.casefold))


def _metadata(context: "ProjectContext", paths: tuple[str, ...]) -> dict[str, object]:
    info = context.git_info
    return {
        "branch": info.branch,
        "head_commit": info.head_commit,
        "paths": list(paths[:25]),
        "path_count": len(paths),
    }


class GitRule(AuditRule):
    """Report release-relevant working-tree state without modifying Git state."""

    rule_id = "RG-GIT-001"
    name = "Git working-tree readiness"
    category = "git"
    description = "Detects conflicts, detached HEAD, and uncommitted or untracked changes."
    default_severity = Severity.MEDIUM

    def check(self, context: "ProjectContext") -> list[Finding]:
        info = context.git_info
        if not info.available or not info.is_repository:
            # Git is optional. An unavailable executable or a non-repository root
            # must never prevent a local audit from completing.
            return []

        findings: list[Finding] = []
        git_path = Path(".git")
        conflicts = _as_paths(info.conflicted_files)
        staged = _as_paths(info.staged_files)
        changed = _as_paths(info.changed_files)
        untracked = _as_paths(info.untracked_files)

        for path in conflicts:
            findings.append(
                make_finding(
                    rule_id="RG-GIT-001",
                    title="Unresolved Git merge conflict",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    context=context,
                    path=Path(path),
                    evidence="Git reports an unmerged path",
                    explanation=(
                        "A merge conflict leaves the working tree in an incomplete state and must be "
                        "resolved before a release can be trusted."
                    ),
                    recommendation=(
                        "Resolve the conflict, run the relevant validation, and create a reviewed commit "
                        "before attempting release approval again."
                    ),
                    confidence=1.0,
                    metadata=_metadata(context, (path,)),
                )
            )

        if info.is_detached:
            findings.append(
                make_finding(
                    rule_id="RG-GIT-002",
                    title="Git HEAD is detached",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    context=context,
                    path=git_path,
                    evidence="HEAD is not attached to a branch",
                    explanation=(
                        "A detached HEAD makes the release source harder to identify and can leave "
                        "fixes unreachable from the intended release branch."
                    ),
                    recommendation=(
                        "Check out or create the intended release branch and confirm the commit that "
                        "will be deployed."
                    ),
                    confidence=0.99,
                    metadata=_metadata(context, ()),
                )
            )

        if staged:
            findings.append(
                make_finding(
                    rule_id="RG-GIT-003",
                    title="Staged Git changes are not committed",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    context=context,
                    path=git_path,
                    evidence=f"{len(staged)} staged file(s)",
                    explanation=(
                        "Staged changes have not been captured in a commit, so the release revision is "
                        "not yet reproducible from repository history."
                    ),
                    recommendation=(
                        "Review the staged diff, run validation, and commit the intended release changes."
                    ),
                    confidence=0.99,
                    metadata=_metadata(context, staged),
                )
            )

        if changed:
            findings.append(
                make_finding(
                    rule_id="RG-GIT-004",
                    title="Working tree contains uncommitted changes",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    context=context,
                    path=git_path,
                    evidence=f"{len(changed)} modified file(s)",
                    explanation=(
                        "Modified files outside a commit can make a release artifact differ from the "
                        "recorded revision."
                    ),
                    recommendation=(
                        "Review, test, and commit or intentionally discard the local changes before release."
                    ),
                    confidence=0.99,
                    metadata=_metadata(context, changed),
                )
            )

        if untracked:
            findings.append(
                make_finding(
                    rule_id="RG-GIT-005",
                    title="Untracked files are present",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    context=context,
                    path=git_path,
                    evidence=f"{len(untracked)} untracked file(s)",
                    explanation=(
                        "Untracked files can be omitted from a reproducible release or accidentally "
                        "included by a packaging step."
                    ),
                    recommendation=(
                        "Review each untracked file, then add it intentionally, ignore it, or remove it "
                        "before the release build."
                    ),
                    confidence=0.98,
                    metadata=_metadata(context, untracked),
                )
            )

        if info.is_dirty and not (conflicts or staged or changed or untracked):
            # Protect against a future GitInfo implementation that only exposes a
            # dirty flag. This keeps the rule graceful without fabricating paths.
            findings.append(
                make_finding(
                    rule_id="RG-GIT-006",
                    title="Git working tree is dirty",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    context=context,
                    path=git_path,
                    evidence="Git reports uncommitted working-tree state",
                    explanation=(
                        "The repository reports pending state that may make a release artifact non-reproducible."
                    ),
                    recommendation="Review and commit, ignore, or remove the pending state before release.",
                    confidence=0.85,
                    metadata=_metadata(context, ()),
                )
            )

        return findings


GitStateRule = GitRule


__all__ = ["GitRule", "GitStateRule"]
