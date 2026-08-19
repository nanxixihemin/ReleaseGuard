"""Small, read-only helpers shared by deterministic audit rules.

The helpers intentionally operate only through ``ProjectContext`` methods.  They
also keep paths and evidence deterministic across Windows and POSIX hosts.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

from ..models import Finding, Severity

if TYPE_CHECKING:
    from ..context import ProjectContext


_CONFIG_SUFFIXES = {".env", ".ini", ".json", ".toml", ".yaml", ".yml"}
_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
}
_DOCUMENTATION_SUFFIXES = {".md", ".mdx", ".rst", ".txt"}


def project_path(context: "ProjectContext", path: Path | str) -> str:
    """Return a project-relative, POSIX-normalized path for a finding."""

    relative_path = getattr(context, "relative_path", None)
    if callable(relative_path):
        return str(relative_path(path)).replace("\\", "/")

    root = Path(getattr(context, "root", "."))
    candidate = Path(path)
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return candidate.as_posix()


def iter_text_files(context: "ProjectContext") -> Iterator[Path]:
    """Yield text files through the context's bounded file iterator."""

    iterator = getattr(context, "iter_text_files", None)
    if callable(iterator):
        yield from iterator()
        return

    files = getattr(context, "iter_files", None) or getattr(context, "files", None)
    if callable(files):
        yield from files()


def iter_files(context: "ProjectContext") -> Iterator[Path]:
    """Yield all context-approved regular files without recursing ourselves."""

    iterator = getattr(context, "iter_files", None) or getattr(context, "files", None)
    if callable(iterator):
        yield from iterator()


def iter_text_lines(context: "ProjectContext", path: Path | str) -> Iterator[tuple[int, str]]:
    """Read a context-approved text file line by line, failing closed on I/O."""

    reader = getattr(context, "iter_text_lines", None)
    if not callable(reader):
        return
    try:
        yield from reader(path)
    except (OSError, UnicodeError, ValueError):
        return


def read_text(context: "ProjectContext", path: Path | str) -> str | None:
    """Read bounded text from context without allowing a rule to open files."""

    reader = getattr(context, "read_text", None)
    if not callable(reader):
        return None
    try:
        return reader(path)
    except (OSError, UnicodeError, ValueError):
        return None


def is_documentation_path(path: Path | str) -> bool:
    """Whether a path is predominantly documentation or an instructional file."""

    candidate = Path(path)
    name = candidate.name.lower()
    parts = {part.lower() for part in candidate.parts}
    generated_metadata = any(
        part.lower().endswith((".egg-info", ".dist-info")) for part in candidate.parts
    ) or name in {"pkg-info", "sources.txt"}
    return (
        candidate.suffix.lower() in _DOCUMENTATION_SUFFIXES
        or name.startswith("readme")
        or bool(parts & {"docs", "doc", "documentation"})
        or generated_metadata
    )


def is_test_path(path: Path | str) -> bool:
    """Whether a path conventionally contains tests, fixtures, or samples."""

    candidate = Path(path)
    name = candidate.name.lower()
    parts = {part.lower() for part in candidate.parts}
    return (
        bool(parts & {"test", "tests", "fixture", "fixtures", "sample", "samples"})
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def is_config_path(path: Path | str) -> bool:
    """Whether a path conventionally controls runtime or build configuration."""

    candidate = Path(path)
    name = candidate.name.lower()
    return (
        name.startswith(".env")
        or candidate.suffix.lower() in _CONFIG_SUFFIXES
        or any(token in name for token in ("config", "setting", "docker", "compose", "webpack", "vite"))
        or name in {"dockerfile", "package.json", "pyproject.toml", "build.gradle", "pom.xml"}
    )


def is_source_path(path: Path | str) -> bool:
    """Whether a file has a common source-code suffix."""

    return Path(path).suffix.lower() in _SOURCE_SUFFIXES


def is_comment_line(line: str) -> bool:
    """Return true for common single-line comment forms."""

    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "*", "<!--", ";"))


def compact_evidence(value: str, *, limit: int = 180) -> str:
    """Normalize a short, report-safe evidence snippet."""

    normalized = re.sub(r"\s+", " ", value).strip()
    return normalized[:limit]


def make_finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    context: "ProjectContext",
    path: Path | str,
    line: int | None = None,
    evidence: str = "",
    explanation: str,
    recommendation: str,
    confidence: float = 0.9,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    """Build a fully structured finding while preserving the model's fingerprint."""

    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        file=project_path(context, path),
        line=line,
        evidence=compact_evidence(evidence),
        explanation=explanation,
        recommendation=recommendation,
        confidence=confidence,
        metadata=metadata or {},
    )


__all__ = [
    "compact_evidence",
    "is_comment_line",
    "is_config_path",
    "is_documentation_path",
    "is_source_path",
    "is_test_path",
    "iter_files",
    "iter_text_files",
    "iter_text_lines",
    "make_finding",
    "project_path",
    "read_text",
]
