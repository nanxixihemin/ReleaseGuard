"""Safe, reusable, read-only project context for release audit rules."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
from types import MappingProxyType
from typing import Literal


DEFAULT_MAX_FILE_SIZE = 1_000_000
DEFAULT_IGNORE_DIRECTORIES = frozenset(
    {
        ".git",
        ".idea",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "coverage",
        ".releaseguard",
        "dist",
        "node_modules",
        "target",
        "venv",
    }
)

# The key is the project type exposed to rules; values are root-level manifests.
KNOWN_PROJECT_MANIFESTS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "android": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"),
        "flutter": ("pubspec.yaml",),
        "go": ("go.mod",),
        "harmonyos": ("oh-package.json5", "build-profile.json5", "hvigorfile.ts"),
        "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
        "node": ("package.json",),
        "python": ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile"),
        "rust": ("Cargo.toml",),
    }
)

# Resolve the executable before switching to an inspected repository as ``cwd``.
# On Windows this prevents a repository-local ``git.exe`` from being selected.
GIT_EXECUTABLE = shutil.which("git", path=os.environ.get("PATH"))


@dataclass(frozen=True, slots=True)
class GitInfo:
    """A best-effort snapshot of repository state with no failure side effects."""

    available: bool
    is_repository: bool
    branch: str | None = None
    head_commit: str | None = None
    is_detached: bool = False
    changed_files: tuple[str, ...] = ()
    staged_files: tuple[str, ...] = ()
    untracked_files: tuple[str, ...] = ()
    conflicted_files: tuple[str, ...] = ()
    error: str | None = None

    @property
    def is_repo(self) -> bool:
        """Compatibility alias for ``is_repository``."""

        return self.is_repository

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicted_files)

    @property
    def is_dirty(self) -> bool:
        return bool(
            self.changed_files
            or self.staged_files
            or self.untracked_files
            or self.conflicted_files
        )

    @property
    def dirty_files(self) -> tuple[str, ...]:
        """All changed paths, de-duplicated and ordered for deterministic output."""

        return tuple(
            sorted(
                {
                    *self.changed_files,
                    *self.staged_files,
                    *self.untracked_files,
                    *self.conflicted_files,
                },
                key=str.casefold,
            )
        )


@dataclass(frozen=True, slots=True)
class _IgnoreRule:
    pattern: str
    negated: bool
    directory_only: bool
    anchored: bool


TextFileStatus = Literal["text", "binary", "oversize", "unreadable", "symlink"]


class ProjectContext:
    """A bounded, cached view of a project tree used by every audit rule.

    The context never writes to the inspected project. Directory traversal skips
    symlinks and configured dependency/build directories, text reads are bounded,
    and all Git calls use fixed built-in inspection commands.
    """

    BINARY_SAMPLE_SIZE = 8_192
    GIT_TIMEOUT_SECONDS = 5

    def __init__(
        self,
        root: str | Path,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        if max_file_size <= 0:
            raise ValueError("max_file_size must be greater than zero")

        root_path = Path(root).expanduser()
        try:
            resolved_root = root_path.resolve(strict=True)
        except FileNotFoundError:
            raise FileNotFoundError(f"Project directory does not exist: {root_path}") from None
        except OSError as error:
            raise OSError(f"Cannot access project directory: {root_path}") from error

        if not resolved_root.is_dir():
            raise NotADirectoryError(f"Project path is not a directory: {root_path}")

        self._root = resolved_root
        self.max_file_size = max_file_size
        self._ignore_rules = self._load_ignore_rules()
        self._files: tuple[Path, ...] | None = None
        self._text_statuses: dict[Path, TextFileStatus] = {}
        self._skipped_paths: set[Path] = set()
        self._skip_reasons: Counter[str] = Counter()
        self._manifests: Mapping[str, tuple[Path, ...]] | None = None
        self._git_info: GitInfo | None = None
        self._git_tracked_cache: dict[str, bool | None] = {}
        self._git_ignored_cache: dict[str, bool | None] = {}

    @property
    def root(self) -> Path:
        """The canonical project root. Consumers should treat it as read-only."""

        return self._root

    @property
    def root_path(self) -> Path:
        """Compatibility alias for :attr:`root`."""

        return self._root

    @property
    def project_name(self) -> str:
        return self._root.name

    def files(self) -> tuple[Path, ...]:
        """Return cached, nonignored regular files without reading their contents."""

        if self._files is None:
            self._files = tuple(self._discover_files())
        return self._files

    def iter_files(self) -> Iterator[Path]:
        """Iterate all cached, nonignored regular files in deterministic order."""

        yield from self.files()

    def iter_text_files(self) -> Iterator[Path]:
        """Iterate files whose bounded sample looks like text."""

        for path in self.files():
            if self._text_status(path) == "text":
                yield path

    def iter_text_lines(self, path: str | Path) -> Iterator[tuple[int, str]]:
        """Stream UTF-8-compatible lines from a bounded text file.

        The method yields ``(line_number, line_without_newline)`` pairs. Binary,
        oversized, unreadable, out-of-root, and symlink paths produce no lines.
        """

        try:
            resolved_path = self._resolve_project_path(path)
        except ValueError:
            return

        if self._text_status(resolved_path) != "text":
            return

        try:
            with resolved_path.open("r", encoding="utf-8", errors="replace", newline=None) as handle:
                for line_number, line in enumerate(handle, start=1):
                    yield line_number, line.rstrip("\r\n")
        except OSError:
            self._set_text_status(resolved_path, "unreadable")
            return

    def read_text(self, path: str | Path) -> str | None:
        """Return one bounded text file for rare non-streaming rule needs."""

        try:
            resolved_path = self._resolve_project_path(path)
        except ValueError:
            return None

        if self._text_status(resolved_path) != "text":
            return None

        try:
            with resolved_path.open("r", encoding="utf-8", errors="replace", newline=None) as handle:
                return handle.read()
        except OSError:
            self._set_text_status(resolved_path, "unreadable")
            return None

    def is_text_file(self, path: str | Path) -> bool:
        """Check a file with the same bounded binary and size policy as rules."""

        try:
            resolved_path = self._resolve_project_path(path)
        except ValueError:
            return False
        return self._text_status(resolved_path) == "text"

    def relative_path(self, path: str | Path) -> str:
        """Return a stable project-relative path using forward slashes."""

        return self._resolve_project_path(path).relative_to(self._root).as_posix()

    def is_ignored(self, path: str | Path, *, is_dir: bool | None = None) -> bool:
        """Return whether a path matches the built-in or user ignore policy."""

        try:
            relative = self.relative_path(path)
        except ValueError:
            return True

        path_parts = PurePosixPath(relative).parts
        if is_dir is None:
            try:
                is_dir = self._resolve_project_path(path).is_dir()
            except OSError:
                is_dir = False

        # Linked Git worktrees store a small `.git` *file* at the project root.
        # Treat it like the regular `.git` directory so scanner rules never
        # inspect internal Git metadata as project content.
        if relative == ".git":
            return True

        directory_parts = path_parts if is_dir else path_parts[:-1]
        if any(part in DEFAULT_IGNORE_DIRECTORIES for part in directory_parts):
            return True

        ignored = False
        for rule in self._ignore_rules:
            if self._ignore_rule_matches(rule, relative, bool(is_dir)):
                ignored = not rule.negated
        return ignored

    @property
    def manifests(self) -> Mapping[str, tuple[Path, ...]]:
        """Known root manifests grouped by detected project type."""

        if self._manifests is None:
            found: dict[str, tuple[Path, ...]] = {}
            for project_type, filenames in KNOWN_PROJECT_MANIFESTS.items():
                paths: list[Path] = []
                for filename in filenames:
                    candidate = self._root / filename
                    try:
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                    except OSError:
                        continue
                    paths.append(candidate)
                if paths:
                    found[project_type] = tuple(paths)
            self._manifests = MappingProxyType(found)
        return self._manifests

    @property
    def project_types(self) -> tuple[str, ...]:
        """Detected project types based on known root-level manifests."""

        return tuple(self.manifests)

    def find_known_project_manifests(self) -> Mapping[str, tuple[Path, ...]]:
        """Explicit method form of :attr:`manifests` for detector consumers."""

        return self.manifests

    @property
    def files_scanned(self) -> int:
        """Count bounded text files, forcing only cheap classification if needed."""

        return sum(1 for _ in self.iter_text_files())

    @property
    def scanned_files(self) -> int:
        return self.files_scanned

    @property
    def files_skipped(self) -> int:
        """Count paths skipped because they are ignored, unsafe, or non-text."""

        self.files()
        return len(self._skipped_paths)

    @property
    def skipped_files(self) -> int:
        return self.files_skipped

    @property
    def skipped_by_reason(self) -> Mapping[str, int]:
        """A copy-safe breakdown useful for diagnostics and future reporting."""

        return MappingProxyType(dict(sorted(self._skip_reasons.items())))

    def scan_statistics(self) -> dict[str, int | Mapping[str, int]]:
        """Return a stable scan metric snapshot after classifying candidate files."""

        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "skipped_by_reason": self.skipped_by_reason,
        }

    @property
    def git_info(self) -> GitInfo:
        """Inspect Git state safely, or return a non-throwing unavailable snapshot."""

        if self._git_info is None:
            self._git_info = self._collect_git_info()
        return self._git_info

    def get_git_info(self) -> GitInfo:
        """Method form of :attr:`git_info` for consumers preferring an operation."""

        return self.git_info

    def is_git_tracked(self, path: str | Path) -> bool | None:
        """Return Git tracking state, or ``None`` when Git state is unavailable."""

        info = self.git_info
        if not info.is_repository:
            return None
        try:
            relative = self.relative_path(path)
        except ValueError:
            return None
        if relative in self._git_tracked_cache:
            return self._git_tracked_cache[relative]

        result, error = self._run_git("ls-files", "--error-unmatch", "--", relative)
        if result is None:
            tracked: bool | None = None
        elif result.returncode == 0:
            tracked = True
        elif result.returncode == 1:
            tracked = False
        else:
            tracked = None
        if error is not None:
            tracked = None
        self._git_tracked_cache[relative] = tracked
        return tracked

    def is_git_ignored(self, path: str | Path) -> bool | None:
        """Return Git ignore state, or ``None`` when Git state is unavailable."""

        info = self.git_info
        if not info.is_repository:
            return None
        try:
            relative = self.relative_path(path)
        except ValueError:
            return None
        if relative in self._git_ignored_cache:
            return self._git_ignored_cache[relative]

        result, error = self._run_git("check-ignore", "-q", "--", relative)
        if result is None or error is not None:
            ignored: bool | None = None
        elif result.returncode == 0:
            ignored = True
        elif result.returncode == 1:
            ignored = False
        else:
            ignored = None
        self._git_ignored_cache[relative] = ignored
        return ignored

    def _discover_files(self) -> Iterator[Path]:
        """Walk without following symlinks, collecting a deterministic file snapshot."""

        pending = [self._root]
        visited_directories: set[Path] = set()
        discovered: list[Path] = []

        while pending:
            directory = pending.pop()
            try:
                canonical_directory = directory.resolve(strict=True)
            except OSError:
                self._record_skip(directory, "unreadable")
                continue
            if not self._is_within_root(canonical_directory):
                self._record_skip(directory, "outside_root")
                continue
            if canonical_directory in visited_directories:
                self._record_skip(directory, "symlink_loop")
                continue
            visited_directories.add(canonical_directory)

            try:
                with os.scandir(directory) as entries:
                    ordered_entries = sorted(entries, key=lambda entry: entry.name.casefold())
            except OSError:
                self._record_skip(directory, "unreadable")
                continue

            for entry in ordered_entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink():
                        self._record_skip(path, "symlink")
                        continue
                    is_directory = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError:
                    self._record_skip(path, "unreadable")
                    continue

                if is_directory:
                    if path.name in DEFAULT_IGNORE_DIRECTORIES:
                        self._record_skip(path, "built_in_ignore")
                    elif self.is_ignored(path, is_dir=True):
                        self._record_skip(path, "user_ignore")
                    else:
                        pending.append(path)
                    continue

                if not is_file:
                    self._record_skip(path, "non_regular")
                    continue
                if self.is_ignored(path, is_dir=False):
                    self._record_skip(path, "user_ignore")
                    continue
                discovered.append(path)

        yield from sorted(discovered, key=lambda path: self.relative_path(path).casefold())

    def _text_status(self, path: Path) -> TextFileStatus:
        try:
            resolved_path = self._resolve_project_path(path)
        except ValueError:
            return "symlink"
        existing = self._text_statuses.get(resolved_path)
        if existing is not None:
            return existing

        # The discovered tree excludes symlinks. Re-check public inputs so direct
        # callers cannot use this API to read through an in-project symlink.
        try:
            if path.is_symlink():
                return self._set_text_status(resolved_path, "symlink")
            stat = resolved_path.stat()
        except OSError:
            return self._set_text_status(resolved_path, "unreadable")

        if stat.st_size > self.max_file_size:
            return self._set_text_status(resolved_path, "oversize")

        try:
            with resolved_path.open("rb") as handle:
                sample = handle.read(self.BINARY_SAMPLE_SIZE)
        except OSError:
            return self._set_text_status(resolved_path, "unreadable")

        if b"\x00" in sample:
            return self._set_text_status(resolved_path, "binary")
        self._text_statuses[resolved_path] = "text"
        return "text"

    def _set_text_status(self, path: Path, status: TextFileStatus) -> TextFileStatus:
        previous = self._text_statuses.get(path)
        self._text_statuses[path] = status
        if status != "text" and previous is None:
            self._record_skip(path, status)
        return status

    def _record_skip(self, path: Path, reason: str) -> None:
        """Count a path at most once, retaining its first, most actionable reason."""

        try:
            # Keep the lexical path: resolving a skipped symlink would follow it
            # merely for accounting and could collapse distinct unsafe entries.
            normalized = Path(os.path.abspath(os.fspath(path)))
        except OSError:
            normalized = path.absolute()
        if normalized in self._skipped_paths:
            return
        self._skipped_paths.add(normalized)
        self._skip_reasons[reason] += 1

    def _resolve_project_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self._root / candidate
        try:
            # Normalize ``..`` without resolving links first, so we can reject
            # every symlink component rather than accidentally following one
            # that happens to point back inside the project.
            lexical_candidate = Path(os.path.abspath(os.fspath(candidate)))
            lexical_relative = lexical_candidate.relative_to(self._root)
            current = self._root
            for part in lexical_relative.parts:
                current /= part
                if current.is_symlink():
                    raise ValueError(f"Path traverses a symlink: {path}")
            resolved = lexical_candidate.resolve(strict=False)
        except OSError as error:
            raise ValueError(f"Cannot resolve project path: {path}") from error
        except ValueError:
            raise ValueError(f"Path is outside the project root: {path}") from None
        if not self._is_within_root(resolved):
            raise ValueError(f"Path is outside the project root: {path}")
        return resolved

    def _is_within_root(self, path: Path) -> bool:
        try:
            path.relative_to(self._root)
        except ValueError:
            return False
        return True

    def _load_ignore_rules(self) -> tuple[_IgnoreRule, ...]:
        ignore_file = self._root / ".releaseguardignore"
        try:
            if ignore_file.is_symlink() or not ignore_file.is_file():
                return ()
            if ignore_file.stat().st_size > self.max_file_size:
                return ()
            with ignore_file.open("r", encoding="utf-8", errors="replace") as handle:
                lines = tuple(handle)
        except OSError:
            return ()

        rules: list[_IgnoreRule] = []
        for raw_line in lines:
            line = raw_line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if line.startswith("\\#") or line.startswith("\\!"):
                line = line[1:]

            negated = line.startswith("!")
            if negated:
                line = line[1:]
            if not line:
                continue

            # Gitignore syntax uses slash separators even when the project lives
            # on Windows. Normalize accidental backslashes for local usability.
            line = line.replace("\\", "/")
            anchored = line.startswith("/")
            if anchored:
                line = line[1:]
            directory_only = line.endswith("/")
            if directory_only:
                line = line.rstrip("/")
            if line:
                rules.append(
                    _IgnoreRule(
                        pattern=line,
                        negated=negated,
                        directory_only=directory_only,
                        anchored=anchored,
                    )
                )
        return tuple(rules)

    def _ignore_rule_matches(
        self,
        rule: _IgnoreRule,
        relative_path: str,
        is_dir: bool,
    ) -> bool:
        parts = PurePosixPath(relative_path).parts
        candidates: list[str] = [relative_path]
        if rule.directory_only:
            directory_limit = len(parts) if is_dir else len(parts) - 1
            candidates = ["/".join(parts[:index]) for index in range(1, directory_limit + 1)]

        return any(
            self._ignore_pattern_matches(candidate, rule.pattern, rule.anchored)
            for candidate in candidates
        )

    @staticmethod
    def _ignore_pattern_matches(candidate: str, pattern: str, anchored: bool) -> bool:
        """Match the useful, common subset of gitignore patterns."""

        if "/" not in pattern:
            parts = PurePosixPath(candidate).parts
            if anchored:
                return len(parts) == 1 and fnmatchcase(parts[0], pattern)
            return any(fnmatchcase(part, pattern) for part in parts)

        if anchored:
            return fnmatchcase(candidate, pattern)

        # A pattern containing a slash can match from any directory boundary.
        parts = PurePosixPath(candidate).parts
        return any(
            fnmatchcase("/".join(parts[index:]), pattern)
            or PurePosixPath("/".join(parts[index:])).match(pattern)
            for index in range(len(parts))
        )

    def _collect_git_info(self) -> GitInfo:
        result, error = self._run_git("rev-parse", "--is-inside-work-tree")
        if result is None:
            return GitInfo(available=False, is_repository=False, error=error)
        if result.returncode != 0 or result.stdout.strip().lower() != b"true":
            return GitInfo(available=True, is_repository=False)

        branch_result, branch_error = self._run_git("symbolic-ref", "--short", "-q", "HEAD")
        branch = None
        detached = False
        if branch_result is not None and branch_result.returncode == 0:
            branch = self._decode_git_output(branch_result.stdout).strip() or None
        else:
            detached = True

        head_result, head_error = self._run_git("rev-parse", "--short", "HEAD")
        head_commit = None
        if head_result is not None and head_result.returncode == 0:
            head_commit = self._decode_git_output(head_result.stdout).strip() or None

        status_result, status_error = self._run_git(
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
        changed: set[str] = set()
        staged: set[str] = set()
        untracked: set[str] = set()
        conflicted: set[str] = set()
        if status_result is not None and status_result.returncode == 0:
            changed, staged, untracked, conflicted = self._parse_git_status(status_result.stdout)

        inspection_error = next(
            (
                candidate
                for candidate in (branch_error, head_error, status_error)
                if candidate is not None
            ),
            None,
        )
        return GitInfo(
            available=True,
            is_repository=True,
            branch=branch,
            head_commit=head_commit,
            is_detached=detached,
            changed_files=tuple(sorted(changed, key=str.casefold)),
            staged_files=tuple(sorted(staged, key=str.casefold)),
            untracked_files=tuple(sorted(untracked, key=str.casefold)),
            conflicted_files=tuple(sorted(conflicted, key=str.casefold)),
            error=inspection_error,
        )

    def _run_git(
        self,
        *arguments: str,
    ) -> tuple[subprocess.CompletedProcess[bytes] | None, str | None]:
        """Run a fixed, read-only Git built-in with no shell or project scripts."""

        if GIT_EXECUTABLE is None:
            return None, "git executable is unavailable"
        command = [
            GIT_EXECUTABLE,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=",
            "-C",
            os.fspath(self._root),
            *arguments,
        ]
        environment = os.environ.copy()
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = subprocess.run(
                command,
                cwd=os.fspath(self._root),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=self.GIT_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return None, "git executable is unavailable"
        except subprocess.TimeoutExpired:
            return None, "git inspection timed out"
        except OSError as error:
            return None, f"git inspection failed: {error.__class__.__name__}"
        return result, None

    @staticmethod
    def _decode_git_output(output: bytes) -> str:
        return output.decode("utf-8", errors="replace")

    @classmethod
    def _parse_git_status(
        cls,
        output: bytes,
    ) -> tuple[set[str], set[str], set[str], set[str]]:
        """Parse porcelain v1 NUL records without depending on locale output."""

        changed: set[str] = set()
        staged: set[str] = set()
        untracked: set[str] = set()
        conflicted: set[str] = set()
        records = output.split(b"\0")
        index = 0
        conflict_codes = {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}

        while index < len(records):
            record = records[index]
            index += 1
            if not record or len(record) < 3:
                continue
            status = cls._decode_git_output(record[:2])
            path = cls._decode_git_output(record[3:]).replace("\\", "/")
            if not path:
                continue

            # For rename/copy records porcelain -z emits a second NUL-delimited
            # source path. It belongs to the same status record and is skipped.
            if "R" in status or "C" in status:
                index += 1

            if status == "??":
                untracked.add(path)
                continue
            if status in conflict_codes:
                conflicted.add(path)
                continue
            if status[0] not in {" ", "?"}:
                staged.add(path)
            if status[1] not in {" ", "?"}:
                changed.add(path)

        return changed, staged, untracked, conflicted


__all__ = [
    "DEFAULT_IGNORE_DIRECTORIES",
    "DEFAULT_MAX_FILE_SIZE",
    "GIT_EXECUTABLE",
    "GitInfo",
    "KNOWN_PROJECT_MANIFESTS",
    "ProjectContext",
]
