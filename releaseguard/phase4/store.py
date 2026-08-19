"""Append-only, redacted evidence storage for Phase 4 workflows."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Iterable
from uuid import uuid4

from .redaction import redact_payload, redact_text


_SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


class EvidenceStore:
    """Persist Phase 4 records below one project-local evidence root.

    The store is deliberately file based.  Every mutating action receives a new
    random GUID directory, while a small redacted state index makes the latest
    audit and approvals discoverable by the CLI and dashboard.
    """

    def __init__(
        self,
        project_path: str | Path,
        *,
        evidence_root: str | Path | None = None,
    ) -> None:
        self.project_path = Path(project_path).expanduser().resolve()
        if not self.project_path.exists() or not self.project_path.is_dir():
            raise ValueError(f"Project path is not a directory: {project_path}")
        self.root = (
            Path(evidence_root).expanduser().resolve()
            if evidence_root is not None
            else self.project_path / ".releaseguard" / "evidence"
        )
        self.state_path = self.root.parent / "state.json"

    def new_evidence_dir(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        while True:
            candidate = self.root / uuid4().hex
            try:
                candidate.mkdir()
            except FileExistsError:
                continue
            return candidate

    def write_json(self, directory: str | Path, name: str, value: Any) -> Path:
        target = self._artifact_path(directory, name)
        payload = redact_payload(_jsonable(value))
        self._atomic_write(
            target,
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        return target

    def write_text(self, directory: str | Path, name: str, value: str) -> Path:
        target = self._artifact_path(directory, name)
        self._atomic_write(target, redact_text(str(value)))
        return target

    def record_action(
        self,
        *,
        artifacts: dict[str, Any] | None = None,
        text_artifacts: dict[str, str] | None = None,
    ) -> Path:
        directory = self.new_evidence_dir()
        for name, value in (artifacts or {}).items():
            self.write_json(directory, name, value)
        for name, value in (text_artifacts or {}).items():
            self.write_text(directory, name, value)
        return directory

    def read_json(self, path: str | Path) -> Any:
        candidate = self._contained_path(path)
        try:
            return json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("could not read ReleaseGuard evidence") from error

    def read_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "audits": [],
                "approvals": [],
                "dispositions": {},
                "timeline": [],
            }
        value = self.read_json(self.state_path)
        return value if isinstance(value, dict) else {}

    def write_state(self, state: dict[str, Any]) -> Path:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = redact_payload(_jsonable(state))
        self._atomic_write(
            self.state_path,
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        return self.state_path

    def update_state(self, **updates: Any) -> dict[str, Any]:
        state = self.read_state()
        state.update(updates)
        self.write_state(state)
        return state

    def list_evidence(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(
            [item for item in self.root.iterdir() if item.is_dir() and _is_guid(item.name)],
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )

    def latest_audit(self) -> dict[str, Any] | None:
        state = self.read_state()
        latest = state.get("latest_audit")
        return latest if isinstance(latest, dict) else None

    def latest_approval(self, finding_id: str) -> dict[str, Any] | None:
        state = self.read_state()
        approvals = state.get("approvals", [])
        if not isinstance(approvals, list):
            return None
        needle = str(finding_id)
        for item in reversed(approvals):
            if not isinstance(item, dict):
                continue
            if (
                str(item.get("finding_id", "")) == needle
                or str(item.get("fingerprint", "")) == needle
                or str(item.get("finding_fingerprint", "")) == needle
            ):
                return item
        return None

    def all_approvals(self) -> list[dict[str, Any]]:
        value = self.read_state().get("approvals", [])
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def all_audits(self) -> list[dict[str, Any]]:
        value = self.read_state().get("audits", [])
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def all_timeline(self) -> list[dict[str, Any]]:
        value = self.read_state().get("timeline", [])
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _artifact_path(self, directory: str | Path, name: str) -> Path:
        if not _SAFE_ARTIFACT_NAME.fullmatch(str(name)):
            raise ValueError("invalid evidence artifact name")
        directory_path = Path(directory).expanduser().resolve()
        try:
            directory_path.relative_to(self.root.resolve())
        except ValueError:
            raise ValueError("evidence directory is outside the evidence root") from None
        directory_path.mkdir(parents=True, exist_ok=True)
        return directory_path / str(name)

    def _contained_path(self, path: str | Path) -> Path:
        candidate = Path(path).expanduser().resolve()
        allowed_roots = (self.root.resolve(), self.state_path.parent.resolve())
        if not any(_is_relative_to(candidate, root) for root in allowed_roots):
            raise ValueError("evidence path is outside the project evidence root")
        return candidate

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(text, encoding="utf-8", newline="\n")
            temporary.replace(path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _is_guid(value: str) -> bool:
    try:
        return len(value) == 32 and int(value, 16) >= 0
    except (TypeError, ValueError):
        return False


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


# Compatibility aliases for callers that prefer a shorter name.
EvidenceRepository = EvidenceStore
EvidenceManager = EvidenceStore


__all__ = ["EvidenceManager", "EvidenceRepository", "EvidenceStore"]
