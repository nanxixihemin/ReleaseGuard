"""Detection of sensitive files using Git and content-aware severity heuristics."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._utils import iter_files, iter_text_lines, make_finding
from .base import AuditRule
from .secrets import is_placeholder

if TYPE_CHECKING:
    from ..context import ProjectContext


_KEY_SUFFIXES = {".key", ".pem"}
_KEYSTORE_SUFFIXES = {".jks", ".p12", ".pfx"}
_PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_CREDENTIAL_NAMES = {
    "credential.json",
    "credentials.json",
    "service-account.json",
    "service_account.json",
    "serviceaccount.json",
}
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"private[_-]?key|password|passwd|secret|token|database[_-]?url|db[_-]?(?:url|password))"
)
_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE\s+KEY-----", re.IGNORECASE)


def _classify(path: Path) -> str | None:
    name = path.name.lower()
    # Checked-in templates contain placeholders by design; the Phase 4 secret
    # migration is allowed to add `.env.example` without creating a new leak.
    if name in {".env.example", ".env.sample", ".env.template"}:
        return None
    if name == ".env" or name.startswith(".env."):
        return "environment_file"
    if name in _PRIVATE_KEY_NAMES or path.suffix.lower() in _KEY_SUFFIXES:
        return "private_key_file"
    if name in _CREDENTIAL_NAMES:
        return "credential_file"
    if name == "keystore" or name.startswith("keystore.") or path.suffix.lower() in _KEYSTORE_SUFFIXES:
        return "keystore_file"
    return None


def _contains_sensitive_content(context: "ProjectContext", path: Path, kind: str) -> bool:
    """Inspect bounded text only; binary key stores remain classified by filename."""

    for _, line in iter_text_lines(context, path):
        if _PRIVATE_KEY_HEADER_RE.search(line):
            return True
        if not _SENSITIVE_VALUE_RE.search(line):
            continue
        if kind == "credential_file":
            # Credential JSON with a key field is meaningful even if its value is
            # escaped across lines or supplied by a test fixture.
            return True
        if "=" not in line and ":" not in line:
            continue
        value = re.split(r"[=:]", line, maxsplit=1)[1].strip().strip("\"',`")
        if value and not is_placeholder(value):
            return True
    return False


def _git_state(context: "ProjectContext", path: Path) -> tuple[bool | None, bool | None]:
    try:
        tracked = context.is_git_tracked(path)
    except (AttributeError, OSError, ValueError):
        tracked = None
    try:
        ignored = context.is_git_ignored(path)
    except (AttributeError, OSError, ValueError):
        ignored = None
    return tracked, ignored


def _severity_for(
    kind: str,
    *,
    tracked: bool | None,
    ignored: bool | None,
    contains_sensitive_content: bool,
) -> Severity:
    high_value_file = kind in {"private_key_file", "credential_file", "keystore_file"}
    if tracked is True:
        if high_value_file or contains_sensitive_content:
            return Severity.CRITICAL
        return Severity.HIGH
    if high_value_file:
        return Severity.MEDIUM if ignored is True else Severity.HIGH
    if contains_sensitive_content:
        return Severity.MEDIUM if ignored is True else Severity.HIGH
    if ignored is True:
        return Severity.LOW
    return Severity.MEDIUM


def _title_for(kind: str, tracked: bool | None) -> str:
    if tracked is True:
        return "Sensitive file is tracked by Git"
    labels = {
        "environment_file": "Environment file is present",
        "private_key_file": "Private key file is present",
        "credential_file": "Credential file is present",
        "keystore_file": "Key store file is present",
    }
    return labels[kind]


class SensitiveFilesRule(AuditRule):
    """Assess sensitive filenames without assuming every local file is a leak."""

    rule_id = "RG-SENSITIVE-001"
    name = "Sensitive file handling"
    category = "sensitive_files"
    description = "Detects environment, key, credential, and key-store files with Git-aware severity."
    default_severity = Severity.HIGH

    def check(self, context: "ProjectContext") -> list[Finding]:
        findings: list[Finding] = []

        for path in iter_files(context):
            kind = _classify(path)
            if kind is None:
                continue
            tracked, ignored = _git_state(context, path)
            contains_sensitive_content = _contains_sensitive_content(context, path, kind)
            severity = _severity_for(
                kind,
                tracked=tracked,
                ignored=ignored,
                contains_sensitive_content=contains_sensitive_content,
            )
            git_description = "tracked" if tracked is True else "ignored" if ignored is True else "not confirmed as tracked"
            findings.append(
                make_finding(
                    rule_id=self.rule_id,
                    title=_title_for(kind, tracked),
                    severity=severity,
                    category=self.category,
                    context=context,
                    path=path,
                    evidence=f"{kind.replace('_', ' ')} ({git_description})",
                    explanation=(
                        "This filename commonly carries credentials or private key material. Severity reflects "
                        "whether Git tracks it, whether Git ignores it, and whether bounded text inspection "
                        "finds sensitive-looking content."
                    ),
                    recommendation=(
                        "Keep sensitive material outside the release tree or in a protected secrets store; "
                        "ensure local-only files are ignored and rotate any value that was committed."
                    ),
                    confidence=0.98 if tracked is True else 0.86,
                    metadata={
                        "file_kind": kind,
                        "git_tracked": tracked,
                        "git_ignored": ignored,
                        "contains_sensitive_content": contains_sensitive_content,
                    },
                )
            )

        return findings


SensitiveFileRule = SensitiveFilesRule


__all__ = ["SensitiveFileRule", "SensitiveFilesRule"]
