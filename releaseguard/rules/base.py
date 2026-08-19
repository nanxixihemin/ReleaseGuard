"""The narrow extension contract for deterministic audit rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from ..models import Finding, Severity

if TYPE_CHECKING:
    from ..context import ProjectContext


@dataclass(frozen=True, slots=True)
class RuleMetadata(Mapping[str, Any]):
    """Descriptive metadata used to register and render an audit rule."""

    rule_id: str
    name: str
    category: str
    description: str = ""
    default_severity: Severity = Severity.MEDIUM

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return self.as_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(("rule_id", "name", "category", "description", "default_severity"))

    def __len__(self) -> int:
        return 5


class AuditRule(ABC):
    """A read-only audit operation over a prepared :class:`ProjectContext`."""

    rule_id = ""
    name = ""
    category = "general"
    description = ""
    default_severity = Severity.MEDIUM

    @property
    def metadata(self) -> RuleMetadata:
        """Return stable registration metadata without running the rule."""

        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name or self.__class__.__name__,
            category=self.category,
            description=self.description,
            default_severity=self.default_severity,
        )

    @abstractmethod
    def check(self, context: "ProjectContext") -> list[Finding]:
        """Inspect ``context`` and return findings without changing the project."""


__all__ = ["AuditRule", "RuleMetadata"]

