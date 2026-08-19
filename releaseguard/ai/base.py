"""A local-only extension point for semantic finding analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from ..context import ProjectContext


class AIAnalyzer(ABC):
    """Future local analyzers enrich findings without owning file traversal."""

    @abstractmethod
    def analyze(
        self,
        findings: Sequence[Finding],
        context: "ProjectContext",
    ) -> list[Finding]:
        """Return enriched findings using only the supplied local context."""


class NullAIAnalyzer(AIAnalyzer):
    """The Phase 1 default, preserving deterministic findings unchanged."""

    def analyze(
        self,
        findings: Sequence[Finding],
        context: "ProjectContext",
    ) -> list[Finding]:
        del context
        return list(findings)


__all__ = ["AIAnalyzer", "NullAIAnalyzer"]

