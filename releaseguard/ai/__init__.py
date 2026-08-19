"""Optional local-AI contracts and backwards-compatible Phase 1 interfaces.

The package initializer does not import ``base`` eagerly: core models need the
schemas for optional result metadata, while the Phase 1 base interface imports
``Finding``. Lazy access preserves the old public symbols without a cycle.
"""

from .schemas import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIReview,
    FindingAnalysis,
    FindingExcerpt,
    FindingPayload,
    ReviewDisposition,
    ReviewStatus,
)

__all__ = [
    "AIAnalysisRequest",
    "AIAnalysisResponse",
    "AIAnalyzer",
    "AIReview",
    "FindingAnalysis",
    "FindingExcerpt",
    "FindingPayload",
    "NullAIAnalyzer",
    "ReviewDisposition",
    "ReviewStatus",
]


def __getattr__(name: str) -> object:
    """Load the legacy Phase 1 analyzer extension point on demand."""

    if name in {"AIAnalyzer", "NullAIAnalyzer"}:
        from .base import AIAnalyzer, NullAIAnalyzer

        return {"AIAnalyzer": AIAnalyzer, "NullAIAnalyzer": NullAIAnalyzer}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
