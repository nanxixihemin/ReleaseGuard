"""ReleaseGuard's public package contract."""

from .models import (
    AuditResult,
    AuditSummary,
    Finding,
    FindingStatus,
    Disposition,
    GitSnapshot,
    ReleaseGate,
    Severity,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "AuditResult",
    "AuditSummary",
    "Finding",
    "FindingStatus",
    "Disposition",
    "GitSnapshot",
    "ReleaseGate",
    "Severity",
    "ApprovalAction",
    "ApprovalRecord",
    "ApprovalStatus",
    "ProjectSnapshot",
    "RemediationPlan",
    "TimelineEvent",
    "TimelineEventType",
]


def __getattr__(name: str):
    """Lazily expose Phase 4 contracts without importing workflow at startup."""

    names = {
        "ApprovalAction",
        "ApprovalRecord",
        "ApprovalStatus",
        "ProjectSnapshot",
        "RemediationPlan",
        "TimelineEvent",
        "TimelineEventType",
    }
    if name in names:
        from .phase4 import models as phase4_models

        return getattr(phase4_models, name)
    raise AttributeError(name)
