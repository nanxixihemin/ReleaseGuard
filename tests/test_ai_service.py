from __future__ import annotations

import json

from releaseguard.ai.schemas import AIAnalysisRequest, FindingPayload, ReviewStatus
from releaseguard.ai.service import LocalOpenVINOReviewClient, LocalServerManager


class FakePipe:
    def __init__(self, statuses: list[dict[str, object]], response: dict[str, object] | None = None) -> None:
        self.statuses = statuses
        self.response = response or {"ok": True, "state": "shutting_down"}
        self.requests: list[dict[str, object]] = []

    def status(self, *, timeout_seconds: float) -> dict[str, object]:
        del timeout_seconds
        return self.statuses.pop(0) if self.statuses else {"ok": True, "state": "running"}

    def request(self, request: dict[str, object], *, timeout_seconds: float) -> dict[str, object]:
        del timeout_seconds
        self.requests.append(request)
        return self.response

    def shutdown(self, *, timeout_seconds: float) -> dict[str, object]:
        del timeout_seconds
        return {"ok": True, "state": "shutting_down"}


def _request() -> AIAnalysisRequest:
    return AIAnalysisRequest(
        project_name="demo",
        findings=[
            FindingPayload(
                fingerprint="b" * 64,
                rule_id="RG-ENV-001",
                title="Loopback URL",
                severity="high",
                category="environment",
                file="config.py",
                line=1,
                evidence="http://localhost:8000",
                explanation="risk",
                recommendation="fix",
                confidence=0.9,
            )
        ],
    )


def test_manager_waits_for_running_state_without_spawning_existing_server() -> None:
    pipe = FakePipe([
        {"ok": True, "state": "loading"},
        {"ok": True, "state": "running", "device": "CPU"},
    ])
    manager = LocalServerManager(
        pipe_client=pipe,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    status = manager.ensure_running(timeout_seconds=1)

    assert status["state"] == "running"


def test_local_review_parses_runtime_metadata_not_model_claimed_device() -> None:
    raw = {
        "finding_assessments": [
            {
                "fingerprint": "b" * 64,
                "likely_true_positive": True,
                "confidence": 0.97,
                "semantic_risk": "high",
                "rationale": "Deployable local fallback.",
                "remediation": "Set a deployment URL.",
            }
        ],
        "release_summary": "Review deployment configuration.",
        "overall_confidence": 0.9,
    }
    pipe = FakePipe(
        [{"ok": True, "state": "running"}],
        {
            "ok": True,
            "state": "running",
            "model_id": "OpenVINO/Qwen-test",
            "device": "GPU",
            "response": json.dumps(raw),
        },
    )
    client = LocalOpenVINOReviewClient(
        manager=LocalServerManager(pipe_client=pipe, sleep_fn=lambda _: None),  # type: ignore[arg-type]
    )

    review = client.review(_request(), timeout_seconds=2)

    assert review.status is ReviewStatus.COMPLETED
    assert review.model_id == "OpenVINO/Qwen-test"
    assert review.device == "GPU"
    assert review.local is True
    assert review.finding_assessments[0].likely_true_positive is True


def test_startup_timeout_degrades_without_submitting_a_request() -> None:
    pipe = FakePipe([{"ok": True, "state": "loading"}])
    client = LocalOpenVINOReviewClient(
        manager=LocalServerManager(pipe_client=pipe, sleep_fn=lambda _: None),  # type: ignore[arg-type]
        startup_timeout_seconds=0,
    )

    review = client.review(_request(), timeout_seconds=1)

    assert review.status is ReviewStatus.TIMEOUT
    assert pipe.requests == []
