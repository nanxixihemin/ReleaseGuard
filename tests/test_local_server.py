from __future__ import annotations

import json
from types import SimpleNamespace

from releaseguard.ai.local_server import (
    MODEL_OUTPUT_JSON_SCHEMA,
    LocalAIServer,
    ServerState,
    build_risk_prompt,
)
from releaseguard.ai.schemas import AIAnalysisRequest, FindingPayload


class ReadyEngine:
    config = SimpleNamespace(model_id="OpenVINO/test-local")
    selected_device = "CPU"

    def ensure_model(self) -> None:
        return None

    def load(self) -> object:
        return object()

    def generate(self, prompt: str, **kwargs: object) -> str:
        assert "DATA_START" in prompt
        assert kwargs["do_sample"] is False
        return json.dumps(
            {
                "finding_assessments": [],
                "release_summary": "Local review.",
                "overall_confidence": 0.8,
            }
        )


def _request() -> AIAnalysisRequest:
    return AIAnalysisRequest(
        project_name="demo",
        findings=[
            FindingPayload(
                fingerprint="a" * 64,
                rule_id="RG-ENV-001",
                title="Loopback endpoint",
                severity="high",
                category="environment",
                file="config.py",
                line=1,
                evidence="http://localhost:8000",
                explanation="Deployment risk",
                recommendation="Use a production endpoint",
                confidence=0.96,
            )
        ],
    )


def test_status_exposes_only_verified_runtime_information() -> None:
    server = LocalAIServer(ReadyEngine())

    status = server.status_payload()

    assert status["state"] == "starting"
    assert status["model_id"] == "OpenVINO/test-local"
    assert status["device"] == "CPU"
    assert status["local"] is True


def test_request_before_model_ready_does_not_generate() -> None:
    server = LocalAIServer(ReadyEngine())

    response = server.handle_payload({"op": "request", "request": _request().model_dump(mode="json")})

    assert response["ok"] is False
    assert response["state"] == "starting"


def test_ready_server_generates_one_structured_response_and_shutdown_changes_state() -> None:
    server = LocalAIServer(ReadyEngine())
    server._set_state(ServerState.RUNNING)  # Focused protocol test, no background model work.

    response = server.handle_payload({"op": "request", "request": _request().model_dump(mode="json")})

    assert response["ok"] is True
    assert response["device"] == "CPU"
    assert json.loads(response["response"])["overall_confidence"] == 0.8
    shutdown = server.handle_payload({"op": "shutdown"})
    assert shutdown == {"ok": True, "state": "shutting_down"}
    assert server.state is ServerState.SHUTTING_DOWN


def test_prompt_contains_only_the_request_json_and_separate_structured_schema() -> None:
    prompt = build_risk_prompt(_request())

    assert '"project_name":"demo"' in prompt
    assert "finding_assessments" in MODEL_OUTPUT_JSON_SCHEMA["properties"]
    assert "likely_true_positive" in MODEL_OUTPUT_JSON_SCHEMA["properties"]["finding_assessments"]["items"]["properties"]
