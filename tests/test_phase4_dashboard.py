from __future__ import annotations

from http.client import HTTPResponse
import json
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from releaseguard.phase4.dashboard import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DashboardContext,
    create_server,
)


RAW_DEMO_TOKEN = "sk-TEST_ONLY_RELEASEGUARD_1234567890"


def _state() -> dict[str, object]:
    return {
        "project": {"name": "<demo>", "path": "C:/demo/<unsafe>"},
        "score": 50,
        "gate": "BLOCKED",
        "summary": {"counts": {"critical": 1, "high": 1, "medium": 0, "low": 0}},
        "findings": [
            {
                "finding_id": "RG-SECRET-001",
                "rule_id": "RG-SECRET-001",
                "title": "Credential <detected>",
                "severity": "critical",
                "status": "NEEDS_REVIEW",
                "file": "src/config.ts",
                "line": 17,
                "evidence": RAW_DEMO_TOKEN,
                "explanation": "A value <requires> human review.",
                "recommendation": "Move it to an environment reference.",
            }
        ],
        "remediation_plan": [
            {
                "finding_id": "RG-SECRET-001",
                "summary": "Move the credential",
                "risk": "high",
                "allowed_files": ["src/config.ts", ".env.example"],
                "allowed_operations": ["replace literal"],
                "forbidden_operations": ["write a real secret"],
            }
        ],
        "timeline": [
            {
                "timestamp": "2026-08-17T10:00:00Z",
                "type": "FindingDetected",
                "finding_id": "RG-SECRET-001",
                "summary": "Credential detected",
            }
        ],
    }


class WorkflowStub:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def review(self, finding_id: str, action: str, reason: str, actor: str = "human") -> dict[str, str]:
        self.calls.append(
            {"finding_id": finding_id, "action": action, "reason": reason, "actor": actor}
        )
        return {"approval_id": "approval-1", "finding_id": finding_id, "action": action}


@pytest.fixture()
def dashboard_server() -> tuple[object, WorkflowStub, DashboardContext, str]:
    workflow = WorkflowStub()
    state = _state()
    server = create_server(
        Path("."),
        port=0,
        workflow=workflow,
        audit_provider=lambda: state,
        status_provider=lambda: {"ok": True, "state": "running", "backend": "OpenVINO", "device": "GPU", "model_id": "local-test"},
        token_secret=b"dashboard-test-secret",
    )
    context = server.dashboard_context
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
    try:
        yield server, workflow, context, base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _read(url: str) -> tuple[int, str, str]:
    response: HTTPResponse
    with urlopen(url) as response:
        body = response.read().decode("utf-8")
        return response.status, response.headers.get("Content-Type", ""), body


def test_server_is_loopback_only_and_uses_expected_default_configuration() -> None:
    assert DEFAULT_HOST == "127.0.0.1"
    assert DEFAULT_PORT == 8765
    with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
        create_server(".", host="0.0.0.0", port=0)

    server = create_server(".", port=0, audit_provider=lambda: {})
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_home_and_detail_escape_content_and_never_render_raw_secret(dashboard_server: tuple[object, WorkflowStub, DashboardContext, str]) -> None:
    _server, _workflow, context, base_url = dashboard_server
    status, content_type, body = _read(base_url + "/")
    assert status == 200
    assert "text/html" in content_type
    assert "ReleaseGuard" in body
    assert "BLOCKED" in body
    assert "RG-SECRET-001" in body
    assert "&lt;demo&gt;" in body
    assert "Remediation Plan" in body
    assert "Approval History" in body
    assert "Audit History" in body
    assert "Review:" in body
    assert RAW_DEMO_TOKEN not in body
    assert "****" in body or "REDACTED" in body

    status, _content_type, detail = _read(base_url + "/finding/RG-SECRET-001")
    assert status == 200
    assert "Approval History" in detail
    assert "Audit History" in detail
    assert "allowed_files" not in detail
    assert RAW_DEMO_TOKEN not in detail
    assert context.action_token("RG-SECRET-001", "approve") in detail


def test_json_endpoints_expose_summary_timeline_and_actual_ai_status(dashboard_server: tuple[object, WorkflowStub, DashboardContext, str]) -> None:
    _server, _workflow, _context, base_url = dashboard_server
    status, content_type, raw = _read(base_url + "/api/state")
    assert status == 200
    assert "application/json" in content_type
    payload = json.loads(raw)
    assert payload["score"] == 50
    assert payload["gate"] == "BLOCKED"
    assert payload["summary"]["counts"]["critical"] == 1
    assert payload["ai_status"]["device"] == "GPU"
    assert RAW_DEMO_TOKEN not in raw

    _status, _content_type, timeline_raw = _read(base_url + "/api/timeline")
    assert "FindingDetected" in timeline_raw

    _status, _content_type, health = _read(base_url + "/healthz")
    assert json.loads(health)["ok"] is True


def test_review_post_requires_finding_bound_token_and_false_positive_reason(dashboard_server: tuple[object, WorkflowStub, DashboardContext, str]) -> None:
    _server, workflow, context, base_url = dashboard_server
    endpoint = base_url + "/api/review/RG-SECRET-001"

    invalid = Request(
        endpoint,
        data=urlencode({"action": "approve", "token": "wrong"}).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with pytest.raises(HTTPError) as error:
        urlopen(invalid)
    assert error.value.code == 403
    assert workflow.calls == []

    missing_reason = Request(
        endpoint,
        data=urlencode(
            {"action": "false_positive", "token": context.action_token("RG-SECRET-001", "false_positive")}
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with pytest.raises(HTTPError) as error:
        urlopen(missing_reason)
    assert error.value.code == 400
    assert workflow.calls == []

    valid = Request(
        endpoint,
        data=urlencode(
            {
                "action": "approve",
                "token": context.action_token("RG-SECRET-001", "approve"),
                "reason": "Approved migration",
            }
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(valid) as response:
        assert response.status == 200
        payload = json.loads(response.read().decode())
    assert payload["ok"] is True
    assert workflow.calls[-1]["action"] == "approve"
    assert workflow.calls[-1]["actor"] == "human"


def test_injectable_server_factory_receives_loopback_address() -> None:
    calls: list[tuple[tuple[str, int], object]] = []

    class FakeServer:
        server_address = ("127.0.0.1", 8765)

    def factory(address: tuple[str, int], handler: object) -> FakeServer:
        calls.append((address, handler))
        return FakeServer()

    server = create_server(".", server_factory=factory)
    assert isinstance(server, FakeServer)
    assert calls and calls[0][0] == ("127.0.0.1", 8765)
    assert getattr(server, "dashboard_context") is not None
