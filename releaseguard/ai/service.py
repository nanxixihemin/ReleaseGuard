"""Client-side lifecycle and review adapter for the local OpenVINO server."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from time import monotonic, sleep
from typing import Any, Callable, Mapping

from .pipe_client import PipeClient
from .pipe_protocol import PipeCommunicationError, PipeTimeoutError, PipeUnavailableError
from .response_parser import parse_analysis_response
from .schemas import AIAnalysisRequest, AIReview, ReviewStatus


SERVER_READY_STATES = frozenset({"starting", "downloading", "loading"})


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


class LocalServerManager:
    """Start and query the standalone local named-pipe model server."""

    def __init__(
        self,
        *,
        pipe_client: PipeClient | None = None,
        python_executable: str | None = None,
        server_script: str | Path | None = None,
        models_directory: str | Path | None = None,
        device: str | None = None,
        popen: Callable[..., Any] = subprocess.Popen,
        sleep_fn: Callable[[float], None] = sleep,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.pipe_client = pipe_client or PipeClient()
        self.python_executable = python_executable or sys.executable
        self.server_script = Path(server_script) if server_script is not None else _project_root() / "scripts" / "server.py"
        self.models_directory = Path(models_directory) if models_directory is not None else None
        self.device = device
        self._popen = popen
        self._sleep = sleep_fn
        self._clock = clock

    def status(self, *, timeout_seconds: float = 2.0) -> dict[str, Any]:
        """Return a safe stopped result when the pipe has not been created yet."""

        try:
            response = self.pipe_client.status(timeout_seconds=timeout_seconds)
        except PipeUnavailableError:
            return {"ok": False, "state": "stopped", "local": True}
        except PipeCommunicationError:
            return {"ok": False, "state": "unavailable", "local": True}
        if not isinstance(response, dict):
            return {"ok": False, "state": "unavailable", "local": True}
        return response

    def start(self) -> dict[str, Any]:
        """Start a server only when a live pipe is not already present."""

        current = self.status()
        if current.get("state") not in {"stopped", "unavailable"}:
            return current

        command = [
            self.python_executable,
            str(self.server_script),
            "--pipe-address",
            str(getattr(self.pipe_client, "address", r"\\.\pipe\releaseguard-openvino-v1")),
        ]
        if self.models_directory is not None:
            command.extend(["--models-directory", str(self.models_directory)])
        if self.device:
            command.extend(["--device", self.device])
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            self._popen(
                command,
                cwd=str(_project_root()),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
        except OSError:
            return {"ok": False, "state": "unavailable", "local": True}
        return {"ok": True, "state": "starting", "local": True}

    def wait_for_ready(self, *, timeout_seconds: float, poll_seconds: float = 0.25) -> dict[str, Any]:
        """Wait across the standard startup states without treating them as success."""

        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        deadline = self._clock() + timeout_seconds
        latest = self.status()
        # Immediately after Popen the pipe may not exist yet. Treat that short
        # window as startup rather than deciding the just-spawned server stopped.
        while self._clock() < deadline:
            state = str(latest.get("state", "unavailable"))
            if state == "running" or state == "error":
                return latest
            if state not in SERVER_READY_STATES and state not in {"stopped", "unavailable"}:
                return latest
            self._sleep(min(poll_seconds, max(0.0, deadline - self._clock())))
            latest = self.status()
        if str(latest.get("state")) in {"stopped", "unavailable"}:
            return {"ok": False, "state": "starting", "local": True}
        return latest

    def ensure_running(self, *, timeout_seconds: float) -> dict[str, Any]:
        """Reuse, start, and then wait for a local server state transition."""

        current = self.status()
        if current.get("state") in {"stopped", "unavailable"}:
            current = self.start()
        if current.get("state") == "running" or timeout_seconds == 0:
            return current
        if current.get("state") in SERVER_READY_STATES:
            return self.wait_for_ready(timeout_seconds=timeout_seconds)
        return current

    def stop(self, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
        """Request graceful local shutdown; absence is already a stopped service."""

        try:
            return self.pipe_client.shutdown(timeout_seconds=timeout_seconds)
        except PipeUnavailableError:
            return {"ok": True, "state": "stopped", "local": True}
        except PipeCommunicationError:
            return {"ok": False, "state": "unavailable", "local": True}


class LocalOpenVINOReviewClient:
    """Concrete advisory reviewer used by `audit_project(..., ai_client=...)`."""

    def __init__(
        self,
        *,
        manager: LocalServerManager | None = None,
        startup_timeout_seconds: float = 15.0,
    ) -> None:
        if startup_timeout_seconds < 0:
            raise ValueError("startup_timeout_seconds must be non-negative")
        self.manager = manager or LocalServerManager()
        self.startup_timeout_seconds = startup_timeout_seconds

    def review(
        self,
        request: AIAnalysisRequest,
        *,
        timeout_seconds: float,
    ) -> AIReview:
        """Obtain local structured advice, returning a safe status on every failure."""

        startup_timeout = min(self.startup_timeout_seconds, timeout_seconds)
        status = self.manager.ensure_running(timeout_seconds=startup_timeout)
        state = str(status.get("state", "unavailable"))
        if state != "running":
            if state in SERVER_READY_STATES:
                return AIReview.failure(
                    ReviewStatus.TIMEOUT,
                    error_code="server_start_timeout",
                    error_message="The local OpenVINO model is still starting or downloading.",
                )
            if state == "error":
                return AIReview.failure(
                    ReviewStatus.ERROR,
                    error_code="server_model_error",
                    error_message="The local OpenVINO model could not initialize.",
                )
            return AIReview.failure(
                ReviewStatus.UNAVAILABLE,
                error_code="server_unavailable",
                error_message="The local OpenVINO server was unavailable.",
            )

        try:
            response = self.manager.pipe_client.request(
                request.model_dump(mode="json"),
                timeout_seconds=timeout_seconds,
            )
        except PipeTimeoutError:
            return AIReview.failure(
                ReviewStatus.TIMEOUT,
                error_code="inference_timeout",
                error_message="The local OpenVINO inference timed out.",
            )
        except PipeCommunicationError:
            return AIReview.failure(
                ReviewStatus.UNAVAILABLE,
                error_code="pipe_communication_failed",
                error_message="The local OpenVINO server could not be reached.",
            )

        if response.get("ok") is not True:
            return AIReview.failure(
                ReviewStatus.ERROR,
                error_code="server_request_failed",
                error_message="The local OpenVINO server could not complete the review.",
            )
        raw_response = response.get("response")
        if not isinstance(raw_response, str):
            return AIReview.failure(
                ReviewStatus.INVALID_RESPONSE,
                error_code="missing_model_response",
                error_message="The local OpenVINO server returned no structured response.",
            )

        # Device/model identity comes from the server runtime, never model text.
        device = response.get("device")
        return parse_analysis_response(
            raw_response,
            (finding.fingerprint for finding in request.findings),
            runtime_model_id=str(response.get("model_id", "OpenVINO local model")),
            runtime_device=device if isinstance(device, str) else None,
        )


__all__ = ["LocalOpenVINOReviewClient", "LocalServerManager", "SERVER_READY_STATES"]
