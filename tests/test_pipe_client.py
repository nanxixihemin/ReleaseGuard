from __future__ import annotations

import json

import pytest

from releaseguard.ai.pipe_client import PipeClient
from releaseguard.ai.pipe_protocol import (
    PipeCommunicationError,
    PipeProtocolError,
    PipeTimeoutError,
    PipeUnavailableError,
    decode_message,
    encode_message,
)


class FakeConnection:
    def __init__(self, response: bytes, *, readable: bool = True) -> None:
        self.response = response
        self.readable = readable
        self.sent: bytes | None = None
        self.closed = False

    def send_bytes(self, buf: bytes) -> None:
        self.sent = buf

    def recv_bytes(self, maxlength: int | None = None) -> bytes:
        if maxlength is not None and len(self.response) > maxlength:
            raise OSError("message too long")
        return self.response

    def poll(self, timeout: float = 0.0) -> bool:
        return self.readable

    def close(self) -> None:
        self.closed = True


def test_protocol_encodes_and_decodes_bounded_json() -> None:
    encoded = encode_message({"op": "status", "unicode": "本地"})

    assert decode_message(encoded) == {"op": "status", "unicode": "本地"}
    with pytest.raises(PipeProtocolError, match="JSON object"):
        encode_message(["status"])  # type: ignore[arg-type]
    with pytest.raises(PipeProtocolError, match="valid UTF-8 JSON"):
        decode_message(b"not json")


def test_client_sends_one_status_request_and_closes_connection() -> None:
    connection = FakeConnection(json.dumps({"ok": True, "state": "running"}).encode())
    client = PipeClient(connection_factory=lambda *args, **kwargs: connection)

    response = client.status()

    assert response == {"ok": True, "state": "running"}
    assert json.loads(connection.sent.decode("utf-8")) == {"op": "status"}
    assert connection.closed is True


def test_client_maps_missing_pipe_to_unavailable() -> None:
    def absent(*args: object, **kwargs: object) -> FakeConnection:
        raise FileNotFoundError("missing")

    with pytest.raises(PipeUnavailableError):
        PipeClient(connection_factory=absent).status()


def test_client_maps_response_timeout() -> None:
    connection = FakeConnection(b"{}", readable=False)
    client = PipeClient(connection_factory=lambda *args, **kwargs: connection)

    with pytest.raises(PipeTimeoutError):
        client.status(timeout_seconds=0.01)
    assert connection.closed is True


def test_client_maps_invalid_server_json_to_safe_communication_error() -> None:
    connection = FakeConnection(b"not json")
    client = PipeClient(connection_factory=lambda *args, **kwargs: connection)

    with pytest.raises(PipeCommunicationError, match="invalid response"):
        client.status()
