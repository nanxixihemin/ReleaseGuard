"""Small, bounded JSON protocol shared by the local AI pipe client and server.

The transport is a Windows ``multiprocessing.connection`` named pipe.  That
transport can pickle arbitrary objects when using ``send`` / ``recv``; this
module deliberately uses ``send_bytes`` / ``recv_bytes`` with UTF-8 JSON
instead so a local client only has a narrow, inspectable message surface.
"""

from __future__ import annotations

import json
from typing import Any, Mapping


PIPE_ADDRESS = r"\\.\pipe\releaseguard-openvino-v1"
PIPE_AUTHKEY = b"releaseguard-openvino-v1"
PIPE_FAMILY = "AF_PIPE"
MAX_REQUEST_BYTES = 512_000
MAX_RESPONSE_BYTES = 512_000


class PipeProtocolError(RuntimeError):
    """Raised when a message cannot satisfy the local protocol contract."""


class PipeCommunicationError(RuntimeError):
    """Raised when the named-pipe transport cannot complete a request."""


class PipeUnavailableError(PipeCommunicationError):
    """Raised when the local server pipe does not exist."""


class PipeTimeoutError(PipeCommunicationError):
    """Raised when a connected server does not answer before the deadline."""


def encode_message(
    payload: Mapping[str, Any], *, max_bytes: int = MAX_REQUEST_BYTES
) -> bytes:
    """Encode one allowlisted protocol object as bounded UTF-8 JSON bytes."""

    if not isinstance(payload, Mapping):
        raise PipeProtocolError("Pipe payload must be a JSON object.")
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PipeProtocolError("Pipe payload must be JSON serializable.") from error
    if len(encoded) > max_bytes:
        raise PipeProtocolError(
            f"Pipe payload exceeds the {max_bytes}-byte local protocol limit."
        )
    return encoded


def decode_message(raw: bytes, *, max_bytes: int = MAX_RESPONSE_BYTES) -> dict[str, Any]:
    """Decode one bounded UTF-8 JSON object from the pipe."""

    if not isinstance(raw, bytes):
        raise PipeProtocolError("Pipe response must be bytes.")
    if len(raw) > max_bytes:
        raise PipeProtocolError(
            f"Pipe response exceeds the {max_bytes}-byte local protocol limit."
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PipeProtocolError("Pipe response is not valid UTF-8 JSON.") from error
    if not isinstance(value, dict):
        raise PipeProtocolError("Pipe response must be a JSON object.")
    return value


def error_response(message: str, *, state: str = "error") -> dict[str, Any]:
    """Return the common, source-safe server error envelope."""

    return {"ok": False, "state": state, "error": message[:500]}


__all__ = [
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "PIPE_ADDRESS",
    "PIPE_AUTHKEY",
    "PIPE_FAMILY",
    "PipeCommunicationError",
    "PipeProtocolError",
    "PipeTimeoutError",
    "PipeUnavailableError",
    "decode_message",
    "encode_message",
    "error_response",
]
