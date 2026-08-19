"""Short-lived request client for ReleaseGuard's local named-pipe server."""

from __future__ import annotations

from contextlib import closing
from multiprocessing.connection import AuthenticationError, Client
from typing import Any, Callable, Mapping, Protocol

from .pipe_protocol import (
    MAX_RESPONSE_BYTES,
    PIPE_ADDRESS,
    PIPE_AUTHKEY,
    PIPE_FAMILY,
    PipeCommunicationError,
    PipeProtocolError,
    PipeTimeoutError,
    PipeUnavailableError,
    decode_message,
    encode_message,
)


class ByteConnection(Protocol):
    """The minimal ``multiprocessing.connection.Connection`` API used here."""

    def send_bytes(self, buf: bytes) -> None: ...

    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...

    def poll(self, timeout: float = 0.0) -> bool: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[..., ByteConnection]


class PipeClient:
    """Make one authenticated, bounded request per pipe connection."""

    def __init__(
        self,
        *,
        address: str = PIPE_ADDRESS,
        authkey: bytes = PIPE_AUTHKEY,
        connection_factory: ConnectionFactory = Client,
    ) -> None:
        self.address = address
        self.authkey = authkey
        self._connection_factory = connection_factory

    def call(
        self,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        """Send one request and return one response, with no implicit retry."""

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        encoded = encode_message(payload)
        try:
            connection = self._connection_factory(
                self.address,
                family=PIPE_FAMILY,
                authkey=self.authkey,
            )
        except FileNotFoundError as error:
            raise PipeUnavailableError("The ReleaseGuard local AI server is not running.") from error
        except (AuthenticationError, OSError) as error:
            raise PipeCommunicationError("Could not connect to the ReleaseGuard local AI server.") from error

        try:
            with closing(connection):
                connection.send_bytes(encoded)
                if not connection.poll(timeout_seconds):
                    raise PipeTimeoutError(
                        "The ReleaseGuard local AI server did not respond before the timeout."
                    )
                raw = connection.recv_bytes(MAX_RESPONSE_BYTES)
        except PipeTimeoutError:
            raise
        except (EOFError, OSError, ValueError) as error:
            raise PipeCommunicationError(
                "Communication with the ReleaseGuard local AI server failed."
            ) from error

        try:
            return decode_message(raw)
        except PipeProtocolError as error:
            raise PipeCommunicationError(
                "The ReleaseGuard local AI server returned an invalid response."
            ) from error

    def status(self, *, timeout_seconds: float = 2.0) -> dict[str, Any]:
        """Return the server's current state."""

        return self.call({"op": "status"}, timeout_seconds=timeout_seconds)

    def request(
        self,
        request: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Submit one structured risk-analysis request."""

        return self.call(
            {"op": "request", "request": dict(request)},
            timeout_seconds=timeout_seconds,
        )

    def shutdown(self, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
        """Ask the local server to stop after its active request completes."""

        return self.call(
            {"op": "shutdown", "timeout": timeout_seconds},
            timeout_seconds=timeout_seconds,
        )


__all__ = ["ByteConnection", "ConnectionFactory", "PipeClient"]
