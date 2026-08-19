"""Long-lived Windows named-pipe host for ReleaseGuard's local OpenVINO model."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from releaseguard.ai.local_server import LocalAIServer
from releaseguard.ai.openvino_engine import OpenVINOEngine
from releaseguard.ai.pipe_protocol import PIPE_ADDRESS, PIPE_AUTHKEY


def _configure_stream_encoding(stream: object) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def _default_log_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "ReleaseGuard" / "log"
    return Path.home() / "AppData" / "Local" / "ReleaseGuard" / "log"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ReleaseGuard local OpenVINO server")
    parser.add_argument("--pipe-address", default=PIPE_ADDRESS)
    parser.add_argument("--models-directory", type=Path, default=None)
    parser.add_argument("--device", default=None, help="Preferred OpenVINO device, if actually available.")
    parser.add_argument("--log-directory", type=Path, default=None)
    return parser


def _logger(log_directory: Path) -> logging.Logger:
    log_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    logger = logging.getLogger(f"releaseguard.openvino.server.{os.getpid()}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(
        log_directory / f"releaseguard-server-{timestamp}.log",
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [server pid=%(process)d] %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    return logger


def main(argv: list[str] | None = None) -> int:
    _configure_stream_encoding(sys.stdout)
    _configure_stream_encoding(sys.stderr)
    args = _build_parser().parse_args(argv)
    if os.name != "nt":
        print("ReleaseGuard local AI server requires Windows named pipes.", file=sys.stderr)
        return 1

    logger = _logger(args.log_directory or _default_log_directory())
    engine = OpenVINOEngine(
        models_directory=args.models_directory,
        requested_device=args.device,
    )
    server = LocalAIServer(
        engine,
        address=args.pipe_address,
        authkey=PIPE_AUTHKEY,
        log=logger.info,
    )
    try:
        server.serve_forever()
    except OSError:
        logger.exception("named-pipe server could not start")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess.
    raise SystemExit(main())
