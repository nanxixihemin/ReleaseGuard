"""Stable short-lived Local Skill client behind ``scripts/run.ps1``."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from releaseguard.ai.schemas import ReviewStatus
from releaseguard.ai.service import LocalOpenVINOReviewClient, LocalServerManager
from releaseguard.reporters import render_json, render_markdown
from releaseguard.scanner import audit_project


DOWNLOAD_EXIT_CODE = 3
DEFAULT_DOWNLOAD_WAIT_SECONDS = 480.0


def _configure_stream_encoding(stream: object) -> None:
    reconfigure = getattr(stream, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def _runtime_home() -> Path:
    configured = os.environ.get("RELEASEGUARD_RUNTIME_HOME")
    if configured:
        return Path(configured)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "ReleaseGuard"
    return Path.home() / "AppData" / "Local" / "ReleaseGuard"


def _pending_path() -> Path:
    return _runtime_home() / "releaseguard-pending-request.json"


def _save_pending(argv: Sequence[str]) -> None:
    """Persist only a local command resume token, never audit content or results."""

    path = _pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "cwd": str(Path.cwd()), "argv": list(argv)}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _load_pending() -> list[str] | None:
    path = _pending_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        argv = payload.get("argv")
        cwd = payload.get("cwd")
        if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
            return None
        if isinstance(cwd, str) and Path(cwd).is_dir():
            os.chdir(cwd)
        return argv
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _remove_pending() -> None:
    try:
        _pending_path().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scripts\\run.ps1 audit")
    parser.add_argument("project_path", type=Path)
    parser.add_argument("--format", "-f", dest="output_format", default="markdown")
    parser.add_argument("--output", "-o", type=Path, default=None)
    parser.add_argument("--ai", action="store_true")
    parser.add_argument("--ai-timeout", type=float, default=None)
    parser.add_argument("--remediation-plan", action="store_true")
    return parser


def _is_audit_invocation(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == "audit"


def _run_audit(argv: Sequence[str]) -> int:
    args = _audit_parser().parse_args(list(argv)[1:])
    output_format = args.output_format.lower().strip()
    if output_format not in {"markdown", "json"}:
        print("Error: --format must be either 'markdown' or 'json'.", file=sys.stderr)
        return 1
    if not args.project_path.is_dir():
        print(f"Audit error: project directory does not exist: {args.project_path}", file=sys.stderr)
        return 1
    if args.ai_timeout is not None and args.ai_timeout <= 0:
        print("Error: --ai-timeout must be greater than zero.", file=sys.stderr)
        return 1

    client: LocalOpenVINOReviewClient | None = None
    audit_options: dict[str, object] = {}
    if args.remediation_plan:
        audit_options["include_remediation_plan"] = True
    if args.ai:
        timeout = args.ai_timeout or DEFAULT_DOWNLOAD_WAIT_SECONDS
        manager = LocalServerManager()
        client = LocalOpenVINOReviewClient(
            manager=manager,
            startup_timeout_seconds=timeout,
        )
        result = audit_project(
            args.project_path,
            ai_client=client,
            ai_timeout_seconds=timeout,
            **audit_options,
        )
    else:
        result = audit_project(args.project_path, **audit_options) if audit_options else audit_project(args.project_path)

    report = render_json(result) if output_format == "json" else render_markdown(result)
    if args.output is not None:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report, end="")

    if (
        args.ai
        and result.ai_review is not None
        and result.ai_review.status is ReviewStatus.TIMEOUT
        and client is not None
        and client.manager.status().get("state") in {"starting", "downloading", "loading"}
    ):
        _save_pending(argv)
        print("模型正在下载或加载，请使用命令 'scripts\\run.ps1 --continue' 继续运行。", file=sys.stderr)
        return DOWNLOAD_EXIT_CODE
    _remove_pending()
    return 0


def _run_cli(argv: Sequence[str]) -> int:
    from releaseguard.cli import app
    import typer

    try:
        app(args=list(argv), prog_name="releaseguard", standalone_mode=False)
    except typer.Exit as error:
        return int(error.exit_code)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stream_encoding(sys.stdout)
    _configure_stream_encoding(sys.stderr)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--continue"]:
        pending = _load_pending()
        if pending is None:
            print("没有可继续的本地模型下载请求。", file=sys.stderr)
            return 1
        arguments = pending
    if not arguments:
        print(
            "Usage: scripts\\run.ps1 audit <path> [--ai] [--remediation-plan] | "
            "compare <before.json> <after.json> | ai status|start|stop",
            file=sys.stderr,
        )
        return 1
    return _run_audit(arguments) if _is_audit_invocation(arguments) else _run_cli(arguments)


if __name__ == "__main__":  # pragma: no cover - executed through PowerShell.
    raise SystemExit(main())
