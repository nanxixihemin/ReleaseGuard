"""Typer command-line interface for ReleaseGuard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import ValidationError

from . import __version__
from .models import AuditResult
from .remediation import compare_audits
from .reporters import (
    render_json,
    render_markdown,
    render_reaudit_json,
    render_reaudit_markdown,
)
from .scanner import audit_project


app = typer.Typer(
    name="releaseguard",
    help="A local-first release audit Skill for AI Coding Agents.",
    add_completion=False,
    no_args_is_help=True,
)
ai_app = typer.Typer(help="Manage the optional local OpenVINO analyzer.", no_args_is_help=True)
app.add_typer(ai_app, name="ai")


def _render(output_format: str, result: object) -> str:
    if output_format == "json":
        return render_json(result)  # type: ignore[arg-type]
    return render_markdown(result)  # type: ignore[arg-type]


@app.command()
def audit(
    project_path: Annotated[
        Path,
        typer.Argument(
            ..., help="Local project directory to audit.", exists=True, file_okay=False
        ),
    ],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Report format: markdown or json.")
    ] = "markdown",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional report output file.")
    ] = None,
    ai: Annotated[
        bool,
        typer.Option("--ai", help="Request advisory analysis from the local OpenVINO server."),
    ] = False,
    ai_timeout: Annotated[
        float,
        typer.Option("--ai-timeout", help="Maximum local-AI startup/inference wait in seconds."),
    ] = 15.0,
    remediation_plan: Annotated[
        bool,
        typer.Option(
            "--remediation-plan",
            help="Include deterministic, safety-classified agent remediation guidance.",
        ),
    ] = False,
) -> None:
    """Audit PROJECT_PATH without executing or modifying project code."""

    normalized_format = output_format.lower().strip()
    if normalized_format not in {"markdown", "json"}:
        typer.echo("Error: --format must be either 'markdown' or 'json'.", err=True)
        raise typer.Exit(code=2)

    try:
        audit_options: dict[str, object] = {}
        if remediation_plan:
            audit_options["include_remediation_plan"] = True
        if ai:
            if ai_timeout <= 0:
                raise ValueError("--ai-timeout must be greater than zero")
            from .ai.service import LocalOpenVINOReviewClient

            result = audit_project(
                project_path,
                ai_client=LocalOpenVINOReviewClient(
                    startup_timeout_seconds=ai_timeout
                ),
                ai_timeout_seconds=ai_timeout,
                **audit_options,
            )
        else:
            # Preserve the Phase 1 call shape and behavior when local AI is off.
            result = audit_project(project_path, **audit_options) if audit_options else audit_project(project_path)
        report = _render(normalized_format, result)
    except (OSError, ValueError) as error:
        typer.echo(f"Audit error: {error}", err=True)
        raise typer.Exit(code=2) from None

    if output is not None:
        try:
            output.write_text(report, encoding="utf-8")
        except OSError as error:
            typer.echo(f"Output error: could not write '{output}': {error}", err=True)
            raise typer.Exit(code=2) from None
        typer.echo(f"Report written to {output}", err=True)
    else:
        typer.echo(report, nl=False)


def _load_audit_result(path: Path) -> AuditResult:
    """Load a saved audit document without accepting arbitrary comparison input."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return AuditResult.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError, TypeError) as error:
        raise ValueError(f"could not read a valid ReleaseGuard JSON audit from '{path}'") from error


@app.command("compare")
def compare(
    before: Annotated[
        Path,
        typer.Argument(..., help="Earlier ReleaseGuard JSON audit.", exists=True, dir_okay=False),
    ],
    after: Annotated[
        Path,
        typer.Argument(..., help="Later ReleaseGuard JSON audit.", exists=True, dir_okay=False),
    ],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Report format: markdown or json.")
    ] = "markdown",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional comparison output file.")
    ] = None,
) -> None:
    """Compare two completed ReleaseGuard JSON audits without modifying either project."""

    normalized_format = output_format.lower().strip()
    if normalized_format not in {"markdown", "json"}:
        typer.echo("Error: --format must be either 'markdown' or 'json'.", err=True)
        raise typer.Exit(code=2)

    try:
        comparison = compare_audits(_load_audit_result(before), _load_audit_result(after))
        report = (
            render_reaudit_json(comparison)
            if normalized_format == "json"
            else render_reaudit_markdown(comparison)
        )
    except ValueError as error:
        typer.echo(f"Comparison error: {error}", err=True)
        raise typer.Exit(code=2) from None

    if output is not None:
        try:
            output.write_text(report, encoding="utf-8")
        except OSError as error:
            typer.echo(f"Output error: could not write '{output}': {error}", err=True)
            raise typer.Exit(code=2) from None
        typer.echo(f"Report written to {output}", err=True)
    else:
        typer.echo(report, nl=False)


@app.command()
def version() -> None:
    """Print the installed ReleaseGuard version."""

    typer.echo(f"ReleaseGuard {__version__}")


# ---------------------------------------------------------------------------
# Phase 4 human-in-the-loop commands.  Imports stay lazy so the Phase 1-3 CLI
# keeps its startup and error behavior when no workflow/evidence exists yet.


def _phase4_workflow(project_path: Path, evidence_root: Path | None = None):
    from .phase4.store import EvidenceStore
    from .phase4.workflow import ReleaseWorkflow

    store = EvidenceStore(project_path, evidence_root=evidence_root)
    return ReleaseWorkflow(project_path, store=store)


def _phase4_project(value: str | Path) -> tuple[Path, str | None]:
    """Interpret a legacy-friendly positional value as project or finding id."""

    candidate = Path(value).expanduser()
    if candidate.exists() and candidate.is_dir():
        return candidate, None
    return Path("."), str(value)


def _phase4_print(value: object, output_format: str = "markdown") -> None:
    from .phase4.redaction import redact_for_persistence, redact_text

    normalized = output_format.lower().strip()
    if normalized not in {"markdown", "json"}:
        raise ValueError("--format must be either 'markdown' or 'json'.")
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, (list, tuple)):
        payload = [item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in value]
    else:
        payload = value
    safe = redact_for_persistence(payload)
    if normalized == "json":
        typer.echo(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if isinstance(safe, list):
        if not safe:
            typer.echo("No findings require human review.")
            return
        for item in safe:
            finding = item if isinstance(item, dict) else {"value": item}
            severity = str(finding.get("severity", "")).upper()
            location = str(finding.get("file", ""))
            if finding.get("line"):
                location += f":{finding['line']}"
            typer.echo(f"{finding.get('rule_id', finding.get('finding_id', 'finding'))}")
            typer.echo(f"Severity: {severity}")
            typer.echo(f"Status: {str(finding.get('status', 'OPEN')).upper()}")
            typer.echo(f"File: {location}")
            typer.echo(f"Message: {redact_text(str(finding.get('title', '')))}")
            preview = finding.get("evidence", finding.get("safe_preview", ""))
            if preview:
                typer.echo(f"Preview: {redact_text(str(preview))}")
            typer.echo("")
        return
    if isinstance(safe, dict):
        typer.echo(json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        typer.echo(redact_text(str(safe)))


def _phase4_error(error: Exception) -> NoReturn:
    typer.echo(f"Phase 4 error: {error}", err=True)
    raise typer.Exit(code=2) from None


@app.command("review")
def review(
    target: Annotated[str | None, typer.Argument(help="Finding id, or a project directory.")] = None,
    finding_id: Annotated[str | None, typer.Argument(help="Optional finding id when TARGET is a project.")] = None,
    project: Annotated[Path, typer.Option("--project", "-p", help="Project directory (default: current directory).", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root", help="Optional evidence directory.")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format: markdown or json.")] = "markdown",
) -> None:
    """List findings awaiting human disposition, or show one finding."""

    try:
        selected_project = project
        selected_id = finding_id
        if target is not None:
            possible_project, inferred_id = _phase4_project(target)
            if inferred_id is None:
                selected_project = possible_project
            elif selected_id is None:
                selected_id = inferred_id
        workflow = _phase4_workflow(selected_project, evidence_root)
        try:
            value = workflow.review(selected_id)
        except Exception as error:
            # A first review in a new checkout is useful and deterministic.
            if "No audit is available" not in str(error):
                raise
            workflow.audit()
            value = workflow.review(selected_id)
        _phase4_print(value, output_format)
    except Exception as error:
        _phase4_error(error)


def _phase4_disposition_command(
    action: str,
    finding_id: str,
    *,
    project: Path,
    reason: str,
    evidence_root: Path | None,
) -> None:
    # High-risk dispositions are deliberately unavailable through the CLI.
    # A shell/agent can supply any ``--reason`` or ``--actor`` string, so a
    # non-interactive command cannot establish human authority.  Keep the
    # command names for compatibility and direct the operator to the local
    # Dashboard trust boundary instead.
    del action, finding_id, project, reason, evidence_root
    from .phase4.workflow import HUMAN_AUTHORIZATION_MESSAGE

    typer.echo(HUMAN_AUTHORIZATION_MESSAGE, err=True)
    raise typer.Exit(code=2)


@app.command("approve")
def approve(
    finding_id: Annotated[str, typer.Argument(help="Finding rule id or fingerprint.")],
    reason: Annotated[str, typer.Option("--reason", help="Human approval rationale.")] = "",
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root")] = None,
) -> None:
    """Record explicit human approval; this does not resolve a finding."""

    _phase4_disposition_command("approve", finding_id, project=project, reason=reason, evidence_root=evidence_root)


@app.command("reject")
def reject(
    finding_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option("--reason")] = "",
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root")] = None,
) -> None:
    """Reject a proposed remediation."""

    _phase4_disposition_command("reject", finding_id, project=project, reason=reason, evidence_root=evidence_root)


@app.command("defer")
def defer(
    finding_id: Annotated[str, typer.Argument()],
    reason: Annotated[str, typer.Option("--reason")] = "",
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root")] = None,
) -> None:
    """Defer a finding for a later review."""

    _phase4_disposition_command("defer", finding_id, project=project, reason=reason, evidence_root=evidence_root)


@app.command("false-positive")
def false_positive(
    finding_id: Annotated[str, typer.Argument()],
    reason: Annotated[str | None, typer.Option("--reason", help="Mandatory false-positive rationale.")] = None,
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root")] = None,
) -> None:
    """Record a human false-positive decision; a reason is mandatory."""

    if not reason or not reason.strip():
        _phase4_error(ValueError("false-positive requires --reason"))
    _phase4_disposition_command(
        "false_positive",
        finding_id,
        project=project,
        reason=reason or "",
        evidence_root=evidence_root,
    )


@app.command("remediate")
def remediate(
    finding_id: Annotated[str, typer.Argument()],
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    evidence_root: Annotated[Path | None, typer.Option("--evidence-root")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f")] = "json",
) -> None:
    """Execute only a snapshot-bound, human-approved remediation and re-audit."""

    try:
        outcome = _phase4_workflow(project, evidence_root).remediate(finding_id)
        _phase4_print(
            {
                "resolved": outcome.resolved,
                "changed_files": outcome.changed_files,
                "audit": outcome.result.to_dict(),
                "evidence_directory": str(outcome.evidence_directory),
                "diff": outcome.diff,
            },
            output_format,
        )
    except Exception as error:
        _phase4_error(error)


@app.command("dashboard")
def dashboard(
    project: Annotated[Path, typer.Option("--project", "-p", exists=True, file_okay=False)] = Path("."),
    host: Annotated[str, typer.Option("--host", help="Dashboard host; only 127.0.0.1 is permitted.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Dashboard TCP port.")] = 8765,
) -> None:
    """Start the local human-review dashboard on loopback."""

    try:
        from .phase4.dashboard import run_dashboard
        workflow = _phase4_workflow(project)
        try:
            workflow.latest_run()
        except Exception as error:
            if "No audit is available" not in str(error):
                raise
            workflow.audit()

        run_dashboard(
            project,
            host=host,
            port=port,
            workflow=workflow,
            store=workflow.store,
        )
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as error:
        _phase4_error(error)


def _print_ai_status(status: dict[str, object]) -> None:
    """Render only data returned by the local server or local pipe manager."""

    state = str(status.get("state", "unavailable"))
    typer.echo("AI Analyzer: OpenVINO")
    typer.echo(f"State: {state}")
    model_id = status.get("model_id")
    if isinstance(model_id, str) and model_id:
        typer.echo(f"Model: {model_id}")
    device = status.get("device")
    if isinstance(device, str) and device:
        typer.echo(f"Device: {device}")
    else:
        typer.echo("Device: not loaded")
    typer.echo("Local: Yes")
    if state == "error":
        typer.echo("The local model reported an initialization error. Check local server logs.", err=True)


@ai_app.command("status")
def ai_status() -> None:
    """Show whether the local named-pipe analyzer is available."""

    from .ai.service import LocalServerManager

    _print_ai_status(LocalServerManager().status())


@ai_app.command("start")
def ai_start(
    wait: Annotated[
        bool,
        typer.Option("--wait", help="Wait for model download/load before returning."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Maximum wait for a ready local model in seconds."),
    ] = 15.0,
) -> None:
    """Start the persistent local OpenVINO analyzer if it is not already running."""

    if timeout < 0:
        typer.echo("Error: --timeout must not be negative.", err=True)
        raise typer.Exit(code=2)
    from .ai.service import LocalServerManager

    manager = LocalServerManager()
    status = manager.start()
    if wait and str(status.get("state")) in {"starting", "downloading", "loading"}:
        status = manager.wait_for_ready(timeout_seconds=timeout)
    _print_ai_status(status)


@ai_app.command("stop")
def ai_stop(
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Maximum graceful shutdown wait in seconds."),
    ] = 5.0,
) -> None:
    """Stop the persistent local OpenVINO analyzer."""

    if timeout <= 0:
        typer.echo("Error: --timeout must be greater than zero.", err=True)
        raise typer.Exit(code=2)
    from .ai.service import LocalServerManager

    status = LocalServerManager().stop(timeout_seconds=timeout)
    typer.echo(json.dumps(status, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":  # pragma: no cover - module entry point delegates here.
    app()
