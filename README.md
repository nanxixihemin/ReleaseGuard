# ReleaseGuard

> **ReleaseGuard 本地AI发布安全审计**
>
> 面向 AI Coding Agent 的本地软件发布安全审计与 Release Gate Skill。

ReleaseGuard answers the release question that code-quality tools do not: is a
project ready to ship now? It evaluates deterministic release risks locally,
adds an optional local OpenVINO review, and returns an explainable `PASS`,
`WARNING`, or `BLOCKED` gate before deployment.

AI can generate working code quickly, but working code is not automatically
safe to release. Credentials can remain in source, a production endpoint can
point to a local address, debug settings can be enabled, and release-critical
work can be unfinished. ReleaseGuard makes those risks visible before a human
or an AI Coding Agent treats a repository as releasable.

```text
Deterministic Release Audit
        +
OpenVINO Local AI Review
        +
Agentic Safe Remediation
        +
Human-in-the-loop Release Gate
```

**Privacy:** source code and credentials do not leave the device. The optional
model runs locally; no cloud LLM or remote inference API is used.

## What Is ReleaseGuard?

ReleaseGuard is a local release-readiness Skill for AI Coding Agents and
developers. It produces structured findings, a score, and a deterministic
release gate for a bounded local project directory.

ReleaseGuard Core is a local-first, read-only release auditing engine.
Source-code modifications are performed by the external AI Coding Agent only
within deterministic safety policies and explicit human authorization
boundaries, followed by mandatory re-audit.

ReleaseGuard is not a replacement for a test runner, linter, formatter, SAST
platform, compliance program, deployment system, or an assurance that a `PASS`
means a product is defect-free. A `PASS` means no configured ReleaseGuard
blockers were found in the bounded local audit.

## Why ReleaseGuard?

ReleaseGuard is the release-engineer boundary in an AI-assisted workflow:

```text
Developer or AI Coding Agent
        -> ReleaseGuard
        -> PASS / WARNING / BLOCKED
        -> human release decision
```

It focuses on release-facing signals that are easy to miss during rapid AI
coding:

- credential-like values in source, with evidence redacted
- production endpoints that point to a local address
- enabled debug settings and staging/test residue
- release-relevant `TODO`, `FIXME`, `HACK`, and `XXX` comments
- sensitive files, unwanted artifacts, release configuration, and Git state

## Features

| Capability | What it does | Authority boundary |
| --- | --- | --- |
| Deterministic Release Audit | Runs bounded local rules and calculates the score and gate. | The only authority for deterministic findings, score, and gate. |
| OpenVINO Local AI Review | Adds an opt-in, redacted semantic explanation through a local Windows named-pipe service. | Advisory only; cannot alter findings, score, or gate. |
| Agentic Safe Remediation | Produces deterministic `SAFE`, `REVIEW_REQUIRED`, and `NEVER_AUTO_FIX` guidance. | Agents may edit only explicit `SAFE` work after user authorization. |
| Human-in-the-loop Release Gate | Binds high-risk decisions to a local Dashboard action, audit run, finding, snapshot, scope, and evidence. | A fresh deterministic re-audit alone can resolve a finding. |

## Four-Phase Architecture

```text
Phase 1
Deterministic Release Audit
        |
        v
Phase 2
OpenVINO Local AI Review
        |
        v
Phase 3
Agentic Safe Remediation
        |
        v
Phase 4
Human-in-the-loop Release Gate
```

Phase 1 creates the authoritative findings, score, and gate. Phase 2 receives
only allowlisted, redacted local context and remains advisory. Phase 3 assigns
deterministic safety classes to remediation guidance. Phase 4 adds a local,
snapshot-bound human review and evidence workflow. It does not add a cloud
service, database, account system, CI/CD integration, or a Phase 5 feature.

See [Architecture](docs/architecture.md) and the focused
[Phase 4 design](docs/architecture/phase4-human-in-the-loop.md) for the
implementation details.

## Quick Start

ReleaseGuard Core requires Python 3.10 or later. Create an isolated environment
and install the package:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
releaseguard audit examples/unsafe_project
```

The unsafe fixture uses only a nonfunctional, clearly fake test credential. It
should return `BLOCKED`.

Install test dependencies when running the test suite:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
```

The module entry point is equivalent when the console script is not on `PATH`:

```powershell
python -m releaseguard version
python -m releaseguard audit examples/clean_project
python -m releaseguard audit examples/unsafe_project --format json
```

`examples/clean_project` should return `PASS`; the JSON output is designed for
tooling and is valid JSON.

## Release Gate

ReleaseGuard starts at 100 and subtracts a fixed penalty for each finding.
Scores are clamped to `0-100`.

| Severity | Penalty |
| --- | ---: |
| Critical | -25 |
| High | -12 |
| Medium | -5 |
| Low | -1 |

| Gate | Rule |
| --- | --- |
| `BLOCKED` | At least one Critical finding, or score below 60. |
| `WARNING` | Score from 60 through 84, with no Critical finding. |
| `PASS` | Score of 85 or higher, with no Critical finding. |

The gate is a release-decision input, not a substitute for engineering
judgment. Agents should surface the gate and its findings instead of treating a
warning as approval.

## OpenVINO Local AI

The Core package depends only on `pydantic` and `typer`. Local AI dependencies
are listed separately in `requirements.txt` because `scripts/run.ps1` provisions
and manages a per-user OpenVINO runtime. This keeps the deterministic audit
usable without a model download.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 ai status
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 audit "<project-directory>" --ai --format markdown
```

The first AI request may download
`OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov` into a per-user local cache. The
model weights are not bundled in this repository. When loading or download
time exceeds the caller limit, the command returns code `3`; resume the
pending local operation with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 --continue
```

The local server uses a Windows named pipe for AI requests. The Phase 4 review
Dashboard is a separate standard-library service and accepts only
`127.0.0.1`, never `0.0.0.0`.

## Qoder Skill Usage

Install the project-local Qoder adapter from a ReleaseGuard checkout:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_qoder_skill.ps1 -ProjectPath "<project-directory>"
```

The resulting project Skill lives at
`.qoder/skills/releaseguard/SKILL.md` and uses a generated local adapter. It
does not copy the ReleaseGuard core into the target project or commit an
absolute repository path.

For a machine-readable audit, use the stable entry point:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 audit "<project-directory>" --format json --remediation-plan
```

An Agent must read the deterministic remediation plan, make only an explicitly
authorized `SAFE` edit, then run a new audit and compare the two completed JSON
documents. Credentials, private keys, merge conflicts, and unverified service
destinations are never automatic edits.

## Human Review and Safe Remediation

Phase 4 stores redacted, project-local evidence under `.releaseguard/` while a
human review is in progress. It is runtime state and is intentionally excluded
from repository releases.

```powershell
releaseguard review --project "<project-directory>"
releaseguard dashboard --project "<project-directory>"
```

Critical and other protected remediation decisions require an action in the
loopback Dashboard. The legacy `approve`, `reject`, `defer`, and
`false-positive` CLI names are compatibility stubs: a reason, a natural
language statement, or `actor=human` cannot authorize a change. A valid
Dashboard action is tied to the active audit, finding fingerprint, project
snapshot, approved scope, and redacted evidence. It is consumed after use.

Only an approved, scope-checked remediation can run, and it always triggers a
fresh deterministic audit. An approval does not make a finding resolved and
cannot force a `PASS` gate.

## Demo

The repository includes deterministic examples and two Qoder-oriented demos.
All fixture credential-shaped values are intentionally nonfunctional and marked
as fake or test-only.

| Fixture | Before | Safe edit | Expected result |
| --- | --- | --- | --- |
| `examples/unsafe_project` | Critical secret and release risks | None | `BLOCKED` |
| `examples/warning_project` | Review items | None | `WARNING` |
| `examples/clean_project` | No configured blockers | None | `PASS` |
| `demos/qoder-release-demo` | `38 / BLOCKED` | Turn off explicit debug mode | `50 / BLOCKED`; protected risks remain |
| `demos/safe-auto-fix-demo` | `83 / WARNING` | Turn off explicit debug mode | `95 / PASS` |

For a guided demo, see [Demo Script](docs/demo-script.md). The checked-in demos
are fixtures; Phase 4 walkthroughs must use a fresh temporary copy.

## Privacy and Security

- Source code, raw credentials, and model prompts remain on the device.
- Finding evidence is redacted before reports, AI requests, Dashboard output,
  and persisted Phase 4 evidence.
- The audit never executes project code, package scripts, Dockerfiles, or build
  steps.
- AI cannot override a deterministic finding, score, gate, or final resolution.
- Snapshot, scope, and diff validation fail closed before a protected
  remediation can write files.
- `.releaseguardignore` controls what ReleaseGuard ignores when auditing this
  repository. It does not control the ModelScope upload file list.

## Tests and Verification

The published release baseline is `149 passed, 1 skipped`; the skipped test is
the existing Windows symlink-capability check. Re-run the suite before release:

```powershell
python -m pytest -q
python -m compileall releaseguard
releaseguard version
releaseguard audit examples/unsafe_project
releaseguard audit examples/clean_project
```

Runtime records and their limits are kept in:

- [Phase 3 verification](docs/verification/phase3-runtime-verification-2026-08-17.md)
- [Phase 4 verification](docs/verification/phase4-runtime-verification-2026-08-17.md)
- [Qoder trigger matrix](tests/qoder_trigger_cases.md)

Those records intentionally preserve historical results: the original Phase 4
Qoder human-review boundary probe failed, the execution-layer enforcement fix
passed automated and isolated runtime checks, and the post-fix Qoder replay is
still `NOT VERIFIED` because it would require desktop interaction.

## Release Package

The ModelScope submission should contain the source, scripts, tests, examples,
demos, documentation, `SKILL.md`, `info.json`, `meta.json`, dependency metadata,
license, and ignore files. It must exclude virtual environments, caches,
`.releaseguard/` runtime evidence, local model caches, temporary logs,
`.merkle-snapshot.json`, and `.codeartsdoer/` development configuration.

## License

Copyright 2026 ReleaseGuard Contributors.

Released under the [Apache License 2.0](LICENSE).
