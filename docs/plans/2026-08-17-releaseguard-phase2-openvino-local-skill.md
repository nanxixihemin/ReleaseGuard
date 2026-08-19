# ReleaseGuard Phase 2 OpenVINO Local Skill Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a real, local OpenVINO semantic-risk enrichment layer behind a standards-compliant Local AI Skill package while preserving every Phase 1 deterministic audit decision.

**Architecture:** The existing scanner completes its bounded, read-only deterministic audit first and fixes the score and gate. An opt-in adapter builds a redacted, size-limited structured request from the resulting findings and sends it over a local Windows named pipe to a long-lived server. The server downloads a verified OpenVINO IR model into a `.partial` directory, atomically promotes it only after validation, loads it once with OpenVINO GenAI, and returns strictly structured AI advice. Any AI or IPC failure is represented as advisory metadata and returns the original deterministic audit result unchanged.

**Tech Stack:** Python 3.11, Pydantic v2, Typer, `multiprocessing.connection` Windows named pipes, `openvino`, `openvino-genai`, `huggingface-hub`, PowerShell, pytest.

---

## Non-negotiable invariants

- Do not alter Phase 1 rule identities, evidence, scoring, gate policy, reporters, or non-AI CLI output.
- Do not send raw repository content, absolute paths, binaries, complete files, unredacted secrets, or arbitrary finding metadata to the model.
- Do not import OpenVINO from the deterministic scanner import path.
- AI may only add a separately namespaced advisory assessment keyed by a deterministic finding fingerprint. It may not change `Finding.severity`, evidence, score, or gate.
- The service listens only on a Windows named pipe; it exposes no network endpoint and calls no cloud LLM API.

### Task 1: Establish the additive AI data contract

**Files:**
- Modify: `releaseguard/models.py`
- Create: `releaseguard/ai/schemas.py`
- Modify: `releaseguard/ai/__init__.py`
- Test: `tests/test_ai_schemas.py`

**Step 1: Write failing contract tests**

Cover valid `AIAnalysis` parsing, rejection of unknown fields, invalid confidence/risk values, duplicate or unknown finding fingerprints, and `AuditResult` JSON compatibility when no AI review is present.

**Step 2: Add strict Pydantic models**

Define an allowlisted request (`AIAnalysisRequest`, `AIRequestFinding`), structured model response (`FindingAssessment`, `AIAnalysis`), and service result (`AIReview`). Keep assessment content length-bounded, associate it only by SHA-256 fingerprint, and define explicit non-success statuses such as unavailable, timeout, model error, and invalid response.

**Step 3: Extend `AuditResult` additively**

Add `ai_review: AIReview | None`; remove only this absent optional key in `AuditResult.to_dict()` so existing non-AI JSON keys and null values remain byte-compatible. Re-export the schema classes without creating an import cycle.

**Step 4: Verify**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ai_schemas.py tests/test_models.py -q
```

Expected: all tests pass and Phase 1 serialization assertions remain unchanged.

### Task 2: Build privacy-preserving request construction and output parsing

**Files:**
- Create: `releaseguard/ai/redaction.py`
- Create: `releaseguard/ai/request_builder.py`
- Create: `releaseguard/ai/response_parser.py`
- Test: `tests/test_ai_redaction.py`
- Test: `tests/test_ai_request_builder.py`
- Test: `tests/test_ai_response_parser.py`

**Step 1: Write failing redaction tests**

Assert that URLs with userinfo, sensitive/encoded query values, bearer tokens, JWT-like strings, database URLs, TODO detail, secret-like filenames, and absolute root paths cannot appear in serialized model input. Assert excerpts are line-local and capped.

**Step 2: Implement a narrow allowlist**

Only serialize deterministic rule id, category, severity, title, normalized relative location, line, sanitized evidence/explanation, fixed contextual labels, and a redacted three-line excerpt capped at a documented limit. Never serialize `ProjectContext`, raw `Finding.metadata`, or an entire file.

**Step 3: Implement strict response handling**

Extract at most one bounded JSON object from model text, parse it, Pydantic-validate it, reject references not present in the request, sanitize text again, and convert every error to an `AIReview` non-success result instead of raising.

**Step 4: Verify**

Run the focused privacy and parsing tests. Confirm that `json.dumps(request)` contains neither raw test secrets nor an absolute project directory.

### Task 3: Wire the hybrid scanner boundary

**Files:**
- Modify: `releaseguard/scanner.py`
- Create: `releaseguard/ai/service.py`
- Test: `tests/test_hybrid_audit.py`

**Step 1: Write failing hybrid tests**

Use a fake local client to return a valid assessment and a series of unavailable/timeout/invalid responses. Assert that score, gate, finding severity, evidence, and fingerprint are identical before and after enrichment. Assert a Critical production-loopback result remains `BLOCKED` even when AI reports a likely false positive.

**Step 2: Add the opt-in scanner hook**

Extend `audit_project()` only with keyword-only `ai_client` and `ai_timeout_seconds`. Build the request after deterministic deduplication and `score_and_gate`; attach a review only when an AI client is explicitly passed. Catch all adapter failures at this boundary and return a non-success `AIReview` without changing Phase 1 output.

**Step 3: Verify**

Run the focused hybrid tests and the complete Phase 1 suite. Compare unsafe/warning/clean example score and gates to the existing baseline.

### Task 4: Implement the named-pipe protocol and persistent server

**Files:**
- Create: `releaseguard/ai/pipe_protocol.py`
- Create: `releaseguard/ai/pipe_client.py`
- Create: `scripts/server.py`
- Test: `tests/test_pipe_client.py`
- Test: `tests/test_server_protocol.py`

**Step 1: Write protocol tests**

Mock transport connections for unavailable pipe, malformed JSON, response timeout, status, request, and shutdown. Add a process-level Windows test which starts a lightweight server mode, verifies `starting`/`running` status transitions, makes one request, and stops it.

**Step 2: Use authenticated, bounded JSON over named pipes**

Use `multiprocessing.connection.Listener` / `Client` with `AF_PIPE`, a stable skill-specific address and auth key. Send only UTF-8 JSON bytes with a maximum request/response size; one request is one connection. The server must expose `status`, `request`, and `shutdown` and retain full initialization errors only in its local log.

**Step 3: Self-spawn and wait safely**

The client detects an absent server, starts `scripts/server.py` using its current Python executable, polls status through the states `starting`, `downloading`, `loading`, `running`, and returns deterministic fallback metadata on any start/communication/timeout failure.

**Step 4: Verify**

Run the protocol tests on Windows. Confirm a server process remains alive across two status/request connections and exits after `shutdown`.

### Task 5: Add a real lazy OpenVINO GenAI engine

**Files:**
- Create: `releaseguard/ai/openvino_engine.py`
- Create: `releaseguard/ai/model_config.py`
- Modify: `requirements.txt`
- Modify: `info.json`
- Test: `tests/test_openvino_engine.py`

**Step 1: Write dependency-free tests**

Mock OpenVINO/Hugging Face imports to assert GPU-first/CPU fallback, requested unsupported NPU fallback, missing runtime/model handling, complete-model validation, `.partial` promotion rules, and load failure conversion to an advisory error.

**Step 2: Implement model integrity and device choice**

Choose `OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov` with a documented Phi-3.5 fallback. Download only the allowlisted required IR/tokenizer files to `<model>.partial`, validate each required file, then atomically rename to its final directory. Read actual available devices from `openvino.Core`; prefer Intel GPU, fall back to CPU, and never claim an unavailable device.

**Step 3: Load once and generate structured advice**

Import `openvino_genai` only in the server initialization thread. Construct one `LLMPipeline`, keep it resident, use a deterministic prompt that treats audit data as untrusted JSON, and require one JSON object with no markdown. Return raw output only internally to the parser; do not write input/output contents to logs.

**Step 4: Verify real runtime**

Install the declared runtime in the Local Skill environment, download the selected model, and execute an actual pipeline load plus one structured generation. Record the exact package versions, model id, and selected device.

### Task 6: Add Skill packaging, user entrypoints, and CLI commands

**Files:**
- Create: `scripts/run.ps1`
- Create: `scripts/install-env.ps1`
- Create: `scripts/client.py`
- Create: `meta.json`
- Modify: `SKILL.md`
- Modify: `pyproject.toml`
- Modify: `releaseguard/cli.py`
- Test: `tests/test_cli_ai.py`
- Test: `tests/test.ps1`

**Step 1: Add the standard package metadata**

Follow the official directory contract. `info.json` declares Python 3.11, honest model memory needs, timeout, model ID, directory name, and every required model file. `meta.json` and `SKILL.md` use focused bilingual release-audit routing triggers and identify `scripts\\run.ps1` as the sole public Skill interface.

**Step 2: Implement PowerShell bootstrap**

Make `$ErrorActionPreference = 'Stop'` the first executable statement. Resolve all paths from the script location, provision an isolated local venv idempotently, use UTF-8, and forward arguments only to `scripts/client.py`. Support `--continue`, persist only sanitized pending invocation metadata, and use exit code `3` only while a real first-run download is still in progress.

**Step 3: Extend the normal CLI additively**

Keep `releaseguard audit <path>` unchanged. Add `releaseguard audit <path> --ai`, plus `releaseguard ai status`, `start`, and `stop`, backed by the same local pipe manager. The commands print only verified analyzer/model/device values from server status.

**Step 4: Verify**

Run Typer tests, `scripts\\run.ps1` help/status/start/stop on Windows, and the standard PowerShell E2E script. Confirm `run.ps1` is the only documented invocation surface in `SKILL.md`.

### Task 7: Add the AI-value demo and documentation

**Files:**
- Create: `examples/ambiguous_environment_project/README.md`
- Create: `examples/ambiguous_environment_project/.env.example`
- Create: `examples/ambiguous_environment_project/vite.config.ts`
- Create: `examples/ambiguous_environment_project/src/runtime.ts`
- Create: `examples/ambiguous_environment_project/deploy/production.env`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Test: `tests/test_ambiguous_demo.py`

**Step 1: Add a bounded ambiguity fixture**

Include documentation/example and Vite dev-proxy localhost cases alongside a deployable source fallback and an explicit production config. Test deterministic severities first; AI suggestions must remain advisory and must not clear the production critical blocker.

**Step 2: Document the execution chain and ADR**

Add the exact chain `Qoder/Agent -> SKILL -> run.ps1 -> client.py -> ReleaseGuard Core -> redacted request -> local OpenVINO server -> AI review -> deterministic gate`. Document the named-pipe, standalone self-spawn choice, local-only privacy boundary, model/device fallback behavior, and no-cloud rule.

**Step 3: Verify actual demos**

Run unsafe project with `--ai` after real model readiness. Capture score, gate, deterministic count, AI reviewed count, model, device, and model-generated assessment. Run the ambiguous fixture and record whether model advice distinguishes examples from deployable configuration; do not assert a semantic claim as passing if model output is invalid or ambiguous.

### Task 8: Final regression and handoff

**Files:**
- Modify only if verification exposes a scoped defect.

**Step 1: Run all Python tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

**Step 2: Run real Skill checks**

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 ai status
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 audit .\examples\unsafe_project --ai
powershell -ExecutionPolicy Bypass -File .\tests\test.ps1
```

**Step 3: Report facts, not assumptions**

Report Phase 1 and Phase 2 test counts, OpenVINO version, exact downloaded model, actual selected device, pipeline load result, generation result, client/server outcome, unsafe audit outcome, and ambiguous demo outcome. Stop after Phase 2; do not begin Phase 3 work.
