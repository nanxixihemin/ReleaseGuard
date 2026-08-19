# ReleaseGuard MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a local-only, read-only CLI that audits a repository, returns structured release findings, and produces a deterministic release gate.

**Architecture:** A single Python package builds a bounded `ProjectContext` once, runs registered deterministic `AuditRule` implementations, aggregates `Finding` objects into `AuditResult`, then calculates score/gate and renders JSON or Markdown. A narrow AI protocol is reserved for a later localhost OpenVINO analyzer; it is not invoked in Phase 1.

**Tech Stack:** Python 3.10+, Typer, Pydantic, pytest, standard library.

---

### Task 1: Bootstrap package contract

**Files:**
- Create: `pyproject.toml`
- Create: `releaseguard/models.py`
- Create: `releaseguard/context.py`
- Create: `releaseguard/scoring.py`
- Create: `releaseguard/rules/base.py`
- Create: `releaseguard/ai/base.py`

**Step 1: Write failing model, score, and context tests.**

**Step 2: Implement immutable-compatible Pydantic models, bounded text iteration, project detection, ignore matching, and score/gate policy.**

**Step 3: Run targeted pytest tests.**

### Task 2: Implement deterministic rules and scanner orchestration

**Files:**
- Create: `releaseguard/rules/secrets.py`
- Create: `releaseguard/rules/environment.py`
- Create: `releaseguard/rules/debug.py`
- Create: `releaseguard/rules/todos.py`
- Create: `releaseguard/rules/git.py`
- Create: `releaseguard/rules/sensitive_files.py`
- Create: `releaseguard/rules/release_config.py`
- Create: `releaseguard/scanner.py`

**Step 1: Write failing tests for secret masking, environment severity, TODO heuristics, sensitive files, Git degradation, and scanner aggregation.**

**Step 2: Implement each read-only rule against `ProjectContext`, using safe evidence masking and stable fingerprints.**

**Step 3: Run the rule test subset and then the complete suite.**

### Task 3: Add reports and CLI

**Files:**
- Create: `releaseguard/reporters.py`
- Create: `releaseguard/cli.py`
- Create: `releaseguard/__main__.py`

**Step 1: Write failing JSON/Markdown and CLI invocation tests.**

**Step 2: Implement stable JSON serialisation, readable Markdown, atomic-like output behavior, and friendly CLI validation errors.**

**Step 3: Verify `python -m releaseguard audit` and installed `releaseguard` entry point.**

### Task 4: Add product assets and extension documentation

**Files:**
- Create: `README.md`
- Create: `SKILL.md`
- Create: `docs/architecture.md`
- Create: `examples/unsafe_project/*`
- Create: `examples/warning_project/*`
- Create: `examples/clean_project/*`

**Step 1: Document local-first and read-only guarantees, score formula, architecture/ADRs, and the future OpenVINO localhost boundary.**

**Step 2: Create only fake, deliberately unsafe example credentials.**

**Step 3: Run each example audit and adjust fixtures/rules until expected gates are reproducible.**

### Task 5: Verification and handoff

**Files:**
- Create: `tests/*`

**Step 1: Run `pytest` and resolve every failure.**

**Step 2: Run Markdown and JSON audit commands against unsafe, warning, and clean examples.**

**Step 3: Verify JSON with `json.loads`, inspect CLI errors, and report exact results and Phase 2 scope.**
