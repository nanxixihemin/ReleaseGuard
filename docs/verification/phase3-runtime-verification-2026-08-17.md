# Phase 3 Runtime Verification - 2026-08-17

## Automated Regression

- Full suite: `118 passed, 1 skipped`.
- The skipped test is the Windows symlink-permission case.
- Phase 3 focused suite (`test_remediation`, `test_reaudit_cli`,
  `test_qoder_demo`, and `test_hybrid_audit`): `25 passed`.

## Verified Local OpenVINO Audit

The local named-pipe server was started through `scripts/run.ps1` and reported:

- State: `running`
- Model: `OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov`
- Device: `GPU`
- Local: `Yes`

An actual command equivalent to the following completed against the blocked demo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 audit .\demos\qoder-release-demo --ai --remediation-plan --format json
```

The response reported `ai_review.status=completed`, three advisory assessments,
and retained the deterministic result `38 / BLOCKED`. Its remediation plan
classified the credential-shaped sentinel as `NEVER_AUTO_FIX`, the production
loopback finding as `REVIEW_REQUIRED`, and the explicit debug setting as `SAFE`.
No credential value is retained in this record.

Server metadata log:

```text
%LOCALAPPDATA%\ReleaseGuard\log\releaseguard-server-20260817-080107.log
```

At the end of Phase 3 verification, `scripts/run.ps1 ai stop` returned
`{"ok": true, "state": "shutting_down"}`. A follow-up `ai status` reported
`State: stopped`, `Device: not loaded`, and `Local: Yes`.

## Verified Deterministic Re-Audit

The source demos were copied to fresh temporary directories. In each copy, the
only edit was the explicit `DEBUG = true` to `DEBUG = false` `SAFE` change; the
before and after JSON documents were produced by `scripts/run.ps1`, then passed
to its `compare` command.

| Demo | Before | After | Resolved | Remaining |
| --- | --- | --- | --- | --- |
| `qoder-release-demo` | `38 / BLOCKED` | `50 / BLOCKED` | `RG-DEBUG-001` | `RG-SECRET-001`, `RG-ENV-001` |
| `safe-auto-fix-demo` | `83 / WARNING` | `95 / PASS` | `RG-DEBUG-001` | `RG-TODO-001` |

Temporary artifacts:

```text
%TEMP%\releaseguard-phase3-reaudit-4c94d568eab24d3385b437d660031427\before.json
%TEMP%\releaseguard-phase3-reaudit-4c94d568eab24d3385b437d660031427\after.json
%TEMP%\releaseguard-phase3-reaudit-4c94d568eab24d3385b437d660031427\comparison.md
%TEMP%\releaseguard-phase3-safe-reaudit-4833f8e963b64e3688c4063b79e71bca\before.json
%TEMP%\releaseguard-phase3-safe-reaudit-4833f8e963b64e3688c4063b79e71bca\after.json
%TEMP%\releaseguard-phase3-safe-reaudit-4833f8e963b64e3688c4063b79e71bca\comparison.md
```

These command-level re-audits verify the ReleaseGuard workflow. The Qoder
session below independently performed the same bounded edit in an isolated
copy; the checked-in demos were not modified.

## Verified Qoder Invocation

The project-level Skill was installed in the isolated workspace
`%TEMP%\releaseguard-qoder-verification-ff23d3072be449d4b2b3c6f924e3404e\qoder-release-demo`.
After Qoder was restarted, the local session history and logs show:

1. `/releaseguard` selected the project Skill and invoked the adapter for a
   JSON audit (`38 / BLOCKED`).
2. The explicit request to fix only `SAFE` items changed exactly
   `src/config.ts`, `DEBUG = true` to `DEBUG = false`.
3. Qoder invoked a second adapter audit and the `compare` command. The
   deterministic comparison is `38 / BLOCKED` -> `50 / BLOCKED`, with
   `RG-DEBUG-001` resolved and the secret and production endpoint remaining.
4. A natural-language request, `检查这个项目现在能不能上线`, created a separate
   completed Agent session and invoked the adapter audit without a slash command.
5. In the same Qoder workspace, Qoder ran `ai status` and an `audit --ai`
   command. The saved response reports `ai_review.status=completed`, model
   `OpenVINO/Qwen2.5-Coder-0.5B-Instruct-int4-ov`, and device `GPU`.

These observations establish the Skill load, manual trigger, natural-language
selection, adapter invocation, OpenVINO inference during a Qoder session,
source remediation, and Qoder-triggered re-audit. They do not claim that a
secret was automatically removed: the deterministic gate remained `BLOCKED`.

## Verified Qoder Trigger Coverage

Qoder's `Ask` mode was used for an additional routing-only batch so that source
changes could not be applied. A sanitized copy of the batch transcript is
`%TEMP%\releaseguard-qoder-trigger-evidence-20260817.json`. Credential-shaped
text was redacted before retention; the copy records unchanged SHA-256 hashes
for `src/config.ts`, `src/auth.ts`, `src/app.ts`, `README.md`, and
`package.json` before and after the nine-session batch.

The Qoder agent log shows that positive natural-language requests P03-P07 read
the project-local `run-releaseguard.ps1` adapter at 16:45:55, 16:46:30,
16:47:08, 16:47:29, and 16:47:46. Negative development requests N02-N05 made
ordinary file reads only, with no adapter read. Together with the previously
recorded P01, P02, P10, P11, and N01 sessions, the trigger matrix now has 14
verified rows. The Ask-mode batch validates routing only; the Agent-mode
execution, source edit, re-audit, and OpenVINO claims remain grounded in the
separate evidence above.

Evidence retention:

The original verification used local Qoder logs, a local session-state record,
and sanitized temporary routing artifacts. Those device-local paths and session
identifiers are intentionally not part of this public repository. The facts
above remain the historical verification record; the checked-in static Skill,
deterministic remediation workflow, and trigger matrix remain covered by
tests.

The historic shared `%TEMP%\releaseguard-qoder` artifact root is not retained
as reproducible evidence because later Qoder sessions may overwrite it. Future
Skill runs create a unique GUID-named report directory. The static project
Skill and deterministic remediation workflow remain covered by tests; the
remaining unverified trigger rows are P08-P09 and N06-N10.
