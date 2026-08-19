# Qoder Release Demo

This small project is a deliberately blocked release-readiness demonstration.
Its source contains a nonfunctional credential-shaped sentinel, a production
configuration fallback, an enabled diagnostic setting, and a visible security
work item. The values are test data only and must never be reused.

The checked-in adapter works while this demo remains inside the ReleaseGuard
repository. When this Skill is copied into another project, install a
project-local adapter from the ReleaseGuard repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_qoder_skill.ps1 -ProjectPath .\demos\qoder-release-demo
```

Then open this folder as the Qoder project and restart Qoder before using the
project Skill. An authorized bounded remediation can address only the safe
configuration item. The audit must remain blocked until the sentinel finding
and other manual-review findings have been handled by an operator.
