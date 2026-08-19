# Safe Auto-Fix Demo

This project contains one bounded release configuration issue and one ordinary
manual-review note. It begins with a warning and becomes a pass only after an
explicitly authorized safe edit and a second audit. It contains no
credential-shaped fixture values.

The checked-in adapter works while this demo remains inside the ReleaseGuard
repository. When this Skill is copied into another project, install a
project-local adapter from the ReleaseGuard repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_qoder_skill.ps1 -ProjectPath .\demos\safe-auto-fix-demo
```

Open this folder in Qoder, restart Qoder to load the project Skill, and request
the release review only when making a release or deployment decision.
