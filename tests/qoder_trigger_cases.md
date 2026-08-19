# Qoder ReleaseGuard Trigger Cases

This matrix records the intended project-level Skill selection coverage. Qoder's
official Skills documentation says that a model may select a Skill from the
user's natural-language request and that `/releaseguard` is an explicit manual
invocation. Automated tests can verify the file layout and instructions, but
they are not evidence that Qoder selected the Skill in a real session.

Rows without live evidence remain `UNVERIFIED`. A `VERIFIED` row requires a
Qoder IDE log, transcript, screenshot, or equivalent live-session evidence
after a Qoder restart with the demo project open.

The 16:42-16:49 batch used Qoder's `Ask` mode to prevent source edits while
testing routing. For positive rows, the Qoder agent log records a read of the
project-local `run-releaseguard.ps1` adapter. For negative rows, it records
only ordinary project-file reads and no adapter read. The retained transcript
and five source-file hashes were stored in a sanitized temporary artifact
outside this public repository; credential-shaped text was redacted from that
copy and its `source_unchanged` value is `true`. Ask-mode routing evidence does
not replace the separate Agent-mode execution evidence recorded for P10 and
P11.

| ID | User request | Expected result | Status | Evidence |
| --- | --- | --- | --- | --- |
| P01 | `检查这个项目现在能不能上线` | Natural-language selection expected | VERIFIED | Local Qoder agent log, retained outside the public package (16:32 session) |
| P02 | `发布前帮我审计这个服务的风险` | Natural-language selection expected | VERIFIED | Local Qoder agent log, retained outside the public package (16:43 session) |
| P03 | `这个项目是否可以部署到生产环境？` | Natural-language selection expected | VERIFIED | Batch transcript plus agent log (16:45:55 adapter read) |
| P04 | `给我一个 release gate` | Natural-language selection expected | VERIFIED | Batch transcript plus agent log (16:46:30 adapter read) |
| P05 | `请检查 deployment readiness` | Natural-language selection expected | VERIFIED | Batch transcript plus agent log (16:47:08 adapter read) |
| P06 | `ship this project 前有哪些阻塞项？` | Natural-language selection expected | VERIFIED | Batch transcript plus agent log (16:47:29 adapter read) |
| P07 | `做一次 production readiness review` | Natural-language selection expected | VERIFIED | Batch transcript plus agent log (16:47:46 adapter read) |
| P08 | `上线前检查配置和发布风险` | Natural-language selection expected | UNVERIFIED | - |
| P09 | `帮我决定这次发布是否应该阻止` | Natural-language selection expected | UNVERIFIED | - |
| P10 | `/releaseguard` | Explicit manual invocation expected | VERIFIED | Local Qoder extension-host log, retained outside the public package (16:24 audit) |
| P11 | `修复可以安全自动修复的问题，然后重新运行 ReleaseGuard 并比较 before/after` | SAFE-only remediation and re-audit expected | VERIFIED | Local Qoder session-state record and agent log, retained outside the public package (16:25-16:28 edit, re-audit, compare) |
| N01 | `调整登录按钮的文案` | Skill should not be selected | VERIFIED | Local Qoder agent log, retained outside the public package (16:42 ordinary-project response, no adapter read) |
| N02 | `修复这个列表的 CSS 间距` | Skill should not be selected | VERIFIED | Batch transcript plus agent log (16:48:36 ordinary file reads, no adapter read) |
| N03 | `给 README 增加安装说明` | Skill should not be selected | VERIFIED | Batch transcript plus agent log (16:48:47 ordinary file reads, no adapter read) |
| N04 | `重命名这个变量` | Skill should not be selected | VERIFIED | Batch transcript plus agent log (16:49:05 ordinary file read, no adapter read) |
| N05 | `为这个函数补充单元测试` | Skill should not be selected | VERIFIED | Batch transcript plus agent log (16:49:21 ordinary file reads, no adapter read) |
| N06 | `解释这一段登录逻辑` | Skill should not be selected | UNVERIFIED | - |
| N07 | `格式化这几个 TypeScript 文件` | Skill should not be selected | UNVERIFIED | - |
| N08 | `修复表单提交时的空状态` | Skill should not be selected | UNVERIFIED | - |
| N09 | `把导航栏改成响应式布局` | Skill should not be selected | UNVERIFIED | - |
| N10 | `为 API 客户端加一个缓存` | Skill should not be selected | UNVERIFIED | - |
