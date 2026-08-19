---
name: releaseguard
description: >-
  面向 AI Coding Agent 的本地发布安全审计与 Release Gate。适用于“检查能不能上线”、发布前审计、发布风险、部署风险、secret/config/debug check、release readiness、production readiness、deployment risk、release audit、release gate、can this ship? 等明确的上线与交付决策。优先用于本地项目的发布、部署或交付判断，而非一般功能开发、格式化、普通代码风格检查或非发布目标的问答。所有源码和本地 AI 推理均留在设备上；AI 不能覆盖确定性 Gate。
---

# ReleaseGuard 本地发布审计

ReleaseGuard 按以下固定边界工作：

```text
Phase 1  Deterministic Release Audit
    -> Phase 2  OpenVINO Local AI Review
    -> Phase 3  Agentic Safe Remediation
    -> Phase 4  Human-in-the-loop Release Gate
```

审计核心始终本地优先且只读：不会执行被审计项目、上传源码或调用云端 LLM。代码修改是独立的处置步骤，只能由外部 AI Coding Agent 在确定性安全策略和明确人工授权边界内执行，并且必须重新审计。AI 语义说明始终是建议，不能改变 Finding、分数或 Gate。

## 使用

**只能调用 `scripts\run.ps1`。** 不要直接调用 `client.py`、`server.py` 或内部 Python 模块。

| 目标 | 调用 |
| --- | --- |
| 确定性发布审计 | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 audit "<项目目录>" --format json` |
| 本地 AI 增强审计 | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 audit "<项目目录>" --ai --format markdown` |
| 查看本地模型服务 | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 ai status` |
| 预热本地模型 | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 ai start --wait --timeout 600` |
| 停止本地模型服务 | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 ai stop` |

首次 `--ai` 调用会安装本地运行环境并下载 OpenVINO 模型。下载时间超过宿主限制时，命令会输出确定性审计结果、提示 `模型正在下载或加载`，并以退出码 `3` 结束；之后使用：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 --continue
```

继续上一个本地待处理请求。不要把 `--continue` 用于新的项目路径。

## 结果解释

- `PASS`：没有 Critical 发现且分数至少为 85。
- `WARNING`：无 Critical，但仍需在发布前人工复核。
- `BLOCKED`：存在 Critical 或分数低于 60，应修复后重新审计。
- `Local AI Review`：仅在 `--ai` 时出现。`Model` 与 `Device` 只来自实际本地 server 状态；若服务、模型或响应不可用，确定性结果仍有效。

AI 建议可能指出上下文风险、误报可能性和修复方案，但不能修改 Finding 的确定性证据、严重级别、分数或 Gate。Secret、Git 冲突、生产 localhost 等硬事实仍由规则引擎决定。

## 重要边界

- 仅支持 Windows 本地命名管道服务；不会绑定网络端口或暴露公网接口。
- `CPU` 和 Intel `GPU` 是默认兼容路径；可用的 `NPU` 会被实际检测后使用，不能检测到时不会伪称可用。
- 首次模型下载来自公开模型仓库，仅保存模型文件到本机；仓库源码、完整文件、二进制和原始 secret 不会发送给模型或外部 API。
- 返回码：`0` 成功，`1` 一般参数/运行错误，`2` 本地通信错误，`3` 模型下载或加载尚未完成，需 `--continue`。
- 只在用户明确授权修复时修改被审计项目；修复后重新运行本 Skill。
- `SAFE` 项目可在明确授权后由 Agent 进行最小处置；`REVIEW_REQUIRED` 与 `NEVER_AUTO_FIX` 不得由 Agent 擅自修改。
- Critical/High 人审必须在本地 Dashboard 中完成。自然语言、`actor=human`、理由文本及 `approve`、`reject`、`defer`、`false-positive` CLI 兼容命令均不能构成授权；Dashboard 审批会绑定当前 audit、finding 和 snapshot，并在使用后消费。
