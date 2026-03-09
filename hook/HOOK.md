---
name: openclaw-sec
description: "Security scanning for outbound messages, prompt injection detection, and structured audit logging for OpenClaw agents"
homepage: https://github.com/openclaw/openclaw-sec
metadata:
  {
    "openclaw":
      {
        "events": ["message:sent", "message:preprocessed", "command"],
      },
  }
---

# OpenClaw Security Hook

OpenClaw 安全扫描 Hook。对 Agent 的出站消息进行密钥 / PII / 凭证检测，对入站消息进行 Prompt Injection 检测，并记录结构化安全审计日志。

## 功能

- 出站消息扫描：检测 API Keys、Token、密码、PII，支持自动脱敏或拦截
- 入站消息扫描：Prompt Injection 检测 + 敏感信息扫描
- 编码绕过防御：自动解码 Base64 / URL / Hex 后二次扫描
- 调用链追踪：跟踪跨工具调用序列，检测数据外泄模式
- 结构化审计日志：记录所有安全事件

## 配置

在工作目录或 `~/.openclaw/` 下放置 `security.config.yaml`：

```yaml
scanner:
  enableEncodingDefense: true
  enablePromptInjection: true

actions:
  onSecretDetected: redact
  onPromptInjection: warn
  onChainThreat: warn

audit:
  adapter: local
  path: ./logs/openclaw-sec-audit.jsonl
```

## 环境要求

- Node.js 18+
