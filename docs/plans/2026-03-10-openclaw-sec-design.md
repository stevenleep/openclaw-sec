# OpenClaw Security Plugin -- 架构设计文档

版本：v0.3  
日期：2026-03-10

## 1. 定位

OpenClaw 已提供沙箱隔离、工具策略（deny/allow）、Exec 审批和基本命令日志。`@openclaw/sec` 作为补充安全层，覆盖 OpenClaw 内置安全体系的盲区：

| 安全盲区 | OpenClaw 现状 | 本插件的应对 |
|---------|--------------|-------------|
| 出站内容安全 | 无检测 | 扫描 Agent 回复中的密钥 / PII / 凭证，自动脱敏或拦截 |
| 入站 Prompt Injection | 无防护 | 基于规则的注入检测，支持拦截或告警 |
| 编码绕过 | 无防护 | 解码 Base64 / URL / Hex / Unicode 后二次扫描 |
| 跨工具数据外泄 | 仅单工具审批 | 调用链分析 + 参数感知 + 数据流追踪 |
| 敏感路径访问 | 依赖沙箱策略 | 30+ 路径规则，4 级风险分类，支持拦截 |
| 危险命令执行 | 依赖 Exec 审批 | 20+ 命令规则，自动评估风险等级 |
| 异常频率操作 | 无 | 速率限制 + 熔断器 |
| 统一安全审计 | 基础命令日志 | 结构化审计（含扫描结果、链分析、LLM 判定） |
| 第三方安全能力 | 无扩展机制 | Provider SPI 框架 |

## 2. 架构

```
  OpenClaw Gateway
       |
       +-- Hook: message:preprocessed
       |     Prompt Injection 检测
       |     入站内容扫描（PII/Secret）
       |     第三方 ContentScannerProvider
       |
       +-- Hook: message:sent
       |     速率限制 / 熔断检查
       |     出站内容扫描 + 高熵检测
       |     第三方 ContentScannerProvider
       |     DecisionEvaluator 决策
       |     执行 redact / block / warn
       |
       +-- Hook: tool_result_persist
       |     敏感路径保护（block/warn）
       |     命令风险评估（block/warn）
       |     调用链事件跟踪（含参数）
       |     工具结果内容脱敏
       |
       +-- Hook: command / message
       |     全量审计记录
       |     调用链分析 -> 威胁检测
       |     LLM Judge（仅 high/critical）
       |     chain threat block/warn
       |
       +-- 审计日志
             本地 JSONL 存储
             第三方 AuditReporterProvider
```

## 3. 集成模式

### 模式一：OpenClaw Plugin

通过 `openclaw.plugin.json` manifest 注册，Gateway 启动时自动加载。注册所有 Hook handler 和 shutdown 回调。支持运行时通过 `providers` / `pipeline` 属性注册第三方 Provider。

### 模式二：OpenClaw Hook

将 `hook/` 目录部署至 `~/.openclaw/hooks/openclaw-sec/`。仅提供出站扫描、入站扫描和审计记录，不包含第三方 Provider 支持。

### 模式三：独立函数库

直接 import 核心模块。适用于 NanoClaw（无插件系统）或任何自定义 Agent 框架。使用方自行决定在何处调用扫描和分析函数。

## 4. Hook 映射

| OpenClaw 事件 | Handler | 执行的安全检查 |
|--------------|---------|--------------|
| message:preprocessed | inboundScan | Prompt Injection 检测, PII/Secret 扫描, 入站 redact/block, Provider 扫描 |
| message:sent | outboundInspector | 速率限制, 熔断, 内容扫描, 高熵检测, Provider 扫描, Decision 决策, redact/block/warn |
| tool_result_persist | toolResultRedactor | 敏感路径检查, 命令风险评估, 调用链跟踪, 内容脱敏, Provider 扫描 |
| command | auditRecorder | 审计记录 |
| message | auditRecorder | 审计记录, 调用链分析, LLM Judge, chain threat block/warn |

## 5. 核心组件

### 5.1 ContentScanner

多层扫描引擎，按以下顺序执行：

1. 正则模式匹配（50+ 内置模式）
2. Allowlist 过滤（抑制已知误报）
3. 编码绕过防御（解码后二次匹配）
4. 高熵字符串检测（Shannon 熵分析）
5. Prompt Injection 检测（独立方法调用）

### 5.2 ChainAnalyzer

维护每个 session 的工具调用历史（滑动窗口），执行：

1. 子序列模式匹配（10+ 内置威胁模式）
2. 参数感知检查（paramCheck 函数）
3. 数据流追踪（资源级别跨工具流向）
4. 频率异常检测

### 5.3 SensitivePathGuard

文件路径风险评估（30+ 规则）和 Shell 命令风险评估（20+ 规则），返回 4 级风险分类。

### 5.4 RateLimiter / CircuitBreaker

滑动窗口速率限制和三态熔断器，应用于出站消息检查。

### 5.5 LLMJudge

仅在 ChainAnalyzer 检测到 high/critical 威胁时触发。构建结构化 Prompt 发送至外部 LLM，解析 SAFE / UNSAFE / NEEDS_REVIEW 判定结果。

### 5.6 ProviderRegistry / SecurityPipeline

第三方 Provider 的注册中心和统一调度器。Provider 注册后通过 SecurityPipeline 与内置检查并行执行，采用 Promise.allSettled 实现故障隔离。

### 5.7 AuditLogger

结构化审计日志，支持多个 StorageAdapter 并行写入。每条记录包含事件类型、扫描结果、调用链分析、LLM 判定等上下文信息。

## 6. 配置结构

```typescript
interface SecurityConfig {
  scanner?: {
    extraPatterns?: Array<...>;   // 自定义检测模式
    disabledPatterns?: string[];  // 禁用指定内置模式
    allowlist?: string[];         // 误报白名单
    enableEncodingDefense?: boolean;
    enableEntropyDetection?: boolean;
    enablePromptInjection?: boolean;
  };
  chain?: {
    windowMs?: number;            // 分析窗口（默认 120s）
    maxWindowSize?: number;       // 最大事件数（默认 100）
    customThreats?: Array<...>;   // 自定义威胁模式
  };
  guard?: {
    rateLimit?: { maxPerMinute?: number; maxPerHour?: number };
    circuitBreaker?: { failureThreshold?: number; resetTimeMs?: number };
  };
  llmJudge?: LLMJudgeConfig;
  audit?: { adapter: string; path?: string };
  actions?: {
    onSecretDetected?: 'redact' | 'block' | 'warn';
    onPromptInjection?: 'log' | 'block' | 'warn';
    onSensitivePath?: 'log' | 'block' | 'warn';
    onDangerousCommand?: 'log' | 'block' | 'warn';
    onChainThreat?: 'log' | 'block' | 'warn';
    onRateLimitExceeded?: 'log' | 'block' | 'warn';
  };
}
```

## 7. NanoClaw 集成

NanoClaw 无插件 / Hook 系统，采用直接函数调用方式集成：

```typescript
import { ContentScanner, ChainAnalyzer, SensitivePathGuard } from '@openclaw/sec'

const scanner = new ContentScanner()
const analyzer = new ChainAnalyzer()
const guard = new SensitivePathGuard()

// 在发送 Agent 回复前
const scan = scanner.scan(reply.text)
if (scan.hasFindings) {
  reply.text = scan.redactedText
}

// 在工具调用前
const pathCheck = guard.checkPath(targetPath)
if (pathCheck.risk === 'critical') {
  // 拒绝操作
}
```
