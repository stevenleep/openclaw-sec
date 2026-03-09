# Changelog

## 0.3.0 (2026-03-10)

### Third-party Provider SPI

- 新增 SecurityProvider SPI 扩展框架，支持四类第三方 Provider 接入：
  - ContentScannerProvider -- 自定义内容扫描（如 AWS Macie、Google DLP）
  - ThreatDetectorProvider -- 行为威胁检测（如 Splunk、CrowdStrike）
  - DecisionEvaluatorProvider -- 决策引擎（如 OPA/Rego、人工审批）
  - AuditReporterProvider -- 审计外发（如 Splunk、Elasticsearch、Datadog）
- 新增 ProviderRegistry 注册中心，提供 initialize / healthCheck / shutdown 生命周期管理
- 新增 SecurityPipeline 统一调度器，以 Promise.allSettled 并行执行内置与第三方检查，实现故障隔离
- Provider 支持声明执行优先级：before-builtin / after-builtin / fallback
- 决策聚合采用 block-wins 策略
- Plugin context 暴露 providers 和 pipeline 属性，支持运行时动态注册 Provider

### 安全能力升级

- 新增 Prompt Injection 检测器：20+ 条规则，覆盖角色覆盖、指令注入、上下文操纵、输出操纵、分隔符攻击、编码攻击 6 类攻击向量，基于加权评分机制
- 新增高熵字符串检测器：基于 Shannon 熵分析识别随机生成的密钥，支持 hex / base64 / alphanumeric / mixed 字符集，结合上下文关键词加权
- 新增编码绕过防御：自动解码 Base64、URL 编码、Hex、Unicode 转义后进行二次扫描
- 新增敏感路径保护：30+ 条路径规则，覆盖 .env / .ssh / .aws / .kube / PEM 密钥文件 / 浏览器凭证 / 系统文件 / git 凭证，4 级风险分类
- 新增命令风险评估：20+ 条规则，覆盖 fork bomb / rm -rf / curl piped to bash / sudo / DROP DATABASE / 特权提升 / 网络外泄
- 新增速率限制器：按分钟和小时的滑动窗口限流，支持按 session 隔离
- 新增熔断器：安全违规累计触发自动熔断，open / half-open / closed 三态机制
- 新增多语言 PII 检测：中国居民身份证号、手机号、银行卡号、护照号、统一社会信用代码，韩国 RRN，日本 My Number
- 新增 JWT Token 检测模式
- 新增 Allowlist 误报抑制：支持精确匹配和正则模式
- ChainAnalyzer 新增数据流追踪：记录资源级别的跨工具流向，检测敏感资源到网络通道的外泄行为
- ChainAnalyzer 新增参数感知威胁模式：可通过 paramCheck 函数检查工具参数（例如仅当读取的文件属于敏感路径时才触发告警）

### Handler 升级

- message:preprocessed 新增 Prompt Injection 检测和入站内容 redact/block 能力
- message:sent 新增速率限制、熔断器保护和第三方 Provider 扫描
- tool_result_persist 新增敏感路径和危险命令的 block/warn 执行能力
- 所有 Handler 接入 SecurityPipeline，第三方 Provider 的检测结果参与决策流程
- audit-recorder 的 chain threat block action 现在会实际阻止消息发出

### 配置

- 新增 scanner.allowlist / scanner.enableEncodingDefense / scanner.enableEntropyDetection / scanner.enablePromptInjection 配置项
- 新增 guard.rateLimit 和 guard.circuitBreaker 配置段
- 新增 actions 类型：onPromptInjection / onSensitivePath / onDangerousCommand / onRateLimitExceeded

## 0.2.0 (2026-03-10)

### 不兼容变更

- 架构完全重设计，面向 OpenClaw / NanoClaw 集成
- 移除 v1 的 interceptor / pipeline / decision-engine（与 OpenClaw 内置安全能力重叠）

### 新增功能

- Content Scanner：25+ 内置模式，检测 API Keys、PII、凭证、私钥
- Chain Analyzer：跨工具调用链外泄检测（如 fs.read -> net.send 模式匹配）
- LLM Judge：针对高风险调用链威胁的 AI 安全审查
- OpenClaw Plugin：标准 openclaw.plugin.json manifest 与 Hook handler
- OpenClaw Hook：轻量级 Hook 集成格式
- Standalone library：面向 NanoClaw 和自定义框架的直接函数调用
- 可配置动作策略：每种检测类型支持 redact / block / warn

### Hook Handlers

- message:sent -- 出站内容检查
- message:preprocessed -- 入站内容扫描
- tool_result_persist -- 工具结果脱敏 + 调用链事件跟踪
- command / message -- 审计记录

## 0.1.0 (2026-03-10)

基于 interceptor 架构的初始原型（已被 0.2.0 替代）。
