/**
 * @openclaw/sec — Standalone library entry point.
 *
 * Use this for:
 * - NanoClaw integration (direct function calls)
 * - Custom agent frameworks
 * - Any non-OpenClaw usage
 */

// Core scanning
export { ContentScanner, scanContent } from './scanner/content-scanner.js';
export type { ContentScannerOptions } from './scanner/content-scanner.js';
export { BUILT_IN_PATTERNS } from './scanner/patterns.js';

// Prompt injection detection
export { PromptInjectionDetector, detectPromptInjection } from './scanner/prompt-injection.js';
export type { PromptInjectionResult, PromptInjectionTrigger } from './scanner/prompt-injection.js';

// High-entropy string detection
export { EntropyDetector, detectHighEntropy } from './scanner/entropy.js';
export type { EntropyFinding, EntropyResult } from './scanner/entropy.js';

// Encoding bypass defense
export { EncodingDecoder, decodeEncodings } from './scanner/encoding.js';
export type { DecodedLayer, DecodingResult } from './scanner/encoding.js';

// Chain analysis
export { ChainAnalyzer, analyzeChain } from './chain/chain-analyzer.js';

// Guard: sensitive paths + command risk
export { SensitivePathGuard, checkSensitivePath, evaluateCommand } from './guard/sensitive-paths.js';
export type { PathCheckResult, CommandRiskResult, PathRiskLevel } from './guard/sensitive-paths.js';

// Guard: rate limiter + circuit breaker
export { RateLimiter, CircuitBreaker } from './guard/rate-limiter.js';
export type {
  RateLimitConfig, RateLimitResult,
  CircuitBreakerConfig, CircuitBreakerState, CircuitState,
} from './guard/rate-limiter.js';

// LLM Judge
export { LLMJudge } from './judge/llm-judge.js';

// Audit logging
export { AuditLogger } from './audit/audit-logger.js';
export { LocalFileAdapter } from './audit/adapters/local-file-adapter.js';

// Configuration
export { resolveConfig, loadConfigFromFile } from './config/config-loader.js';

// OpenClaw plugin integration
export { createSecurityPlugin, buildHandlers, registerProviders } from './plugin.js';

// Third-party provider SPI
export {
  ProviderRegistry,
  SecurityPipeline,
} from './provider/index.js';
export type {
  SecurityProvider,
  SecurityProviderType,
  ProviderMetadata,
  ProviderLifecycle,
  ProviderPriority,
  ContentScannerProvider,
  ThreatDetectorProvider,
  DecisionEvaluatorProvider,
  AuditReporterProvider,
  DecisionResult,
  DecisionContext,
  ProviderDecision,
  ScanContext,
  ProviderHealth,
  PipelineScanResult,
  PipelineThreatResult,
  PipelineDecisionResult,
} from './provider/index.js';

// Handler factories (for custom hook wiring)
export { createOutboundInspector } from './handlers/outbound-inspector.js';
export { createInboundScan } from './handlers/inbound-scan.js';
export { createToolResultRedactor } from './handlers/tool-result-redactor.js';
export { createAuditRecorder, categorizeToolName } from './handlers/audit-recorder.js';

// All types
export type {
  ScanFinding,
  ScanResult,
  DetectionPattern,
  ToolCategory,
  ToolEvent,
  ChainThreat,
  ChainAnalysisResult,
  LLMJudgeDecision,
  LLMJudgeResult,
  LLMJudgeConfig,
  AuditEntry,
  AuditFilter,
  AuditStorageAdapter,
  SecurityConfig,
  OpenClawHookEvent,
  OpenClawHookHandler,
} from './types/index.js';
