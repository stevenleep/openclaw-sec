/**
 * Security Provider SPI (Service Provider Interface).
 *
 * Third-party security services implement one or more of these interfaces
 * to plug into the openclaw-sec pipeline. Each interface targets a specific
 * stage of the security lifecycle:
 *
 *   Content  →  Threat  →  Decision  →  Audit
 *   Scanner     Detector   Evaluator   Reporter
 *
 * Providers are registered via ProviderRegistry and automatically
 * invoked by the security pipeline alongside built-in capabilities.
 */

import type {
  ScanFinding,
  ScanResult,
  ToolEvent,
  ChainThreat,
  AuditEntry,
} from '../types/index.js';

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

export type ProviderPriority = 'before-builtin' | 'after-builtin' | 'fallback';

export interface ProviderMetadata {
  /** Unique ID (e.g. "virustotal", "aws-macie", "custom-dlp") */
  id: string;
  /** Human-readable name */
  name: string;
  /** Semantic version */
  version: string;
  /** When to run relative to built-in checks */
  priority?: ProviderPriority;
  /** Provider-specific configuration schema (for documentation) */
  configSchema?: Record<string, unknown>;
}

export interface ProviderLifecycle {
  /** Called once when the provider is registered. Use for connection setup. */
  initialize?(config: Record<string, unknown>): Promise<void>;
  /** Health check — return true if the provider is operational */
  healthCheck?(): Promise<boolean>;
  /** Called when the plugin shuts down. Use for cleanup. */
  shutdown?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Content Scanner Provider — extends secret/PII detection
// ---------------------------------------------------------------------------

/**
 * Implement this to add custom content scanning (e.g. DLP service, Macie,
 * custom regex engine, ML-based PII detection).
 */
export interface ContentScannerProvider extends ProviderLifecycle {
  readonly metadata: ProviderMetadata;
  readonly type: 'content-scanner';

  /**
   * Scan text for sensitive content.
   * Return findings only — redaction is handled by the core pipeline.
   */
  scan(text: string, context?: ScanContext): Promise<ScanFinding[]>;
}

export interface ScanContext {
  sessionKey?: string;
  field?: string;
  source?: string;
  direction?: 'inbound' | 'outbound' | 'tool-result';
}

// ---------------------------------------------------------------------------
// Threat Detector Provider — extends chain/behavior analysis
// ---------------------------------------------------------------------------

/**
 * Implement this to add custom threat detection (e.g. SIEM integration,
 * behavioral ML models, anomaly detection services).
 */
export interface ThreatDetectorProvider extends ProviderLifecycle {
  readonly metadata: ProviderMetadata;
  readonly type: 'threat-detector';

  /**
   * Evaluate a sequence of tool events for threats.
   * Called after each tool invocation with the full session history.
   */
  detect(events: ToolEvent[], sessionKey: string): Promise<ChainThreat[]>;
}

// ---------------------------------------------------------------------------
// Decision Evaluator Provider — extends risk decisions
// ---------------------------------------------------------------------------

export type ProviderDecision = 'allow' | 'block' | 'review' | 'abstain';

export interface DecisionContext {
  sessionKey: string;
  event: string;
  findings?: ScanFinding[];
  threats?: ChainThreat[];
  metadata?: Record<string, unknown>;
}

export interface DecisionResult {
  decision: ProviderDecision;
  reasoning: string;
  confidence?: number;
  provider: string;
}

/**
 * Implement this to add custom decision logic (e.g. policy engine,
 * OPA/Rego, external approval service, human-in-the-loop).
 */
export interface DecisionEvaluatorProvider extends ProviderLifecycle {
  readonly metadata: ProviderMetadata;
  readonly type: 'decision-evaluator';

  evaluate(context: DecisionContext): Promise<DecisionResult>;
}

// ---------------------------------------------------------------------------
// Audit Reporter Provider — extends audit destinations
// ---------------------------------------------------------------------------

/**
 * Implement this to send audit events to external systems
 * (e.g. Splunk, Elasticsearch, CloudWatch, Datadog, SIEM).
 */
export interface AuditReporterProvider extends ProviderLifecycle {
  readonly metadata: ProviderMetadata;
  readonly type: 'audit-reporter';

  report(entry: AuditEntry): Promise<void>;
  reportBatch?(entries: AuditEntry[]): Promise<void>;
}

// ---------------------------------------------------------------------------
// Union type
// ---------------------------------------------------------------------------

export type SecurityProvider =
  | ContentScannerProvider
  | ThreatDetectorProvider
  | DecisionEvaluatorProvider
  | AuditReporterProvider;

export type SecurityProviderType = SecurityProvider['type'];
