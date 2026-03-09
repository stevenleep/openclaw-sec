/**
 * SecurityPipeline — orchestrates built-in checks and third-party providers
 * into a unified security evaluation flow.
 *
 *   ┌─────────────────────────────────────────────────────┐
 *   │  before-builtin providers  →  built-in checks  →   │
 *   │  after-builtin providers   →  fallback providers    │
 *   │         ↓                                           │
 *   │   Decision Evaluators (if findings/threats exist)   │
 *   │         ↓                                           │
 *   │   Audit Reporters (always)                          │
 *   └─────────────────────────────────────────────────────┘
 */

import type { ScanFinding, ToolEvent, ChainThreat, AuditEntry } from '../types/index.js';
import type {
  ContentScannerProvider,
  ThreatDetectorProvider,
  DecisionEvaluatorProvider,
  AuditReporterProvider,
  DecisionResult,
  ScanContext,
} from './types.js';
import type { ProviderRegistry } from './registry.js';

// ---------------------------------------------------------------------------
// Pipeline result types
// ---------------------------------------------------------------------------

export interface PipelineScanResult {
  /** Merged findings from built-in + all providers */
  findings: ScanFinding[];
  /** Which providers contributed findings */
  providerSources: string[];
}

export interface PipelineThreatResult {
  threats: ChainThreat[];
  providerSources: string[];
}

export interface PipelineDecisionResult {
  decisions: DecisionResult[];
  /** Final aggregated outcome: block if ANY provider says block */
  finalDecision: 'allow' | 'block' | 'review';
}

// ---------------------------------------------------------------------------
// SecurityPipeline
// ---------------------------------------------------------------------------

export class SecurityPipeline {
  constructor(private readonly registry: ProviderRegistry) {}

  /**
   * Run all registered ContentScannerProviders against text.
   * The caller should merge these with built-in scan results.
   */
  async runContentScanners(text: string, context?: ScanContext): Promise<PipelineScanResult> {
    const scanners = this.registry.getByType('content-scanner');
    if (scanners.length === 0) return { findings: [], providerSources: [] };

    const findings: ScanFinding[] = [];
    const providerSources: string[] = [];

    const results = await Promise.allSettled(
      scanners.map(async (scanner: ContentScannerProvider) => {
        const providerFindings = await scanner.scan(text, context);
        return { id: scanner.metadata.id, findings: providerFindings };
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.findings.length > 0) {
        findings.push(...result.value.findings);
        providerSources.push(result.value.id);
      }
    }

    return { findings, providerSources };
  }

  /**
   * Run all registered ThreatDetectorProviders against session events.
   */
  async runThreatDetectors(events: ToolEvent[], sessionKey: string): Promise<PipelineThreatResult> {
    const detectors = this.registry.getByType('threat-detector');
    if (detectors.length === 0) return { threats: [], providerSources: [] };

    const threats: ChainThreat[] = [];
    const providerSources: string[] = [];

    const results = await Promise.allSettled(
      detectors.map(async (detector: ThreatDetectorProvider) => {
        const providerThreats = await detector.detect(events, sessionKey);
        return { id: detector.metadata.id, threats: providerThreats };
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.threats.length > 0) {
        threats.push(...result.value.threats);
        providerSources.push(result.value.id);
      }
    }

    return { threats, providerSources };
  }

  /**
   * Run all registered DecisionEvaluatorProviders.
   * Returns individual decisions and a final aggregated outcome.
   *
   * Aggregation rules:
   *  - If ANY provider returns 'block' → final = 'block'
   *  - If ANY provider returns 'review' (and none block) → final = 'review'
   *  - If all return 'allow' or 'abstain' → final = 'allow'
   */
  async runDecisionEvaluators(context: {
    sessionKey: string;
    event: string;
    findings?: ScanFinding[];
    threats?: ChainThreat[];
    metadata?: Record<string, unknown>;
  }): Promise<PipelineDecisionResult> {
    const evaluators = this.registry.getByType('decision-evaluator');
    if (evaluators.length === 0) {
      return { decisions: [], finalDecision: 'allow' };
    }

    const decisions: DecisionResult[] = [];

    const results = await Promise.allSettled(
      evaluators.map(async (evaluator: DecisionEvaluatorProvider) => {
        return evaluator.evaluate(context);
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        decisions.push(result.value);
      }
    }

    let finalDecision: 'allow' | 'block' | 'review' = 'allow';
    for (const d of decisions) {
      if (d.decision === 'block') {
        finalDecision = 'block';
        break;
      }
      if (d.decision === 'review') {
        finalDecision = 'review';
      }
    }

    return { decisions, finalDecision };
  }

  /**
   * Send an audit entry to all registered AuditReporterProviders.
   * Failures are silently caught — audit reporting should never break the flow.
   */
  async runAuditReporters(entry: AuditEntry): Promise<void> {
    const reporters = this.registry.getByType('audit-reporter');
    if (reporters.length === 0) return;

    await Promise.allSettled(
      reporters.map(async (reporter: AuditReporterProvider) => {
        await reporter.report(entry);
      }),
    );
  }

  /**
   * Batch audit reporting for efficiency.
   */
  async runAuditReportersBatch(entries: AuditEntry[]): Promise<void> {
    const reporters = this.registry.getByType('audit-reporter');
    if (reporters.length === 0) return;

    await Promise.allSettled(
      reporters.map(async (reporter: AuditReporterProvider) => {
        if (reporter.reportBatch) {
          await reporter.reportBatch(entries);
        } else {
          for (const entry of entries) {
            await reporter.report(entry);
          }
        }
      }),
    );
  }
}
