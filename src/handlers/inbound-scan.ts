import type { OpenClawHookEvent, SecurityConfig } from '../types/index.js';
import { ContentScanner } from '../scanner/content-scanner.js';
import { AuditLogger } from '../audit/audit-logger.js';
import type { SecurityPipeline } from '../provider/pipeline.js';

export const createInboundScan = (
  scanner: ContentScanner,
  auditLogger: AuditLogger,
  config?: SecurityConfig,
  pipeline?: SecurityPipeline,
) => {
  const injectionAction = config?.actions?.onPromptInjection ?? 'warn';
  const secretAction = config?.actions?.onSecretDetected ?? 'redact';

  return async (event: OpenClawHookEvent): Promise<void> => {
    if (event.type !== 'message' || event.action !== 'preprocessed') return;

    const body = (event.context.bodyForAgent ?? event.context.body) as string | undefined;
    if (!body) return;

    // Secret/PII scan (built-in)
    const result = scanner.scan(body);

    // Third-party provider scan
    if (pipeline) {
      const providerResult = await pipeline.runContentScanners(body, {
        sessionKey: event.sessionKey,
        direction: 'inbound',
      });
      if (providerResult.findings.length > 0) {
        result.findings.push(...providerResult.findings);
        result.hasFindings = true;
      }
    }

    if (result.hasFindings) {
      await auditLogger.log({
        sessionKey: event.sessionKey,
        event: 'inbound:secret_detected',
        source: event.context.channelId as string | undefined,
        scanResult: result,
        metadata: {
          from: event.context.from,
          findingLabels: result.findings.map(f => f.label),
          action: secretAction,
        },
      });

      // Redact inbound content so the Agent never sees raw secrets
      if (secretAction === 'redact') {
        event.context.bodyForAgent = result.redactedText;
      } else if (secretAction === 'block') {
        event.context.bodyForAgent = '[BLOCKED: Inbound message contained sensitive information]';
        event.context.body = '[BLOCKED: Inbound message contained sensitive information]';
        event.messages.push(
          `[SEC] Blocked inbound message containing ${result.findings.length} sensitive item(s)`,
        );
      }
    }

    // Prompt injection detection
    const injectionResult = scanner.detectInjection(body);
    if (injectionResult?.isInjection) {
      await auditLogger.log({
        sessionKey: event.sessionKey,
        event: 'inbound:prompt_injection',
        source: event.context.channelId as string | undefined,
        metadata: {
          from: event.context.from,
          score: injectionResult.score,
          triggers: injectionResult.triggers.map(t => ({
            pattern: t.pattern,
            category: t.category,
            severity: t.severity,
          })),
          action: injectionAction,
        },
      });

      if (injectionAction === 'block') {
        event.context.bodyForAgent = '[BLOCKED: Potential prompt injection detected]';
        event.context.body = '[BLOCKED: Potential prompt injection detected]';
        event.messages.push(
          `[SEC] Blocked inbound message -- prompt injection detected (score: ${injectionResult.score}, ${injectionResult.triggers.length} trigger(s))`,
        );
      } else if (injectionAction === 'warn') {
        event.messages.push(
          `[SEC] Warning: Potential prompt injection detected (score: ${injectionResult.score}, triggers: ${injectionResult.triggers.map(t => t.pattern).join(', ')})`,
        );
      }
    }
  };
};
