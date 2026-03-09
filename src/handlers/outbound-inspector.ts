import type { OpenClawHookEvent, SecurityConfig } from '../types/index.js';
import { ContentScanner } from '../scanner/content-scanner.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { RateLimiter, CircuitBreaker } from '../guard/rate-limiter.js';
import type { SecurityPipeline } from '../provider/pipeline.js';

export const createOutboundInspector = (
  scanner: ContentScanner,
  auditLogger: AuditLogger,
  config?: SecurityConfig,
  pipeline?: SecurityPipeline,
) => {
  const action = config?.actions?.onSecretDetected ?? 'redact';
  const rateLimiter = new RateLimiter(config?.guard?.rateLimit);
  const circuitBreaker = new CircuitBreaker(config?.guard?.circuitBreaker);

  return async (event: OpenClawHookEvent): Promise<void> => {
    if (event.type !== 'message' || event.action !== 'sent') return;

    const content = event.context.content as string | undefined;
    if (!content) return;

    const cbKey = `outbound:${event.sessionKey}`;
    if (!circuitBreaker.canProceed(cbKey)) {
      const state = circuitBreaker.getState(cbKey);
      event.context.content = '[BLOCKED: Security circuit breaker tripped — too many violations]';
      event.messages.push(
        `[SEC] Session blocked by circuit breaker (${state.failures} violations, state: ${state.state})`,
      );
      await auditLogger.log({
        sessionKey: event.sessionKey,
        event: 'outbound:circuit_breaker_tripped',
        metadata: { circuitState: state },
      });
      return;
    }

    const rlKey = `outbound:${event.sessionKey}`;
    const rlResult = rateLimiter.consume(rlKey);
    if (!rlResult.allowed) {
      await auditLogger.log({
        sessionKey: event.sessionKey,
        event: 'outbound:rate_limited',
        metadata: { reason: rlResult.reason, retryAfterMs: rlResult.retryAfterMs },
      });
      if (config?.actions?.onRateLimitExceeded === 'block') {
        event.context.content = '[BLOCKED: Rate limit exceeded]';
        event.messages.push(`[SEC] Outbound rate limit exceeded`);
        return;
      }
    }

    // Built-in scan
    const result = scanner.scan(content);

    // Third-party provider scan (merge findings)
    if (pipeline) {
      const providerResult = await pipeline.runContentScanners(content, {
        sessionKey: event.sessionKey,
        direction: 'outbound',
      });
      if (providerResult.findings.length > 0) {
        result.findings.push(...providerResult.findings);
        result.hasFindings = true;
      }
    }

    if (!result.hasFindings) {
      circuitBreaker.recordSuccess(cbKey);
      return;
    }

    // Third-party decision evaluation
    if (pipeline) {
      const decision = await pipeline.runDecisionEvaluators({
        sessionKey: event.sessionKey,
        event: 'outbound:scan',
        findings: result.findings,
      });
      if (decision.finalDecision === 'allow') {
        circuitBreaker.recordSuccess(cbKey);
        return;
      }
    }

    circuitBreaker.recordFailure(cbKey);

    await auditLogger.log({
      sessionKey: event.sessionKey,
      event: 'outbound:secret_detected',
      source: event.context.channelId as string | undefined,
      scanResult: result,
      metadata: {
        to: event.context.to,
        findingLabels: result.findings.map(f => f.label),
        action,
      },
    });

    if (action === 'redact') {
      event.context.content = result.redactedText;
    } else if (action === 'block') {
      event.context.content = '[BLOCKED: Message contained sensitive information]';
      event.messages.push(
        `[SEC] Blocked outbound message containing ${result.findings.length} sensitive item(s): `
        + result.findings.map(f => f.label).join(', '),
      );
    } else if (action === 'warn') {
      event.messages.push(
        `[SEC] Warning: Outbound message contains ${result.findings.length} sensitive item(s): `
        + result.findings.map(f => f.label).join(', '),
      );
    }
  };
};
