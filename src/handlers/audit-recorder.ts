import type { OpenClawHookEvent } from '../types/index.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { ChainAnalyzer } from '../chain/chain-analyzer.js';
import type { LLMJudge } from '../judge/llm-judge.js';
import type { ToolCategory, SecurityConfig } from '../types/index.js';

const TOOL_NAME_TO_CATEGORY: Record<string, ToolCategory> = {
  read: 'fs.read',
  write: 'fs.write',
  edit: 'fs.write',
  apply_patch: 'fs.write',
  delete: 'fs.delete',
  exec: 'shell.exec',
  process: 'shell.exec',
  fetch: 'net.fetch',
  web_fetch: 'net.fetch',
  browser: 'net.fetch',
  curl: 'net.send',
  http: 'net.send',
  db_query: 'db.query',
  db_exec: 'db.mutate',
  env: 'env.read',
  message: 'message.send',
  agent_send: 'message.send',
};

const categorize = (toolName: string): ToolCategory =>
  TOOL_NAME_TO_CATEGORY[toolName] ?? 'unknown';

export const createAuditRecorder = (
  auditLogger: AuditLogger,
  chainAnalyzer: ChainAnalyzer,
  llmJudge: LLMJudge | null,
  config?: SecurityConfig,
) => {
  const chainAction = config?.actions?.onChainThreat ?? 'log';

  return async (event: OpenClawHookEvent): Promise<void> => {
    // Record all command/message events
    await auditLogger.log({
      sessionKey: event.sessionKey,
      event: `${event.type}:${event.action}`,
      source: event.context.commandSource as string | undefined
        ?? event.context.channelId as string | undefined,
      metadata: {
        senderId: event.context.senderId,
        from: event.context.from,
        to: event.context.to,
      },
    });

    // Feed tool-related events into chain analysis
    if (event.type === 'message' && event.action === 'sent') {
      const chainResult = chainAnalyzer.track({
        category: 'message.send',
        toolName: 'message',
        timestamp: event.timestamp.getTime(),
        sessionKey: event.sessionKey,
      });

      if (chainResult.threats.length > 0) {
        await handleChainThreats(event, chainResult, auditLogger, llmJudge, chainAction);
      }
    }
  };
};

const handleChainThreats = async (
  event: OpenClawHookEvent,
  chainResult: ReturnType<ChainAnalyzer['track']>,
  auditLogger: AuditLogger,
  llmJudge: LLMJudge | null,
  action: string,
) => {
  let llmResult = undefined;

  if (
    llmJudge &&
    (chainResult.highestSeverity === 'high' || chainResult.highestSeverity === 'critical')
  ) {
    llmResult = await llmJudge.evaluate({
      chainThreats: chainResult.threats,
      sessionKey: event.sessionKey,
    });
  }

  await auditLogger.log({
    sessionKey: event.sessionKey,
    event: 'chain:threat_detected',
    chainAnalysis: chainResult,
    llmJudge: llmResult,
    metadata: {
      action,
      threatPatterns: chainResult.threats.map(t => t.pattern),
    },
  });

  if (action === 'block') {
    const threatSummary = chainResult.threats
      .map(t => `[${t.severity}] ${t.description}`)
      .join('; ');

    event.context.content = `[BLOCKED: Suspicious tool chain detected — ${threatSummary}]`;
    event.messages.push(
      `[SEC] Blocked -- ${chainResult.threats.length} suspicious chain pattern(s): ${threatSummary}`,
    );
  } else if (action === 'warn') {
    const threatSummary = chainResult.threats
      .map(t => `[${t.severity}] ${t.description}`)
      .join('; ');

    event.messages.push(
      `[SEC] Warning: ${chainResult.threats.length} suspicious pattern(s) detected: ${threatSummary}`,
    );
  }
};

export { categorize as categorizeToolName };
