/**
 * OpenClaw Hook handler entry point (v0.3).
 *
 * When used as a standalone hook, copy this directory to ~/.openclaw/hooks/openclaw-sec/
 * and run: openclaw hooks enable openclaw-sec
 *
 * This handler imports from the built dist/ output.
 * Make sure the package is installed: npm install @openclaw/sec
 */

import { ContentScanner } from '../dist/scanner/content-scanner.js';
import { ChainAnalyzer } from '../dist/chain/chain-analyzer.js';
import { AuditLogger } from '../dist/audit/audit-logger.js';
import { LocalFileAdapter } from '../dist/audit/adapters/local-file-adapter.js';
import { createOutboundInspector } from '../dist/handlers/outbound-inspector.js';
import { createInboundScan } from '../dist/handlers/inbound-scan.js';
import { createToolResultRedactor } from '../dist/handlers/tool-result-redactor.js';
import { createAuditRecorder } from '../dist/handlers/audit-recorder.js';
import { resolveConfig } from '../dist/config/config-loader.js';

const config = resolveConfig();

const scanner = new ContentScanner(config);
const chainAnalyzer = new ChainAnalyzer(config);
const auditLogger = new AuditLogger();
auditLogger.addAdapter(
  new LocalFileAdapter(config.audit?.path ?? './logs/openclaw-sec-audit.jsonl'),
);

const outboundInspector = createOutboundInspector(scanner, auditLogger, config);
const inboundScan = createInboundScan(scanner, auditLogger, config);
const toolResultRedactor = createToolResultRedactor(scanner, auditLogger, chainAnalyzer, config);
const auditRecorder = createAuditRecorder(auditLogger, chainAnalyzer, null, config);

const handler = async (event: {
  type: string;
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: Record<string, unknown>;
}) => {
  try {
    if (event.type === 'message' && event.action === 'sent') {
      await outboundInspector(event);
    }
    if (event.type === 'message' && event.action === 'preprocessed') {
      await inboundScan(event);
    }
    if (event.type === 'command' || event.type === 'message') {
      await auditRecorder(event);
    }
  } catch (err) {
    console.error('[openclaw-sec]', err instanceof Error ? err.message : String(err));
  }
};

export default handler;

export { toolResultRedactor };
