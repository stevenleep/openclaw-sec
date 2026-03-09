/**
 * OpenClaw Plugin entry point.
 *
 * This module is loaded by the OpenClaw gateway at startup when installed as a plugin.
 * It registers hook handlers for message scanning, tool result redaction,
 * chain analysis, and audit logging.
 *
 * Third-party providers can be registered via the ProviderRegistry on the context.
 */

import { ContentScanner } from './scanner/content-scanner.js';
import { ChainAnalyzer } from './chain/chain-analyzer.js';
import { LLMJudge } from './judge/llm-judge.js';
import { AuditLogger } from './audit/audit-logger.js';
import { LocalFileAdapter } from './audit/adapters/local-file-adapter.js';
import { resolveConfig } from './config/config-loader.js';
import { createOutboundInspector } from './handlers/outbound-inspector.js';
import { createInboundScan } from './handlers/inbound-scan.js';
import { createToolResultRedactor } from './handlers/tool-result-redactor.js';
import { createAuditRecorder } from './handlers/audit-recorder.js';
import { ProviderRegistry } from './provider/registry.js';
import { SecurityPipeline } from './provider/pipeline.js';
import type { SecurityProvider } from './provider/types.js';
import type { OpenClawHookEvent, SecurityConfig } from './types/index.js';

export interface SecPluginContext {
  scanner: ContentScanner;
  chainAnalyzer: ChainAnalyzer;
  llmJudge: LLMJudge | null;
  auditLogger: AuditLogger;
  config: SecurityConfig;
  /** Third-party provider registry */
  providers: ProviderRegistry;
  /** Unified pipeline that orchestrates built-in + third-party checks */
  pipeline: SecurityPipeline;
}

export const createSecurityPlugin = (configPath?: string, overrides?: Partial<SecurityConfig>): SecPluginContext => {
  const config = resolveConfig(configPath, overrides);

  const scanner = new ContentScanner(config);
  const chainAnalyzer = new ChainAnalyzer(config);
  const llmJudge = config.llmJudge ? new LLMJudge(config.llmJudge) : null;

  const auditLogger = new AuditLogger();
  const auditConfig = config.audit ?? { adapter: 'local' };
  if (auditConfig.adapter === 'local') {
    auditLogger.addAdapter(
      new LocalFileAdapter(auditConfig.path ?? './logs/openclaw-sec-audit.jsonl'),
    );
  }

  const providers = new ProviderRegistry();
  const pipeline = new SecurityPipeline(providers);

  return { scanner, chainAnalyzer, llmJudge, auditLogger, config, providers, pipeline };
};

/**
 * Register one or more third-party security providers on the context.
 *
 * @example
 *   const ctx = createSecurityPlugin();
 *   registerProviders(ctx, [myVirusTotalScanner, mySplunkReporter]);
 *   await ctx.providers.initializeAll({ virusTotal: { apiKey: '...' } });
 */
export const registerProviders = (ctx: SecPluginContext, providerList: SecurityProvider[]): void => {
  for (const provider of providerList) {
    ctx.providers.register(provider);
  }
};

/**
 * Builds the set of OpenClaw hook handlers from a SecPluginContext.
 * Each handler follows the OpenClaw event signature: async (event) => void.
 */
export const buildHandlers = (ctx: SecPluginContext) => {
  const outboundInspector = createOutboundInspector(ctx.scanner, ctx.auditLogger, ctx.config, ctx.pipeline);
  const inboundScan = createInboundScan(ctx.scanner, ctx.auditLogger, ctx.config, ctx.pipeline);
  const toolResultRedactor = createToolResultRedactor(ctx.scanner, ctx.auditLogger, ctx.chainAnalyzer, ctx.config, ctx.pipeline);
  const auditRecorder = createAuditRecorder(
    ctx.auditLogger, ctx.chainAnalyzer, ctx.llmJudge, ctx.config,
  );

  return {
    outboundInspector,
    inboundScan,
    toolResultRedactor,
    auditRecorder,
  };
};

/**
 * Default export for OpenClaw plugin loader.
 * This is what OpenClaw calls when loading the plugin.
 */
export default (api: { config: Record<string, unknown> }) => {
  const pluginConfig = (api.config?.sec ?? api.config?.security ?? {}) as Partial<SecurityConfig>;

  const ctx = createSecurityPlugin(undefined, pluginConfig);

  const handlers = buildHandlers(ctx);

  return {
    name: '@openclaw/sec',

    hooks: {
      'message:sent': handlers.outboundInspector,
      'message:preprocessed': handlers.inboundScan,
      'tool_result_persist': handlers.toolResultRedactor,
      'command': handlers.auditRecorder,
      'message': handlers.auditRecorder,
    },

    /** Expose the provider registry so external code can add providers at runtime */
    get providers() { return ctx.providers; },
    get pipeline() { return ctx.pipeline; },

    async shutdown() {
      await ctx.providers.shutdownAll();
      await ctx.auditLogger.close();
    },
  };
};
