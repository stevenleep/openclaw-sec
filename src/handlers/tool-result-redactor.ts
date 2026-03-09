import { ContentScanner } from '../scanner/content-scanner.js';
import { AuditLogger } from '../audit/audit-logger.js';
import { ChainAnalyzer } from '../chain/chain-analyzer.js';
import { SensitivePathGuard } from '../guard/sensitive-paths.js';
import { categorizeToolName } from './audit-recorder.js';
import type { SecurityConfig } from '../types/index.js';
import type { SecurityPipeline } from '../provider/pipeline.js';

export interface ToolResultPayload {
  content?: string;
  sessionKey?: string;
  toolName?: string;
  params?: Record<string, unknown>;
  blocked?: boolean;
  blockReason?: string;
}

export const createToolResultRedactor = (
  scanner: ContentScanner,
  auditLogger: AuditLogger,
  chainAnalyzer?: ChainAnalyzer,
  config?: SecurityConfig,
  pipeline?: SecurityPipeline,
) => {
  const pathGuard = new SensitivePathGuard();
  const cmdAction = config?.actions?.onDangerousCommand ?? 'warn';
  const pathAction = config?.actions?.onSensitivePath ?? 'warn';

  return (payload: ToolResultPayload): ToolResultPayload | undefined => {
    const category = payload.toolName ? categorizeToolName(payload.toolName) : 'unknown';

    if (chainAnalyzer && payload.toolName && payload.sessionKey) {
      chainAnalyzer.track({
        category,
        toolName: payload.toolName,
        params: payload.params,
        timestamp: Date.now(),
        sessionKey: payload.sessionKey,
      });
    }

    // Sensitive path check — execute configured action
    if ((category === 'fs.read' || category === 'fs.write' || category === 'fs.delete') && payload.params?.path) {
      const pathResult = pathGuard.checkPath(String(payload.params.path));
      if (pathResult.risk === 'critical' || pathResult.risk === 'dangerous') {
        void auditLogger.log({
          sessionKey: payload.sessionKey ?? 'unknown',
          event: 'tool:sensitive_path_access',
          metadata: {
            toolName: payload.toolName,
            path: pathResult.path,
            risk: pathResult.risk,
            reason: pathResult.reason,
            category: pathResult.category,
            action: pathAction,
          },
        });

        if (pathAction === 'block') {
          return {
            ...payload,
            content: `[BLOCKED: Access to sensitive path "${pathResult.path}" denied — ${pathResult.reason}]`,
            blocked: true,
            blockReason: pathResult.reason,
          };
        }
      }
    }

    // Dangerous command check — execute configured action
    if (category === 'shell.exec' && payload.params?.command) {
      const cmdResult = pathGuard.evaluateCommand(String(payload.params.command));
      if (cmdResult.risk === 'critical' || cmdResult.risk === 'dangerous') {
        void auditLogger.log({
          sessionKey: payload.sessionKey ?? 'unknown',
          event: 'tool:dangerous_command',
          metadata: {
            toolName: payload.toolName,
            command: String(payload.params.command).slice(0, 200),
            risk: cmdResult.risk,
            reasons: cmdResult.reasons,
            destructive: cmdResult.destructive,
            requiresElevation: cmdResult.requiresElevation,
            networkAccess: cmdResult.networkAccess,
            action: cmdAction,
          },
        });

        if (cmdAction === 'block') {
          return {
            ...payload,
            content: `[BLOCKED: Dangerous command denied — ${cmdResult.reasons.join(', ')}]`,
            blocked: true,
            blockReason: cmdResult.reasons.join(', '),
          };
        }
      }
    }

    if (!payload.content) return undefined;

    // Built-in content scan
    const result = scanner.scan(payload.content);

    // Third-party provider scan
    if (pipeline) {
      void pipeline.runContentScanners(payload.content, {
        sessionKey: payload.sessionKey,
        direction: 'tool-result',
      }).then(providerResult => {
        if (providerResult.findings.length > 0) {
          void auditLogger.log({
            sessionKey: payload.sessionKey ?? 'unknown',
            event: 'tool_result:provider_findings',
            metadata: {
              toolName: payload.toolName,
              providerSources: providerResult.providerSources,
              findingCount: providerResult.findings.length,
            },
          });
        }
      });
    }

    if (!result.hasFindings) return undefined;

    void auditLogger.log({
      sessionKey: payload.sessionKey ?? 'unknown',
      event: 'tool_result:redacted',
      metadata: {
        toolName: payload.toolName,
        findingCount: result.findings.length,
        findingLabels: result.findings.map(f => f.label),
      },
      scanResult: result,
    });

    return { ...payload, content: result.redactedText };
  };
};
