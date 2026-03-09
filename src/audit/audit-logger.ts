import { v4 as uuidv4 } from 'uuid';
import type {
  AuditEntry,
  AuditFilter,
  AuditStorageAdapter,
  ChainAnalysisResult,
  LLMJudgeResult,
  ScanResult,
} from '../types/index.js';

export class AuditLogger {
  private readonly adapters: AuditStorageAdapter[] = [];

  addAdapter(adapter: AuditStorageAdapter): void {
    this.adapters.push(adapter);
  }

  async log(opts: {
    sessionKey: string;
    event: string;
    source?: string;
    scanResult?: ScanResult;
    chainAnalysis?: ChainAnalysisResult;
    llmJudge?: LLMJudgeResult;
    metadata?: Record<string, unknown>;
  }): Promise<string> {
    const entry: AuditEntry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      sessionKey: opts.sessionKey,
      event: opts.event,
      source: opts.source,
      scanResult: opts.scanResult?.hasFindings
        ? {
            findingCount: opts.scanResult.findings.length,
            types: [...new Set(opts.scanResult.findings.map(f => f.type))],
            redacted: true,
          }
        : undefined,
      chainAnalysis: opts.chainAnalysis?.threats.length
        ? {
            threats: opts.chainAnalysis.threats,
            highestSeverity: opts.chainAnalysis.highestSeverity,
          }
        : undefined,
      llmJudge: opts.llmJudge,
      metadata: opts.metadata,
    };

    await this.writeToAdapters(entry);
    return entry.id;
  }

  async query(filter: AuditFilter): Promise<AuditEntry[]> {
    for (const adapter of this.adapters) {
      if (adapter.query) {
        return adapter.query(filter);
      }
    }
    return [];
  }

  async flush(): Promise<void> {
    await Promise.all(
      this.adapters.filter(a => a.flush).map(a => a.flush!()),
    );
  }

  async close(): Promise<void> {
    await this.flush();
    await Promise.all(
      this.adapters.filter(a => a.close).map(a => a.close!()),
    );
  }

  private async writeToAdapters(entry: AuditEntry): Promise<void> {
    const results = await Promise.allSettled(
      this.adapters.map(a => a.write(entry)),
    );
    for (const result of results) {
      if (result.status === 'rejected') {
        console.error('[openclaw-sec] Audit write failed:', result.reason);
      }
    }
  }
}
