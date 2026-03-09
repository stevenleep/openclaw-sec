import type {
  ChainAnalysisResult,
  ChainThreat,
  SecurityConfig,
  ToolCategory,
  ToolEvent,
} from '../types/index.js';
import { SensitivePathGuard } from '../guard/sensitive-paths.js';

interface ThreatPattern {
  id: string;
  description: string;
  sequence: ToolCategory[];
  severity: ChainThreat['severity'];
  paramCheck?: (events: ToolEvent[]) => boolean;
}

/**
 * Tracks data resources touched by a session for cross-tool flow analysis.
 * E.g. if fs.read reads `/etc/shadow`, and the next net.send sends that data,
 * we can link the two.
 */
interface DataFlowNode {
  resource: string;
  category: ToolCategory;
  timestamp: number;
  sensitive: boolean;
}

const BUILT_IN_THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: 'file-exfil-net',
    description: 'File content read followed by network send — potential data exfiltration',
    sequence: ['fs.read', 'net.send'],
    severity: 'high',
  },
  {
    id: 'file-exfil-msg',
    description: 'File content read followed by message send — potential data leak via chat',
    sequence: ['fs.read', 'message.send'],
    severity: 'high',
  },
  {
    id: 'env-exfil-net',
    description: 'Environment variable read followed by network send — secret exfiltration',
    sequence: ['env.read', 'net.send'],
    severity: 'critical',
  },
  {
    id: 'env-exfil-msg',
    description: 'Environment variable read followed by message send — secret leak via chat',
    sequence: ['env.read', 'message.send'],
    severity: 'critical',
  },
  {
    id: 'db-exfil-net',
    description: 'Database query followed by network send — data exfiltration',
    sequence: ['db.query', 'net.send'],
    severity: 'high',
  },
  {
    id: 'db-exfil-msg',
    description: 'Database query followed by message send — data leak via chat',
    sequence: ['db.query', 'message.send'],
    severity: 'high',
  },
  {
    id: 'auth-exfil',
    description: 'Auth token access followed by network send — credential theft',
    sequence: ['auth.token', 'net.send'],
    severity: 'critical',
  },
  {
    id: 'bulk-read-send',
    description: 'Multiple file reads followed by network activity — bulk exfiltration',
    sequence: ['fs.read', 'fs.read', 'fs.read', 'net.send'],
    severity: 'critical',
  },
  {
    id: 'destructive-shell',
    description: 'File read followed by destructive shell execution',
    sequence: ['fs.read', 'shell.exec', 'fs.delete'],
    severity: 'high',
  },
  {
    id: 'sensitive-file-exfil',
    description: 'Sensitive file read followed by network send — high-value data exfiltration',
    sequence: ['fs.read', 'net.send'],
    severity: 'critical',
    paramCheck: (events) => {
      const readEvent = events.find(e => e.category === 'fs.read');
      if (!readEvent?.params?.path) return false;
      const guard = new SensitivePathGuard();
      const result = guard.checkPath(String(readEvent.params.path));
      return result.risk === 'critical' || result.risk === 'dangerous';
    },
  },
  {
    id: 'credential-steal-exec',
    description: 'Shell execution followed by network send — potential credential theft via command',
    sequence: ['shell.exec', 'net.send'],
    severity: 'high',
    paramCheck: (events) => {
      const shellEvent = events.find(e => e.category === 'shell.exec');
      const cmd = String(shellEvent?.params?.command ?? '');
      return /(?:cat|head|tail|less|more)\s+.*(?:\.env|\.ssh|password|secret|key|token|credential)/i.test(cmd);
    },
  },
];

export class ChainAnalyzer {
  private readonly sessions = new Map<string, ToolEvent[]>();
  private readonly dataFlows = new Map<string, DataFlowNode[]>();
  private readonly windowMs: number;
  private readonly maxWindowSize: number;
  private readonly threatPatterns: ThreatPattern[];
  private readonly pathGuard: SensitivePathGuard;

  constructor(config?: SecurityConfig) {
    this.windowMs = config?.chain?.windowMs ?? 120_000;
    this.maxWindowSize = config?.chain?.maxWindowSize ?? 100;
    this.pathGuard = new SensitivePathGuard();

    this.threatPatterns = [...BUILT_IN_THREAT_PATTERNS];

    if (config?.chain?.customThreats) {
      for (const custom of config.chain.customThreats) {
        this.threatPatterns.push({
          id: custom.pattern,
          description: custom.description,
          sequence: custom.sequence,
          severity: custom.severity,
        });
      }
    }
  }

  track(event: ToolEvent): ChainAnalysisResult {
    const history = this.getSessionHistory(event.sessionKey);
    history.push(event);
    this.pruneOldEvents(history, event.timestamp);

    if (history.length > this.maxWindowSize) {
      history.splice(0, history.length - this.maxWindowSize);
    }

    this.sessions.set(event.sessionKey, history);

    this.trackDataFlow(event);

    const threats = this.detectThreats(history, event.sessionKey);

    const dataFlowThreats = this.detectDataFlowThreats(event.sessionKey);
    threats.push(...dataFlowThreats);

    const severityOrder: Record<string, number> = {
      none: 0, low: 1, medium: 2, high: 3, critical: 4,
    };
    let highestSeverity: ChainThreat['severity'] | 'none' = 'none';
    for (const threat of threats) {
      if (severityOrder[threat.severity] > severityOrder[highestSeverity]) {
        highestSeverity = threat.severity;
      }
    }

    return { threats, highestSeverity, sessionKey: event.sessionKey };
  }

  clearSession(sessionKey: string): void {
    this.sessions.delete(sessionKey);
    this.dataFlows.delete(sessionKey);
  }

  getSessionHistory(sessionKey: string): ToolEvent[] {
    return this.sessions.get(sessionKey) ?? [];
  }

  getDataFlow(sessionKey: string): DataFlowNode[] {
    return this.dataFlows.get(sessionKey) ?? [];
  }

  private trackDataFlow(event: ToolEvent): void {
    const flows = this.dataFlows.get(event.sessionKey) ?? [];

    let resource: string | undefined;

    if (event.category === 'fs.read' || event.category === 'fs.write' || event.category === 'fs.delete') {
      resource = String(event.params?.path ?? event.params?.file ?? '');
    } else if (event.category === 'env.read') {
      resource = `env:${String(event.params?.name ?? event.params?.key ?? '*')}`;
    } else if (event.category === 'db.query' || event.category === 'db.mutate') {
      resource = `db:${String(event.params?.table ?? event.params?.collection ?? '*')}`;
    } else if (event.category === 'net.send' || event.category === 'net.fetch') {
      resource = String(event.params?.url ?? event.params?.endpoint ?? '');
    } else if (event.category === 'shell.exec') {
      resource = `cmd:${String(event.params?.command ?? '').slice(0, 80)}`;
    }

    if (resource) {
      let sensitive = false;
      if (event.category.startsWith('fs.') || event.category === 'env.read') {
        const pathResult = this.pathGuard.checkPath(resource);
        sensitive = pathResult.risk === 'critical' || pathResult.risk === 'dangerous';
      }
      if (event.category === 'env.read') sensitive = true;
      if (event.category === 'auth.token') sensitive = true;

      flows.push({ resource, category: event.category, timestamp: event.timestamp, sensitive });

      if (flows.length > this.maxWindowSize) {
        flows.splice(0, flows.length - this.maxWindowSize);
      }
      this.dataFlows.set(event.sessionKey, flows);
    }
  }

  private detectDataFlowThreats(sessionKey: string): ChainThreat[] {
    const threats: ChainThreat[] = [];
    const flows = this.dataFlows.get(sessionKey) ?? [];

    const sensitiveReads = flows.filter(
      f => f.sensitive && (f.category === 'fs.read' || f.category === 'env.read' || f.category === 'auth.token'),
    );
    const sends = flows.filter(
      f => f.category === 'net.send' || f.category === 'net.fetch' || f.category === 'message.send',
    );

    for (const read of sensitiveReads) {
      for (const send of sends) {
        if (send.timestamp > read.timestamp && send.timestamp - read.timestamp < this.windowMs) {
          threats.push({
            pattern: 'dataflow:sensitive-resource-to-network',
            description: `Sensitive resource "${read.resource}" accessed at ${new Date(read.timestamp).toISOString()}, then network/message activity to "${send.resource}" at ${new Date(send.timestamp).toISOString()}`,
            events: [],
            severity: 'critical',
          });
        }
      }
    }

    return threats;
  }

  private pruneOldEvents(history: ToolEvent[], now: number): void {
    const cutoff = now - this.windowMs;
    while (history.length > 0 && history[0].timestamp < cutoff) {
      history.shift();
    }
  }

  private detectThreats(history: ToolEvent[], _sessionKey: string): ChainThreat[] {
    const threats: ChainThreat[] = [];
    const categories = history.map(e => e.category);

    for (const pattern of this.threatPatterns) {
      const matchResult = this.findSubsequence(categories, pattern.sequence, history);
      if (matchResult) {
        if (pattern.paramCheck && !pattern.paramCheck(matchResult)) continue;

        threats.push({
          pattern: pattern.id,
          description: pattern.description,
          events: matchResult,
          severity: pattern.severity,
        });
      }
    }

    const frequencyThreat = this.detectFrequencyAnomaly(history);
    if (frequencyThreat) {
      threats.push(frequencyThreat);
    }

    return threats;
  }

  private findSubsequence(
    categories: ToolCategory[],
    sequence: ToolCategory[],
    events: ToolEvent[],
  ): ToolEvent[] | null {
    if (sequence.length > categories.length) return null;

    let seqIdx = 0;
    const matchedEvents: ToolEvent[] = [];

    for (let i = 0; i < categories.length && seqIdx < sequence.length; i++) {
      if (categories[i] === sequence[seqIdx]) {
        matchedEvents.push(events[i]);
        seqIdx++;
      }
    }

    return seqIdx === sequence.length ? matchedEvents : null;
  }

  private detectFrequencyAnomaly(history: ToolEvent[]): ChainThreat | null {
    if (history.length < 2) return null;
    const window30s = history.filter(
      e => e.timestamp > history[history.length - 1].timestamp - 30_000,
    );

    const readOps = window30s.filter(
      e => e.category === 'fs.read' || e.category === 'db.query' || e.category === 'env.read',
    );

    if (readOps.length >= 15) {
      return {
        pattern: 'high-frequency-reads',
        description: `${readOps.length} read operations in 30 seconds — unusual data access pattern`,
        events: readOps.slice(-5),
        severity: 'high',
      };
    }

    return null;
  }
}

export const analyzeChain = (
  events: ToolEvent[],
  sessionKey: string,
  config?: SecurityConfig,
): ChainAnalysisResult => {
  const analyzer = new ChainAnalyzer(config);
  let lastResult: ChainAnalysisResult = {
    threats: [],
    highestSeverity: 'none',
    sessionKey,
  };
  for (const event of events) {
    lastResult = analyzer.track(event);
  }
  return lastResult;
};
