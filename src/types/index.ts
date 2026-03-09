// --- Content scanning ---

export interface ScanFinding {
  type: 'secret' | 'pii' | 'credential' | 'custom';
  label: string;
  match: string;
  redacted: string;
  field?: string;
  patternId: string;
}

export interface ScanResult {
  hasFindings: boolean;
  findings: ScanFinding[];
  redactedText: string;
  originalText: string;
}

export interface DetectionPattern {
  id: string;
  label: string;
  type: ScanFinding['type'];
  regex: RegExp;
  redactWith?: string;
}

// --- Chain analysis ---

export const TOOL_CATEGORIES = [
  'fs.read', 'fs.write', 'fs.delete',
  'net.send', 'net.fetch',
  'shell.exec',
  'db.query', 'db.mutate',
  'env.read',
  'message.send',
  'process.exec',
  'auth.token',
  'unknown',
] as const;

export type ToolCategory = (typeof TOOL_CATEGORIES)[number];

export interface ToolEvent {
  category: ToolCategory;
  toolName: string;
  params?: Record<string, unknown>;
  timestamp: number;
  sessionKey: string;
}

export interface ChainThreat {
  pattern: string;
  description: string;
  events: ToolEvent[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ChainAnalysisResult {
  threats: ChainThreat[];
  highestSeverity: ChainThreat['severity'] | 'none';
  sessionKey: string;
}

// --- LLM Judge ---

export type LLMJudgeDecision = 'SAFE' | 'UNSAFE' | 'NEEDS_REVIEW';

export interface LLMJudgeResult {
  decision: LLMJudgeDecision;
  reasoning: string;
}

export interface LLMJudgeConfig {
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
}

// --- Audit log ---

export interface AuditEntry {
  id: string;
  timestamp: string;
  sessionKey: string;
  event: string;
  source?: string;
  scanResult?: {
    findingCount: number;
    types: string[];
    redacted: boolean;
  };
  chainAnalysis?: {
    threats: ChainThreat[];
    highestSeverity: string;
  };
  llmJudge?: LLMJudgeResult;
  metadata?: Record<string, unknown>;
}

export interface AuditFilter {
  sessionKey?: string;
  event?: string;
  from?: string;
  to?: string;
  limit?: number;
}

export interface AuditStorageAdapter {
  write(entry: AuditEntry): Promise<void>;
  query?(filter: AuditFilter): Promise<AuditEntry[]>;
  flush?(): Promise<void>;
  close?(): Promise<void>;
}

// --- Configuration ---

export interface SecurityConfig {
  scanner?: {
    extraPatterns?: Array<{
      id: string;
      label: string;
      type: ScanFinding['type'];
      pattern: string;
      flags?: string;
      redactWith?: string;
    }>;
    disabledPatterns?: string[];
    allowlist?: string[];
    enableEncodingDefense?: boolean;
    enableEntropyDetection?: boolean;
    enablePromptInjection?: boolean;
  };
  chain?: {
    windowMs?: number;
    maxWindowSize?: number;
    customThreats?: Array<{
      pattern: string;
      description: string;
      sequence: ToolCategory[];
      severity: ChainThreat['severity'];
    }>;
  };
  guard?: {
    rateLimit?: {
      maxPerMinute?: number;
      maxPerHour?: number;
    };
    circuitBreaker?: {
      failureThreshold?: number;
      resetTimeMs?: number;
    };
  };
  llmJudge?: LLMJudgeConfig;
  audit?: {
    adapter: string;
    path?: string;
    options?: Record<string, unknown>;
  };
  actions?: {
    onSecretDetected?: 'redact' | 'block' | 'warn';
    onChainThreat?: 'log' | 'block' | 'warn';
    onLLMUnsafe?: 'block' | 'warn';
    onPromptInjection?: 'log' | 'block' | 'warn';
    onSensitivePath?: 'log' | 'block' | 'warn';
    onDangerousCommand?: 'log' | 'block' | 'warn';
    onRateLimitExceeded?: 'log' | 'block' | 'warn';
  };
}

// --- OpenClaw Hook types (matching real OpenClaw event system) ---

export interface OpenClawHookEvent {
  type: 'command' | 'session' | 'agent' | 'gateway' | 'message';
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: Record<string, unknown>;
}

export type OpenClawHookHandler = (event: OpenClawHookEvent) => Promise<void>;

// --- OpenClaw Plugin types (matching real OpenClaw plugin API) ---

export interface OpenClawPluginAPI {
  config: Record<string, unknown>;
  registerHttpRoute?(opts: {
    path: string;
    auth: 'gateway' | 'plugin';
    match?: 'exact' | 'prefix';
    handler: (req: unknown, res: unknown) => Promise<boolean>;
  }): void;
}
