import type {
  ChainThreat,
  LLMJudgeConfig,
  LLMJudgeDecision,
  LLMJudgeResult,
  ScanFinding,
} from '../types/index.js';

const SYSTEM_PROMPT = `You are a security auditor for an AI Agent framework.
Your job is to evaluate whether detected security signals represent a real threat.

You receive:
- Content scan findings (detected secrets, PII, credentials)
- Chain analysis threats (suspicious tool invocation sequences)
- Context about the current session

Respond with EXACTLY one of:
- SAFE — False positive or benign activity
- UNSAFE — Real security threat, should be blocked
- NEEDS_REVIEW — Ambiguous, requires human review

Follow with a brief reasoning (1-2 sentences).

Format:
DECISION: <SAFE|UNSAFE|NEEDS_REVIEW>
REASON: <your reasoning>`;

interface JudgeContext {
  scanFindings?: ScanFinding[];
  chainThreats?: ChainThreat[];
  sessionKey?: string;
  additionalContext?: string;
}

const buildPrompt = (ctx: JudgeContext): string => {
  const parts: string[] = [];

  if (ctx.scanFindings?.length) {
    parts.push('## Content Scan Findings');
    for (const f of ctx.scanFindings) {
      parts.push(`- [${f.type}] ${f.label}: matched pattern "${f.patternId}"`);
    }
  }

  if (ctx.chainThreats?.length) {
    parts.push('## Chain Analysis Threats');
    for (const t of ctx.chainThreats) {
      parts.push(`- [${t.severity}] ${t.pattern}: ${t.description}`);
      parts.push(`  Events: ${t.events.map(e => e.category).join(' → ')}`);
    }
  }

  if (ctx.sessionKey) {
    parts.push(`\nSession: ${ctx.sessionKey}`);
  }
  if (ctx.additionalContext) {
    parts.push(`\nContext: ${ctx.additionalContext}`);
  }

  return parts.join('\n');
};

const parseResponse = (text: string): LLMJudgeResult => {
  const decisionMatch = text.match(/DECISION:\s*(SAFE|UNSAFE|NEEDS_REVIEW)/i);
  const reasonMatch = text.match(/REASON:\s*(.+)/is);

  const raw = decisionMatch?.[1]?.toUpperCase() ?? 'NEEDS_REVIEW';
  const validDecisions: LLMJudgeDecision[] = ['SAFE', 'UNSAFE', 'NEEDS_REVIEW'];
  const decision = validDecisions.includes(raw as LLMJudgeDecision)
    ? (raw as LLMJudgeDecision)
    : 'NEEDS_REVIEW';

  return {
    decision,
    reasoning: reasonMatch?.[1]?.trim() ?? 'No reasoning provided',
  };
};

export class LLMJudge {
  private readonly config: LLMJudgeConfig;

  constructor(config: LLMJudgeConfig) {
    this.config = config;
  }

  async evaluate(ctx: JudgeContext): Promise<LLMJudgeResult> {
    const messages = [
      { role: 'system' as const, content: SYSTEM_PROMPT },
      { role: 'user' as const, content: buildPrompt(ctx) },
    ];

    try {
      const { url, headers, body } = this.buildRequest(messages);
      const timeout = this.config.timeout ?? 10_000;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errorText = await response.text();
        return {
          decision: 'NEEDS_REVIEW',
          reasoning: `LLM API error (${response.status}): ${errorText}`,
        };
      }

      const data = await response.json() as Record<string, unknown>;
      return parseResponse(this.extractContent(data));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        decision: 'NEEDS_REVIEW',
        reasoning: `LLM Judge unavailable: ${message}`,
      };
    }
  }

  private buildRequest(messages: Array<{ role: string; content: string }>): {
    url: string;
    headers: Record<string, string>;
    body: Record<string, unknown>;
  } {
    const body = { model: this.config.model, messages, max_tokens: 256, temperature: 0 };

    const apiKey = this.config.apiKey
      ?? (this.config.provider === 'anthropic'
        ? process.env.ANTHROPIC_API_KEY
        : process.env.OPENAI_API_KEY)
      ?? '';

    if (this.config.provider === 'anthropic') {
      return {
        url: this.config.baseUrl ?? 'https://api.anthropic.com/v1/messages',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: { ...body, messages: messages.filter(m => m.role !== 'system') },
      };
    }

    return {
      url: this.config.baseUrl ?? 'https://api.openai.com/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body,
    };
  }

  private extractContent(data: Record<string, unknown>): string {
    const choices = data.choices as Array<{ message?: { content?: string } }> | undefined;
    if (choices?.[0]?.message?.content) return choices[0].message.content;

    const content = data.content as Array<{ text?: string }> | undefined;
    if (content?.[0]?.text) return content[0].text;

    return JSON.stringify(data);
  }
}
