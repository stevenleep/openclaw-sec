/**
 * Prompt Injection detector.
 *
 * Detects attempts to manipulate AI agent behavior through injected instructions
 * in user messages, tool outputs, or any text the agent processes.
 */

export interface PromptInjectionResult {
  isInjection: boolean;
  score: number;
  triggers: PromptInjectionTrigger[];
}

export interface PromptInjectionTrigger {
  pattern: string;
  category: 'role_override' | 'instruction_injection' | 'context_manipulation'
    | 'output_manipulation' | 'delimiter_attack' | 'encoding_attack';
  severity: 'low' | 'medium' | 'high' | 'critical';
  matched: string;
}

interface InjectionPattern {
  id: string;
  regex: RegExp;
  category: PromptInjectionTrigger['category'];
  severity: PromptInjectionTrigger['severity'];
  weight: number;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // --- Role override attempts ---
  {
    id: 'ignore-previous',
    regex: /ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?|directions?)/gi,
    category: 'role_override',
    severity: 'critical',
    weight: 40,
  },
  {
    id: 'forget-instructions',
    regex: /forget\s+(?:all\s+)?(?:your|the|previous|prior)\s+(?:instructions?|rules?|prompts?|context)/gi,
    category: 'role_override',
    severity: 'critical',
    weight: 40,
  },
  {
    id: 'you-are-now',
    regex: /you\s+are\s+now\s+(?:a|an|the|my)\s+/gi,
    category: 'role_override',
    severity: 'high',
    weight: 30,
  },
  {
    id: 'act-as',
    regex: /(?:act|behave|respond|function)\s+as\s+(?:if\s+you\s+(?:are|were)|a|an|the)\s+/gi,
    category: 'role_override',
    severity: 'high',
    weight: 25,
  },
  {
    id: 'new-role',
    regex: /(?:your|my)\s+(?:new|updated|real|actual|true)\s+(?:role|purpose|task|mission|objective)\s+is/gi,
    category: 'role_override',
    severity: 'critical',
    weight: 35,
  },
  {
    id: 'disregard',
    regex: /disregard\s+(?:all|any|the|your)?\s*(?:previous|prior|above|earlier|original)?\s*(?:instructions?|rules?|constraints?|guidelines?|safety)/gi,
    category: 'role_override',
    severity: 'critical',
    weight: 40,
  },
  {
    id: 'override-safety',
    regex: /(?:override|bypass|disable|turn\s+off|ignore)\s+(?:your\s+)?(?:safety|security|content|ethical)\s*(?:filter|guard|check|measure|policy|constraint|rule)/gi,
    category: 'role_override',
    severity: 'critical',
    weight: 45,
  },

  // --- Instruction injection ---
  {
    id: 'system-prompt-inject',
    regex: /\[?\s*(?:SYSTEM|ADMIN|ROOT|DEVELOPER|OPERATOR)\s*(?:PROMPT|MESSAGE|INSTRUCTION|OVERRIDE|COMMAND)\s*\]?\s*[:：]/gi,
    category: 'instruction_injection',
    severity: 'critical',
    weight: 45,
  },
  {
    id: 'hidden-instruction',
    regex: /(?:hidden|secret|internal|private)\s+(?:instruction|command|directive|order|task)\s*[:：]/gi,
    category: 'instruction_injection',
    severity: 'high',
    weight: 30,
  },
  {
    id: 'do-not-tell',
    regex: /(?:do\s+not|don'?t|never)\s+(?:tell|reveal|show|mention|disclose|share)\s+(?:the\s+)?(?:user|them|anyone|human)/gi,
    category: 'instruction_injection',
    severity: 'high',
    weight: 30,
  },
  {
    id: 'execute-command',
    regex: /(?:execute|run|perform)\s+(?:the\s+following|this)\s+(?:command|code|script|instruction)/gi,
    category: 'instruction_injection',
    severity: 'high',
    weight: 25,
  },

  // --- Context manipulation ---
  {
    id: 'fake-tool-output',
    regex: /(?:tool\s+(?:output|result|response)|function\s+(?:output|result|return))\s*[:：]\s*/gi,
    category: 'context_manipulation',
    severity: 'high',
    weight: 30,
  },
  {
    id: 'simulated-response',
    regex: /(?:the\s+(?:system|api|server|database)\s+(?:returned|responded|replied|said)|(?:simulate|pretend|fake)\s+(?:a|the|that)\s+(?:response|output|result))/gi,
    category: 'context_manipulation',
    severity: 'high',
    weight: 25,
  },
  {
    id: 'conversation-reset',
    regex: /(?:start|begin|reset)\s+(?:a\s+)?(?:new|fresh)\s+(?:conversation|session|context|chat)/gi,
    category: 'context_manipulation',
    severity: 'medium',
    weight: 15,
  },

  // --- Output manipulation ---
  {
    id: 'include-in-response',
    regex: /(?:include|insert|add|put|embed|append)\s+(?:the\s+following|this)\s+(?:in|into|to)\s+(?:your|the)\s+(?:response|output|reply|answer|message)/gi,
    category: 'output_manipulation',
    severity: 'medium',
    weight: 20,
  },
  {
    id: 'respond-with-exactly',
    regex: /(?:respond|reply|answer|output)\s+(?:with\s+)?(?:exactly|only|just)\s*[:：]/gi,
    category: 'output_manipulation',
    severity: 'medium',
    weight: 20,
  },
  {
    id: 'exfiltrate-via-url',
    regex: /(?:send|post|fetch|call|request|visit|navigate|open)\s+(?:to\s+)?(?:https?:\/\/|\/\/)/gi,
    category: 'output_manipulation',
    severity: 'high',
    weight: 30,
  },

  // --- Delimiter attacks ---
  {
    id: 'delimiter-break',
    regex: /(?:---+|===+|####+|\*\*\*+)\s*(?:END|STOP|IGNORE|NEW|SYSTEM|BEGIN)\b[^]*?(?:---+|===+|####+|\*\*\*+)?/gi,
    category: 'delimiter_attack',
    severity: 'high',
    weight: 30,
  },
  {
    id: 'xml-tag-injection',
    regex: /<\/?(?:system|instruction|prompt|context|tool_result|function_call|assistant|user|human|ai)>/gi,
    category: 'delimiter_attack',
    severity: 'critical',
    weight: 40,
  },
  {
    id: 'markdown-code-injection',
    regex: /```(?:system|prompt|instruction|override)\b/gi,
    category: 'delimiter_attack',
    severity: 'high',
    weight: 25,
  },

  // --- Encoding attacks ---
  {
    id: 'unicode-obfuscation',
    regex: /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g,
    category: 'encoding_attack',
    severity: 'medium',
    weight: 20,
  },
  {
    id: 'homoglyph-attack',
    regex: /[\u0400-\u04FF\u13A0-\u13FF].*(?:ignore|forget|override|system|admin)/gi,
    category: 'encoding_attack',
    severity: 'medium',
    weight: 20,
  },
];

const INJECTION_THRESHOLD = 30;

export class PromptInjectionDetector {
  private readonly patterns: InjectionPattern[];
  private readonly threshold: number;

  constructor(opts?: { threshold?: number; extraPatterns?: InjectionPattern[] }) {
    this.patterns = [...INJECTION_PATTERNS, ...(opts?.extraPatterns ?? [])];
    this.threshold = opts?.threshold ?? INJECTION_THRESHOLD;
  }

  detect(text: string): PromptInjectionResult {
    const triggers: PromptInjectionTrigger[] = [];
    let score = 0;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        triggers.push({
          pattern: pattern.id,
          category: pattern.category,
          severity: pattern.severity,
          matched: match[0].slice(0, 100),
        });
        score += pattern.weight;
        if (!regex.global) break;
      }
    }

    return {
      isInjection: score >= this.threshold,
      score: Math.min(score, 100),
      triggers,
    };
  }
}

export const detectPromptInjection = (text: string): PromptInjectionResult => {
  const detector = new PromptInjectionDetector();
  return detector.detect(text);
};
