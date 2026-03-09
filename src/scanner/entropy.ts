/**
 * High-entropy string detector.
 *
 * Detects randomly generated secrets that don't match any fixed-prefix pattern.
 * Uses Shannon entropy as the primary signal, combined with structural heuristics.
 */

export interface EntropyFinding {
  value: string;
  entropy: number;
  charset: 'hex' | 'base64' | 'alphanumeric' | 'mixed';
  start: number;
  end: number;
}

export interface EntropyResult {
  hasFindings: boolean;
  findings: EntropyFinding[];
}

const CHARSETS = {
  hex: /[0-9a-f]/i,
  base64: /[A-Za-z0-9+/=]/,
  alphanumeric: /[A-Za-z0-9]/,
};

const MIN_LENGTH = 16;
const MAX_LENGTH = 256;

const HEX_THRESHOLD = 3.0;
const BASE64_THRESHOLD = 4.2;
const GENERIC_THRESHOLD = 4.5;

const shannonEntropy = (s: string): number => {
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
};

const classifyCharset = (s: string): EntropyFinding['charset'] => {
  if (/^[0-9a-f]+$/i.test(s)) return 'hex';
  if (/^[A-Za-z0-9+/=]+$/.test(s)) return 'base64';
  if (/^[A-Za-z0-9_\-]+$/.test(s)) return 'alphanumeric';
  return 'mixed';
};

const getThreshold = (charset: EntropyFinding['charset']): number => {
  switch (charset) {
    case 'hex': return HEX_THRESHOLD;
    case 'base64': return BASE64_THRESHOLD;
    default: return GENERIC_THRESHOLD;
  }
};

// Tokens that commonly appear in code but aren't secrets
const FALSE_POSITIVE_PATTERNS = [
  /^[0-9a-f]{32}$/i,        // Could be MD5 hash (common, usually not secret)
  /^[01]+$/,                 // Binary string
  /^(.)\1+$/,                // Repeated single character
  /^(..)\1+$/,               // Repeated two-character pattern
  /^(?:undefined|null|true|false|NaN)/i,
  /^[A-Z_]+$/,               // ALL_CAPS_CONSTANTS
  /^(?:https?|ftp|ssh|git):\/\//,
  /^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s/i,
];

const TOKEN_SPLIT = /[\s=:'"`,;(){}\[\]<>|&!@#$%^]+/;

const CONTEXT_KEYWORDS = [
  'key', 'token', 'secret', 'password', 'passwd', 'pwd', 'auth',
  'credential', 'api_key', 'apikey', 'access_key', 'private',
];

export class EntropyDetector {
  private readonly minLength: number;
  private readonly maxLength: number;

  constructor(opts?: { minLength?: number; maxLength?: number }) {
    this.minLength = opts?.minLength ?? MIN_LENGTH;
    this.maxLength = opts?.maxLength ?? MAX_LENGTH;
  }

  detect(text: string): EntropyResult {
    const findings: EntropyFinding[] = [];
    const tokens = text.split(TOKEN_SPLIT);

    let pos = 0;
    for (const token of tokens) {
      const start = text.indexOf(token, pos);
      pos = start + token.length;

      if (token.length < this.minLength || token.length > this.maxLength) continue;
      if (FALSE_POSITIVE_PATTERNS.some(p => p.test(token))) continue;

      const charset = classifyCharset(token);
      const entropy = shannonEntropy(token);
      const threshold = getThreshold(charset);

      if (entropy >= threshold) {
        // Boost confidence if nearby context suggests a secret
        const contextWindow = text.slice(Math.max(0, start - 40), start).toLowerCase();
        const hasContext = CONTEXT_KEYWORDS.some(kw => contextWindow.includes(kw));

        if (hasContext || entropy >= threshold + 0.5) {
          findings.push({
            value: token.slice(0, 40) + (token.length > 40 ? '...' : ''),
            entropy: Math.round(entropy * 100) / 100,
            charset,
            start,
            end: start + token.length,
          });
        }
      }
    }

    return { hasFindings: findings.length > 0, findings };
  }
}

export const detectHighEntropy = (text: string): EntropyResult => {
  const detector = new EntropyDetector();
  return detector.detect(text);
};
