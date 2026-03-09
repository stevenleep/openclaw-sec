import type { DetectionPattern, ScanFinding, ScanResult, SecurityConfig } from '../types/index.js';
import { BUILT_IN_PATTERNS } from './patterns.js';
import { EncodingDecoder } from './encoding.js';
import { EntropyDetector } from './entropy.js';
import { PromptInjectionDetector } from './prompt-injection.js';
import type { PromptInjectionResult } from './prompt-injection.js';
import type { EntropyResult } from './entropy.js';

export interface ContentScannerOptions {
  enableEncodingDefense?: boolean;
  enableEntropyDetection?: boolean;
  enablePromptInjection?: boolean;
  allowlist?: string[];
  allowlistPatterns?: RegExp[];
}

export class ContentScanner {
  private readonly patterns: DetectionPattern[];
  private readonly allowlist: Set<string>;
  private readonly allowlistPatterns: RegExp[];
  private readonly encodingDecoder: EncodingDecoder | null;
  private readonly entropyDetector: EntropyDetector | null;
  private readonly injectionDetector: PromptInjectionDetector | null;

  constructor(config?: SecurityConfig, options?: ContentScannerOptions) {
    const disabled = new Set(config?.scanner?.disabledPatterns ?? []);
    this.patterns = BUILT_IN_PATTERNS.filter(p => !disabled.has(p.id));

    if (config?.scanner?.extraPatterns) {
      for (const extra of config.scanner.extraPatterns) {
        this.patterns.push({
          id: extra.id,
          label: extra.label,
          type: extra.type,
          regex: new RegExp(extra.pattern, extra.flags ?? 'gi'),
          redactWith: extra.redactWith,
        });
      }
    }

    this.allowlist = new Set(config?.scanner?.allowlist ?? options?.allowlist ?? []);
    this.allowlistPatterns = options?.allowlistPatterns ?? [];

    const enableEncoding = options?.enableEncodingDefense ?? config?.scanner?.enableEncodingDefense ?? true;
    const enableEntropy = options?.enableEntropyDetection ?? config?.scanner?.enableEntropyDetection ?? true;
    const enableInjection = options?.enablePromptInjection ?? config?.scanner?.enablePromptInjection ?? true;

    this.encodingDecoder = enableEncoding ? new EncodingDecoder() : null;
    this.entropyDetector = enableEntropy ? new EntropyDetector() : null;
    this.injectionDetector = enableInjection ? new PromptInjectionDetector() : null;
  }

  scan(text: string, field?: string): ScanResult {
    const findings: ScanFinding[] = [];
    let redactedText = text;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      const matches: Array<{ index: number; text: string }> = [];
      let match: RegExpExecArray | null;

      while ((match = regex.exec(redactedText)) !== null) {
        matches.push({ index: match.index, text: match[0] });
        if (!regex.global) break;
      }

      for (let i = matches.length - 1; i >= 0; i--) {
        const m = matches[i];

        if (this.isAllowlisted(m.text)) continue;

        const redactLabel = pattern.redactWith ?? `[${pattern.type.toUpperCase()}_REDACTED]`;

        findings.push({
          type: pattern.type,
          label: pattern.label,
          match: m.text,
          redacted: redactLabel,
          field,
          patternId: pattern.id,
        });

        redactedText =
          redactedText.slice(0, m.index) +
          redactLabel +
          redactedText.slice(m.index + m.text.length);
      }
    }

    // Encoding bypass defense: decode & re-scan
    if (this.encodingDecoder) {
      const decoded = this.encodingDecoder.decode(text);
      for (const layer of decoded.decodedLayers) {
        const innerResult = this.scanPlainPatterns(layer.decoded, field);
        for (const f of innerResult) {
          f.label = `[${layer.encoding.toUpperCase()} encoded] ${f.label}`;
          f.patternId = `encoded:${layer.encoding}:${f.patternId}`;
        }
        findings.push(...innerResult);
      }
    }

    // High-entropy detection
    if (this.entropyDetector) {
      const entropyResult = this.entropyDetector.detect(text);
      for (const ef of entropyResult.findings) {
        if (this.isAllowlisted(ef.value)) continue;

        const alreadyCaptured = findings.some(
          f => f.match.includes(ef.value.slice(0, 20)) || ef.value.includes(f.match.slice(0, 20)),
        );
        if (alreadyCaptured) continue;

        findings.push({
          type: 'secret',
          label: `High entropy ${ef.charset} string (${ef.entropy} bits/char)`,
          match: ef.value,
          redacted: '[HIGH_ENTROPY_REDACTED]',
          field,
          patternId: `entropy:${ef.charset}`,
        });
      }
    }

    return {
      hasFindings: findings.length > 0,
      findings,
      redactedText,
      originalText: text,
    };
  }

  detectInjection(text: string): PromptInjectionResult | null {
    return this.injectionDetector?.detect(text) ?? null;
  }

  detectEntropy(text: string): EntropyResult | null {
    return this.entropyDetector?.detect(text) ?? null;
  }

  scanObject(obj: Record<string, unknown>): {
    hasFindings: boolean;
    allFindings: ScanFinding[];
    redactedObj: Record<string, unknown>;
  } {
    const allFindings: ScanFinding[] = [];
    const redactedObj = { ...obj };

    const scanValue = (value: unknown, path: string): unknown => {
      if (typeof value === 'string') {
        const result = this.scan(value, path);
        allFindings.push(...result.findings);
        return result.redactedText;
      }
      if (Array.isArray(value)) {
        return value.map((item, i) => scanValue(item, `${path}[${i}]`));
      }
      if (value && typeof value === 'object') {
        const scannedObj: Record<string, unknown> = {};
        for (const [key, val] of Object.entries(value)) {
          scannedObj[key] = scanValue(val, `${path}.${key}`);
        }
        return scannedObj;
      }
      return value;
    };

    for (const [key, value] of Object.entries(obj)) {
      redactedObj[key] = scanValue(value, key);
    }

    return {
      hasFindings: allFindings.length > 0,
      allFindings,
      redactedObj,
    };
  }

  private isAllowlisted(value: string): boolean {
    if (this.allowlist.has(value)) return true;
    return this.allowlistPatterns.some(p => p.test(value));
  }

  private scanPlainPatterns(text: string, field?: string): ScanFinding[] {
    const findings: ScanFinding[] = [];
    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) !== null) {
        if (this.isAllowlisted(match[0])) continue;
        const redactLabel = pattern.redactWith ?? `[${pattern.type.toUpperCase()}_REDACTED]`;
        findings.push({
          type: pattern.type,
          label: pattern.label,
          match: match[0],
          redacted: redactLabel,
          field,
          patternId: pattern.id,
        });
        if (!regex.global) break;
      }
    }
    return findings;
  }
}

export const scanContent = (text: string, config?: SecurityConfig): ScanResult => {
  const scanner = new ContentScanner(config);
  return scanner.scan(text);
};
