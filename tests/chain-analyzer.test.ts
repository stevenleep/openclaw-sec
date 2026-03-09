import { describe, it, expect, beforeEach } from 'vitest';
import { ChainAnalyzer, analyzeChain } from '../src/chain/chain-analyzer.js';
import type { ToolEvent } from '../src/types/index.js';

describe('ChainAnalyzer', () => {
  let analyzer: ChainAnalyzer;

  beforeEach(() => {
    analyzer = new ChainAnalyzer();
  });

  const makeEvent = (
    category: ToolEvent['category'],
    sessionKey = 'sess1',
    timestamp?: number,
  ): ToolEvent => ({
    category,
    toolName: category,
    timestamp: timestamp ?? Date.now(),
    sessionKey,
  });

  describe('file exfiltration detection', () => {
    it('detects fs.read → net.send chain', () => {
      const now = Date.now();
      analyzer.track(makeEvent('fs.read', 'sess1', now));
      const result = analyzer.track(makeEvent('net.send', 'sess1', now + 1000));

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats.some(t => t.pattern === 'file-exfil-net')).toBe(true);
      expect(result.highestSeverity).toBe('high');
    });

    it('detects fs.read → message.send chain', () => {
      const now = Date.now();
      analyzer.track(makeEvent('fs.read', 'sess1', now));
      const result = analyzer.track(makeEvent('message.send', 'sess1', now + 1000));

      expect(result.threats.some(t => t.pattern === 'file-exfil-msg')).toBe(true);
    });
  });

  describe('secret exfiltration detection', () => {
    it('detects env.read → net.send chain (critical)', () => {
      const now = Date.now();
      analyzer.track(makeEvent('env.read', 'sess1', now));
      const result = analyzer.track(makeEvent('net.send', 'sess1', now + 1000));

      expect(result.threats.some(t => t.pattern === 'env-exfil-net')).toBe(true);
      expect(result.highestSeverity).toBe('critical');
    });

    it('detects env.read → message.send chain (critical)', () => {
      const now = Date.now();
      analyzer.track(makeEvent('env.read', 'sess1', now));
      const result = analyzer.track(makeEvent('message.send', 'sess1', now + 1000));

      expect(result.threats.some(t => t.pattern === 'env-exfil-msg')).toBe(true);
      expect(result.highestSeverity).toBe('critical');
    });
  });

  describe('session isolation', () => {
    it('does not cross-contaminate sessions', () => {
      const now = Date.now();
      analyzer.track(makeEvent('env.read', 'sess1', now));
      const result = analyzer.track(makeEvent('net.send', 'sess2', now + 1000));

      expect(result.threats.length).toBe(0);
    });
  });

  describe('time window', () => {
    it('ignores events outside the window', () => {
      const shortWindowAnalyzer = new ChainAnalyzer({ chain: { windowMs: 5000 } });
      const now = Date.now();

      shortWindowAnalyzer.track(makeEvent('env.read', 'sess1', now - 10_000));
      const result = shortWindowAnalyzer.track(makeEvent('net.send', 'sess1', now));

      expect(result.threats.filter(t => t.pattern === 'env-exfil-net').length).toBe(0);
    });
  });

  describe('frequency anomaly', () => {
    it('detects high-frequency reads', () => {
      const now = Date.now();
      let result;
      for (let i = 0; i < 16; i++) {
        result = analyzer.track(makeEvent('fs.read', 'sess1', now + i * 100));
      }
      expect(result!.threats.some(t => t.pattern === 'high-frequency-reads')).toBe(true);
    });
  });

  describe('clearSession', () => {
    it('clears session history', () => {
      const now = Date.now();
      analyzer.track(makeEvent('env.read', 'sess1', now));
      analyzer.clearSession('sess1');
      const result = analyzer.track(makeEvent('net.send', 'sess1', now + 1000));

      expect(result.threats.filter(t => t.pattern === 'env-exfil-net').length).toBe(0);
    });
  });

  describe('analyzeChain convenience function', () => {
    it('analyzes a batch of events', () => {
      const now = Date.now();
      const events: ToolEvent[] = [
        makeEvent('env.read', 'sess1', now),
        makeEvent('net.send', 'sess1', now + 1000),
      ];
      const result = analyzeChain(events, 'sess1');
      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('custom threat patterns', () => {
    it('supports custom patterns via config', () => {
      const customAnalyzer = new ChainAnalyzer({
        chain: {
          customThreats: [{
            pattern: 'custom-read-exec',
            description: 'Custom: read then exec',
            sequence: ['fs.read', 'shell.exec'],
            severity: 'medium',
          }],
        },
      });

      const now = Date.now();
      customAnalyzer.track(makeEvent('fs.read', 'sess1', now));
      const result = customAnalyzer.track(makeEvent('shell.exec', 'sess1', now + 1000));

      expect(result.threats.some(t => t.pattern === 'custom-read-exec')).toBe(true);
    });
  });
});
