import { describe, it, expect, vi } from 'vitest';
import { ProviderRegistry } from '../src/provider/registry.js';
import { SecurityPipeline } from '../src/provider/pipeline.js';
import type {
  ContentScannerProvider,
  ThreatDetectorProvider,
  DecisionEvaluatorProvider,
  AuditReporterProvider,
} from '../src/provider/types.js';
import type { ScanFinding, ChainThreat, AuditEntry } from '../src/types/index.js';

// ---------------------------------------------------------------------------
// Mock providers
// ---------------------------------------------------------------------------

const mockContentScanner: ContentScannerProvider = {
  metadata: { id: 'mock-dlp', name: 'Mock DLP', version: '1.0.0', priority: 'after-builtin' },
  type: 'content-scanner',
  async scan(text) {
    const findings: ScanFinding[] = [];
    if (text.includes('CONFIDENTIAL')) {
      findings.push({
        type: 'custom',
        label: 'DLP: Confidential marker',
        match: 'CONFIDENTIAL',
        redacted: '[DLP_REDACTED]',
        patternId: 'mock-dlp:confidential',
      });
    }
    return findings;
  },
};

const mockThreatDetector: ThreatDetectorProvider = {
  metadata: { id: 'mock-siem', name: 'Mock SIEM', version: '1.0.0' },
  type: 'threat-detector',
  async detect(events, sessionKey) {
    const threats: ChainThreat[] = [];
    if (events.length > 3) {
      threats.push({
        pattern: 'mock-siem:burst',
        description: 'SIEM detected burst activity',
        events: events.slice(-3),
        severity: 'medium',
      });
    }
    return threats;
  },
};

const mockDecisionEvaluator: DecisionEvaluatorProvider = {
  metadata: { id: 'mock-policy', name: 'Mock Policy Engine', version: '1.0.0' },
  type: 'decision-evaluator',
  async evaluate(context) {
    const hasFindings = (context.findings?.length ?? 0) > 0;
    return {
      decision: hasFindings ? 'block' as const : 'allow' as const,
      reasoning: hasFindings ? 'Policy violation detected' : 'No issues',
      confidence: 0.95,
      provider: 'mock-policy',
    };
  },
};

const mockAuditReporter: AuditReporterProvider = {
  metadata: { id: 'mock-splunk', name: 'Mock Splunk', version: '1.0.0' },
  type: 'audit-reporter',
  report: vi.fn(async (_entry: AuditEntry) => {}),
  reportBatch: vi.fn(async (_entries: AuditEntry[]) => {}),
};

// ---------------------------------------------------------------------------
// ProviderRegistry tests
// ---------------------------------------------------------------------------

describe('ProviderRegistry', () => {
  it('registers and retrieves providers', () => {
    const registry = new ProviderRegistry();
    registry.register(mockContentScanner);
    registry.register(mockThreatDetector);

    expect(registry.size).toBe(2);
    expect(registry.has('mock-dlp')).toBe(true);
    expect(registry.get('mock-dlp')).toBe(mockContentScanner);
  });

  it('prevents duplicate registration', () => {
    const registry = new ProviderRegistry();
    registry.register(mockContentScanner);
    expect(() => registry.register(mockContentScanner)).toThrow('already registered');
  });

  it('unregisters providers', () => {
    const registry = new ProviderRegistry();
    registry.register(mockContentScanner);
    expect(registry.unregister('mock-dlp')).toBe(true);
    expect(registry.has('mock-dlp')).toBe(false);
    expect(registry.size).toBe(0);
  });

  it('filters by type', () => {
    const registry = new ProviderRegistry();
    registry.register(mockContentScanner);
    registry.register(mockThreatDetector);
    registry.register(mockDecisionEvaluator);

    expect(registry.getByType('content-scanner')).toHaveLength(1);
    expect(registry.getByType('threat-detector')).toHaveLength(1);
    expect(registry.getByType('decision-evaluator')).toHaveLength(1);
    expect(registry.getByType('audit-reporter')).toHaveLength(0);
  });

  it('sorts by priority', () => {
    const registry = new ProviderRegistry();
    const earlyScanner: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'early', priority: 'before-builtin' },
    };
    const lateScanner: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'late', priority: 'fallback' },
    };

    registry.register(lateScanner);
    registry.register(earlyScanner);

    const ordered = registry.getByType('content-scanner');
    expect(ordered[0].metadata.id).toBe('early');
    expect(ordered[1].metadata.id).toBe('late');
  });

  it('initializes all providers', async () => {
    const initFn = vi.fn(async () => {});
    const provider: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'init-test' },
      initialize: initFn,
    };

    const registry = new ProviderRegistry();
    registry.register(provider);
    await registry.initializeAll({ 'init-test': { apiKey: 'test-key' } });

    expect(initFn).toHaveBeenCalledWith({ apiKey: 'test-key' });
    expect(registry.isInitialized()).toBe(true);

    const health = registry.getHealthStatus();
    expect(health).toHaveLength(1);
    expect(health[0].healthy).toBe(true);
  });

  it('handles initialization failures gracefully', async () => {
    const provider: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'fail-init' },
      initialize: async () => { throw new Error('Connection refused'); },
    };

    const registry = new ProviderRegistry();
    registry.register(provider);
    await registry.initializeAll();

    const health = registry.getHealthStatus();
    expect(health[0].healthy).toBe(false);
    expect(health[0].error).toContain('Connection refused');
  });

  it('runs health checks', async () => {
    const provider: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'health-test' },
      healthCheck: async () => true,
    };

    const registry = new ProviderRegistry();
    registry.register(provider);
    const results = await registry.healthCheckAll();
    expect(results).toHaveLength(1);
    expect(results[0].healthy).toBe(true);
  });

  it('shuts down all providers', async () => {
    const shutdownFn = vi.fn(async () => {});
    const provider: ContentScannerProvider = {
      ...mockContentScanner,
      metadata: { ...mockContentScanner.metadata, id: 'shutdown-test' },
      shutdown: shutdownFn,
    };

    const registry = new ProviderRegistry();
    registry.register(provider);
    await registry.initializeAll();
    await registry.shutdownAll();

    expect(shutdownFn).toHaveBeenCalled();
    expect(registry.isInitialized()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SecurityPipeline tests
// ---------------------------------------------------------------------------

describe('SecurityPipeline', () => {
  it('runs content scanners and merges findings', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockContentScanner);
    const pipeline = new SecurityPipeline(registry);

    const result = await pipeline.runContentScanners('This is CONFIDENTIAL data');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].label).toContain('DLP');
    expect(result.providerSources).toContain('mock-dlp');
  });

  it('returns empty when no providers registered', async () => {
    const registry = new ProviderRegistry();
    const pipeline = new SecurityPipeline(registry);

    const result = await pipeline.runContentScanners('Hello world');
    expect(result.findings).toHaveLength(0);
  });

  it('runs threat detectors', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockThreatDetector);
    const pipeline = new SecurityPipeline(registry);

    const events = [
      { category: 'fs.read' as const, toolName: 'read', timestamp: 1, sessionKey: 's1' },
      { category: 'fs.read' as const, toolName: 'read', timestamp: 2, sessionKey: 's1' },
      { category: 'net.send' as const, toolName: 'fetch', timestamp: 3, sessionKey: 's1' },
      { category: 'net.send' as const, toolName: 'fetch', timestamp: 4, sessionKey: 's1' },
    ];

    const result = await pipeline.runThreatDetectors(events, 's1');
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0].pattern).toBe('mock-siem:burst');
  });

  it('runs decision evaluators and aggregates to block', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockDecisionEvaluator);
    const pipeline = new SecurityPipeline(registry);

    const result = await pipeline.runDecisionEvaluators({
      sessionKey: 's1',
      event: 'outbound:scan',
      findings: [{ type: 'secret', label: 'test', match: 'x', redacted: 'y', patternId: 'z' }],
    });

    expect(result.finalDecision).toBe('block');
    expect(result.decisions).toHaveLength(1);
  });

  it('aggregates to allow when no findings', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockDecisionEvaluator);
    const pipeline = new SecurityPipeline(registry);

    const result = await pipeline.runDecisionEvaluators({
      sessionKey: 's1',
      event: 'outbound:scan',
      findings: [],
    });

    expect(result.finalDecision).toBe('allow');
  });

  it('runs audit reporters', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockAuditReporter);
    const pipeline = new SecurityPipeline(registry);

    const entry: AuditEntry = {
      id: 'test-1',
      timestamp: new Date().toISOString(),
      sessionKey: 's1',
      event: 'test:event',
    };

    await pipeline.runAuditReporters(entry);
    expect(mockAuditReporter.report).toHaveBeenCalledWith(entry);
  });

  it('runs audit reporters in batch', async () => {
    const registry = new ProviderRegistry();
    registry.register(mockAuditReporter);
    const pipeline = new SecurityPipeline(registry);

    const entries: AuditEntry[] = [
      { id: '1', timestamp: new Date().toISOString(), sessionKey: 's1', event: 'a' },
      { id: '2', timestamp: new Date().toISOString(), sessionKey: 's1', event: 'b' },
    ];

    await pipeline.runAuditReportersBatch(entries);
    expect(mockAuditReporter.reportBatch).toHaveBeenCalledWith(entries);
  });

  it('handles provider failures gracefully', async () => {
    const failScanner: ContentScannerProvider = {
      metadata: { id: 'fail-scanner', name: 'Fail', version: '1.0.0' },
      type: 'content-scanner',
      async scan() { throw new Error('API timeout'); },
    };

    const registry = new ProviderRegistry();
    registry.register(failScanner);
    registry.register(mockContentScanner);
    const pipeline = new SecurityPipeline(registry);

    const result = await pipeline.runContentScanners('CONFIDENTIAL');
    expect(result.findings).toHaveLength(1);
    expect(result.providerSources).toContain('mock-dlp');
  });
});
