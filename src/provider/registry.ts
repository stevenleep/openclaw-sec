/**
 * ProviderRegistry — central registration and lifecycle management for
 * third-party security providers.
 *
 * Usage:
 *   const registry = new ProviderRegistry();
 *   registry.register(myVirusTotalProvider);
 *   registry.register(mySplunkReporter);
 *   await registry.initializeAll({ virusTotal: { apiKey: '...' } });
 *
 *   // Later, in the pipeline:
 *   const scanners = registry.getByType('content-scanner');
 *   const threats  = registry.getByType('threat-detector');
 */

import type {
  SecurityProvider,
  SecurityProviderType,
  ContentScannerProvider,
  ThreatDetectorProvider,
  DecisionEvaluatorProvider,
  AuditReporterProvider,
  ProviderPriority,
} from './types.js';

export interface ProviderHealth {
  id: string;
  type: SecurityProviderType;
  healthy: boolean;
  lastChecked: number;
  error?: string;
}

export class ProviderRegistry {
  private readonly providers = new Map<string, SecurityProvider>();
  private readonly healthStatus = new Map<string, ProviderHealth>();
  private initialized = false;

  register(provider: SecurityProvider): void {
    const { id } = provider.metadata;
    if (this.providers.has(id)) {
      throw new Error(`Provider "${id}" is already registered`);
    }
    this.providers.set(id, provider);
  }

  unregister(id: string): boolean {
    return this.providers.delete(id);
  }

  get(id: string): SecurityProvider | undefined {
    return this.providers.get(id);
  }

  has(id: string): boolean {
    return this.providers.has(id);
  }

  getAll(): SecurityProvider[] {
    return [...this.providers.values()];
  }

  /**
   * Returns providers of a specific type, sorted by priority:
   *  before-builtin → (no priority / after-builtin) → fallback
   */
  getByType<T extends SecurityProviderType>(type: T): ProviderByType<T>[] {
    const result: SecurityProvider[] = [];
    for (const provider of this.providers.values()) {
      if (provider.type === type) result.push(provider);
    }
    return result.sort(comparePriority) as ProviderByType<T>[];
  }

  /**
   * Initialize all registered providers.
   * `configs` is a map from provider ID to its configuration object.
   */
  async initializeAll(configs?: Record<string, Record<string, unknown>>): Promise<void> {
    const promises = [...this.providers.entries()].map(async ([id, provider]) => {
      try {
        const providerConfig = configs?.[id] ?? {};
        await provider.initialize?.(providerConfig);
        this.healthStatus.set(id, {
          id,
          type: provider.type,
          healthy: true,
          lastChecked: Date.now(),
        });
      } catch (err) {
        this.healthStatus.set(id, {
          id,
          type: provider.type,
          healthy: false,
          lastChecked: Date.now(),
          error: err instanceof Error ? err.message : String(err),
        });
      }
    });

    await Promise.all(promises);
    this.initialized = true;
  }

  async shutdownAll(): Promise<void> {
    const promises = [...this.providers.values()].map(async (provider) => {
      try { await provider.shutdown?.(); } catch { /* best-effort */ }
    });
    await Promise.all(promises);
    this.initialized = false;
  }

  async healthCheckAll(): Promise<ProviderHealth[]> {
    const results: ProviderHealth[] = [];

    const promises = [...this.providers.entries()].map(async ([id, provider]) => {
      const health: ProviderHealth = {
        id,
        type: provider.type,
        healthy: true,
        lastChecked: Date.now(),
      };

      try {
        if (provider.healthCheck) {
          health.healthy = await provider.healthCheck();
        }
      } catch (err) {
        health.healthy = false;
        health.error = err instanceof Error ? err.message : String(err);
      }

      this.healthStatus.set(id, health);
      results.push(health);
    });

    await Promise.all(promises);
    return results;
  }

  getHealthStatus(): ProviderHealth[] {
    return [...this.healthStatus.values()];
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  get size(): number {
    return this.providers.size;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ProviderByType<T extends SecurityProviderType> =
  T extends 'content-scanner' ? ContentScannerProvider :
  T extends 'threat-detector' ? ThreatDetectorProvider :
  T extends 'decision-evaluator' ? DecisionEvaluatorProvider :
  T extends 'audit-reporter' ? AuditReporterProvider :
  never;

const PRIORITY_ORDER: Record<ProviderPriority, number> = {
  'before-builtin': 0,
  'after-builtin': 1,
  'fallback': 2,
};

const comparePriority = (a: SecurityProvider, b: SecurityProvider): number => {
  const pa = PRIORITY_ORDER[a.metadata.priority ?? 'after-builtin'];
  const pb = PRIORITY_ORDER[b.metadata.priority ?? 'after-builtin'];
  return pa - pb;
};
