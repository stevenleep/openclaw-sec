/**
 * Rate limiter and circuit breaker for security operations.
 *
 * Prevents abuse by limiting the rate of operations per session/globally,
 * and automatically trips a circuit breaker when too many security violations
 * occur in a short window.
 */

export interface RateLimitConfig {
  maxPerMinute?: number;
  maxPerHour?: number;
  maxConcurrent?: number;
}

export interface CircuitBreakerConfig {
  failureThreshold?: number;
  resetTimeMs?: number;
  halfOpenMaxAttempts?: number;
}

export type CircuitState = 'closed' | 'open' | 'half-open';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
  reason?: string;
}

export interface CircuitBreakerState {
  state: CircuitState;
  failures: number;
  lastFailure?: number;
  lastTrip?: number;
}

interface BucketEntry {
  timestamps: number[];
}

export class RateLimiter {
  private readonly maxPerMinute: number;
  private readonly maxPerHour: number;
  private readonly buckets = new Map<string, BucketEntry>();

  constructor(config?: RateLimitConfig) {
    this.maxPerMinute = config?.maxPerMinute ?? 60;
    this.maxPerHour = config?.maxPerHour ?? 600;
  }

  check(key: string): RateLimitResult {
    const now = Date.now();
    const bucket = this.getBucket(key);
    this.pruneTimestamps(bucket, now);

    const lastMinute = bucket.timestamps.filter(t => t > now - 60_000).length;
    const lastHour = bucket.timestamps.length;

    if (lastMinute >= this.maxPerMinute) {
      const oldestInWindow = bucket.timestamps.find(t => t > now - 60_000)!;
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: oldestInWindow + 60_000 - now,
        reason: `Rate limit exceeded: ${lastMinute}/${this.maxPerMinute} per minute`,
      };
    }

    if (lastHour >= this.maxPerHour) {
      const oldestInWindow = bucket.timestamps[0];
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: oldestInWindow + 3_600_000 - now,
        reason: `Rate limit exceeded: ${lastHour}/${this.maxPerHour} per hour`,
      };
    }

    return {
      allowed: true,
      remaining: Math.min(this.maxPerMinute - lastMinute, this.maxPerHour - lastHour),
    };
  }

  record(key: string): void {
    const bucket = this.getBucket(key);
    bucket.timestamps.push(Date.now());
  }

  consume(key: string): RateLimitResult {
    const result = this.check(key);
    if (result.allowed) {
      this.record(key);
    }
    return result;
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }

  private getBucket(key: string): BucketEntry {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { timestamps: [] };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  private pruneTimestamps(bucket: BucketEntry, now: number): void {
    const hourAgo = now - 3_600_000;
    bucket.timestamps = bucket.timestamps.filter(t => t > hourAgo);
  }
}

export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly resetTimeMs: number;
  private readonly halfOpenMaxAttempts: number;
  private readonly circuits = new Map<string, {
    state: CircuitState;
    failures: number;
    lastFailure: number;
    lastTrip: number;
    halfOpenAttempts: number;
  }>();

  constructor(config?: CircuitBreakerConfig) {
    this.failureThreshold = config?.failureThreshold ?? 5;
    this.resetTimeMs = config?.resetTimeMs ?? 300_000;
    this.halfOpenMaxAttempts = config?.halfOpenMaxAttempts ?? 2;
  }

  canProceed(key: string): boolean {
    const circuit = this.circuits.get(key);
    if (!circuit) return true;

    this.maybeTransitionToHalfOpen(circuit);

    switch (circuit.state) {
      case 'closed':
        return true;
      case 'open':
        return false;
      case 'half-open':
        return circuit.halfOpenAttempts < this.halfOpenMaxAttempts;
    }
  }

  recordFailure(key: string): CircuitBreakerState {
    const now = Date.now();
    let circuit = this.circuits.get(key);

    if (!circuit) {
      circuit = { state: 'closed', failures: 0, lastFailure: 0, lastTrip: 0, halfOpenAttempts: 0 };
      this.circuits.set(key, circuit);
    }

    circuit.failures++;
    circuit.lastFailure = now;

    if (circuit.state === 'half-open') {
      circuit.state = 'open';
      circuit.lastTrip = now;
    } else if (circuit.failures >= this.failureThreshold) {
      circuit.state = 'open';
      circuit.lastTrip = now;
    }

    return {
      state: circuit.state,
      failures: circuit.failures,
      lastFailure: circuit.lastFailure,
      lastTrip: circuit.lastTrip || undefined,
    };
  }

  recordSuccess(key: string): void {
    const circuit = this.circuits.get(key);
    if (!circuit) return;

    this.maybeTransitionToHalfOpen(circuit);

    if (circuit.state === 'half-open') {
      circuit.halfOpenAttempts++;
      if (circuit.halfOpenAttempts >= this.halfOpenMaxAttempts) {
        circuit.state = 'closed';
        circuit.failures = 0;
        circuit.halfOpenAttempts = 0;
      }
    } else if (circuit.state === 'closed') {
      if (circuit.failures > 0) circuit.failures--;
    }
  }

  getState(key: string): CircuitBreakerState {
    const circuit = this.circuits.get(key);
    if (!circuit) return { state: 'closed', failures: 0 };

    this.maybeTransitionToHalfOpen(circuit);

    return {
      state: circuit.state,
      failures: circuit.failures,
      lastFailure: circuit.lastFailure || undefined,
      lastTrip: circuit.lastTrip || undefined,
    };
  }

  reset(key: string): void {
    this.circuits.delete(key);
  }

  private maybeTransitionToHalfOpen(circuit: {
    state: CircuitState;
    lastTrip: number;
    halfOpenAttempts: number;
  }): void {
    if (circuit.state === 'open' && Date.now() - circuit.lastTrip >= this.resetTimeMs) {
      circuit.state = 'half-open';
      circuit.halfOpenAttempts = 0;
    }
  }
}
