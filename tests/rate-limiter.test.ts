import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RateLimiter, CircuitBreaker } from '../src/guard/rate-limiter.js';

describe('RateLimiter', () => {
  it('allows requests within limit', () => {
    const limiter = new RateLimiter({ maxPerMinute: 10, maxPerHour: 100 });
    for (let i = 0; i < 10; i++) {
      const result = limiter.consume('session-1');
      expect(result.allowed).toBe(true);
    }
  });

  it('blocks requests exceeding per-minute limit', () => {
    const limiter = new RateLimiter({ maxPerMinute: 3, maxPerHour: 100 });
    limiter.consume('session-1');
    limiter.consume('session-1');
    limiter.consume('session-1');
    const result = limiter.consume('session-1');
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('per minute');
  });

  it('isolates rate limits between keys', () => {
    const limiter = new RateLimiter({ maxPerMinute: 2, maxPerHour: 100 });
    limiter.consume('session-1');
    limiter.consume('session-1');
    const result = limiter.consume('session-2');
    expect(result.allowed).toBe(true);
  });

  it('check() does not consume', () => {
    const limiter = new RateLimiter({ maxPerMinute: 1, maxPerHour: 100 });
    const r1 = limiter.check('session-1');
    expect(r1.allowed).toBe(true);
    const r2 = limiter.check('session-1');
    expect(r2.allowed).toBe(true);
    limiter.consume('session-1');
    const r3 = limiter.consume('session-1');
    expect(r3.allowed).toBe(false);
  });

  it('reset clears the bucket', () => {
    const limiter = new RateLimiter({ maxPerMinute: 1, maxPerHour: 100 });
    limiter.consume('session-1');
    expect(limiter.consume('session-1').allowed).toBe(false);
    limiter.reset('session-1');
    expect(limiter.consume('session-1').allowed).toBe(true);
  });
});

describe('CircuitBreaker', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('starts in closed state (allows proceeding)', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    expect(cb.canProceed('s1')).toBe(true);
  });

  it('trips to open after threshold failures', () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, resetTimeMs: 10000 });
    cb.recordFailure('s1');
    cb.recordFailure('s1');
    expect(cb.canProceed('s1')).toBe(true);
    cb.recordFailure('s1');
    expect(cb.canProceed('s1')).toBe(false);
    expect(cb.getState('s1').state).toBe('open');
  });

  it('transitions to half-open after reset time', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, resetTimeMs: 5000 });
    cb.recordFailure('s1');
    cb.recordFailure('s1');
    expect(cb.canProceed('s1')).toBe(false);

    vi.advanceTimersByTime(5001);
    expect(cb.canProceed('s1')).toBe(true);
    expect(cb.getState('s1').state).toBe('half-open');
  });

  it('closes again after successful half-open attempts', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, resetTimeMs: 5000, halfOpenMaxAttempts: 2 });
    cb.recordFailure('s1');
    cb.recordFailure('s1');

    vi.advanceTimersByTime(5001);
    cb.recordSuccess('s1');
    cb.recordSuccess('s1');
    expect(cb.getState('s1').state).toBe('closed');
    expect(cb.canProceed('s1')).toBe(true);
  });

  it('re-opens on failure during half-open', () => {
    const cb = new CircuitBreaker({ failureThreshold: 2, resetTimeMs: 5000 });
    cb.recordFailure('s1');
    cb.recordFailure('s1');

    vi.advanceTimersByTime(5001);
    expect(cb.canProceed('s1')).toBe(true);
    cb.recordFailure('s1');
    expect(cb.getState('s1').state).toBe('open');
    expect(cb.canProceed('s1')).toBe(false);
  });

  it('reset clears the circuit', () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 });
    cb.recordFailure('s1');
    expect(cb.canProceed('s1')).toBe(false);
    cb.reset('s1');
    expect(cb.canProceed('s1')).toBe(true);
  });
});
