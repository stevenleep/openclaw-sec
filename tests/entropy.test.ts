import { describe, it, expect } from 'vitest';
import { EntropyDetector, detectHighEntropy } from '../src/scanner/entropy.js';

describe('EntropyDetector', () => {
  const detector = new EntropyDetector();

  it('detects high entropy random strings with keyword context', () => {
    const secret = 'xK9mQ2vR7nP4wL6jB3hT8cY1fA5sD0gE';
    const text = `api_key = "${secret}"`;
    const result = detector.detect(text);
    expect(result.hasFindings).toBe(true);
  });

  it('does not flag normal English words', () => {
    const text = 'This is a normal English sentence with regular words.';
    const result = detector.detect(text);
    expect(result.hasFindings).toBe(false);
  });

  it('does not flag ALL_CAPS_CONSTANTS', () => {
    const text = 'MAX_RETRY_COUNT DATABASE_CONNECTION_POOL';
    const result = detector.detect(text);
    expect(result.hasFindings).toBe(false);
  });

  it('does not flag common URL patterns', () => {
    const text = 'https://example.com/api/v1/users';
    const result = detector.detect(text);
    expect(result.hasFindings).toBe(false);
  });

  it('convenience function works', () => {
    const secret = 'xK9mQ2vR7nP4wL6jB3hT8cY1fA5sD0gEq';
    const result = detectHighEntropy(`secret = ${secret}`);
    expect(result.hasFindings).toBe(true);
  });
});
