import { describe, it, expect } from 'vitest';
import { ContentScanner, scanContent } from '../src/scanner/content-scanner.js';

describe('ContentScanner', () => {
  const scanner = new ContentScanner();

  describe('API key detection', () => {
    it('detects OpenAI API keys', () => {
      const result = scanner.scan('My key is sk-abc123def456ghi789jkl012mno345pq');
      expect(result.hasFindings).toBe(true);
      expect(result.findings[0].label).toBe('OpenAI API Key');
      expect(result.redactedText).not.toContain('sk-abc123');
    });

    it('detects GitHub PATs', () => {
      const result = scanner.scan('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'GitHub Personal Access Token')).toBe(true);
    });

    it('detects AWS access keys', () => {
      const result = scanner.scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'AWS Access Key ID')).toBe(true);
    });

    it('detects Stripe keys', () => {
      const result = scanner.scan('sk_test_abcdefghijklmnopqrstuvwxyz');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Stripe API Key')).toBe(true);
    });

    it('detects Anthropic API keys', () => {
      const result = scanner.scan('key: sk-ant-api03-abcdefghijklmnopqrst');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Anthropic API Key')).toBe(true);
    });
  });

  describe('PII detection', () => {
    it('detects email addresses', () => {
      const result = scanner.scan('Contact me at user@example.com');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Email Address')).toBe(true);
    });

    it('detects international phone numbers', () => {
      const result = scanner.scan('Call me at +15551234567');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Phone Number (International)')).toBe(true);
    });

    it('detects US SSNs', () => {
      const result = scanner.scan('SSN: 123-45-6789');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'US Social Security Number')).toBe(true);
    });

    it('detects credit card numbers', () => {
      const result = scanner.scan('Card: 4111-1111-1111-1111');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Credit Card Number')).toBe(true);
    });
  });

  describe('credential detection', () => {
    it('detects Bearer tokens', () => {
      const result = scanner.scan('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.type === 'credential')).toBe(true);
    });

    it('detects database connection strings', () => {
      const result = scanner.scan('DATABASE_URL=postgres://user:pass@host:5432/db');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Database Connection String')).toBe(true);
    });

    it('detects PEM private keys', () => {
      const result = scanner.scan('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.label === 'Private Key (PEM)')).toBe(true);
    });
  });

  describe('redaction correctness', () => {
    it('does not corrupt text with overlapping patterns', () => {
      const text = 'Authorization: Bearer sk-abc123def456ghi789jkl012mno345pq';
      const result = scanner.scan(text);
      expect(result.hasFindings).toBe(true);
      expect(result.redactedText).not.toContain('sk-abc123');
      // Ensure no broken fragments remain
      expect(result.redactedText).not.toMatch(/sk-[A-Za-z0-9]/);
    });

    it('handles multiple secrets in one text', () => {
      const text = 'key1=sk-abc123def456ghi789jkl012mno345pq and key2=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
      const result = scanner.scan(text);
      expect(result.findings.length).toBeGreaterThanOrEqual(2);
      expect(result.redactedText).not.toContain('sk-abc123');
      expect(result.redactedText).not.toContain('ghp_ABCDEF');
    });

    it('returns original text unchanged when no findings', () => {
      const text = 'This is perfectly safe text with no secrets.';
      const result = scanner.scan(text);
      expect(result.hasFindings).toBe(false);
      expect(result.redactedText).toBe(text);
    });
  });

  describe('configuration', () => {
    it('respects disabled patterns', () => {
      const customScanner = new ContentScanner({
        scanner: { disabledPatterns: ['email-address'] },
      });
      const result = customScanner.scan('Contact: user@example.com');
      expect(result.findings.some(f => f.patternId === 'email-address')).toBe(false);
    });

    it('supports custom patterns', () => {
      const customScanner = new ContentScanner({
        scanner: {
          extraPatterns: [{
            id: 'custom-token',
            label: 'Custom Token',
            type: 'secret',
            pattern: 'myapp_[A-Za-z0-9]{16}',
            flags: 'g',
          }],
        },
      });
      const result = customScanner.scan('token: myapp_abcdefgh12345678');
      expect(result.hasFindings).toBe(true);
      expect(result.findings.some(f => f.patternId === 'custom-token')).toBe(true);
    });
  });

  describe('scanContent convenience function', () => {
    it('works as a one-liner', () => {
      const result = scanContent('key: sk-abc123def456ghi789jkl012mno345pq');
      expect(result.hasFindings).toBe(true);
    });
  });

  describe('scanObject', () => {
    it('recursively scans object values', () => {
      const result = scanner.scanObject({
        message: 'here is sk-abc123def456ghi789jkl012mno345pq',
        nested: { deep: 'and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' },
      });
      expect(result.hasFindings).toBe(true);
      expect(result.allFindings.length).toBeGreaterThanOrEqual(2);
    });
  });
});
