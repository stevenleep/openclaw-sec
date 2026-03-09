import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { AuditLogger } from '../src/audit/audit-logger.js';
import { LocalFileAdapter } from '../src/audit/adapters/local-file-adapter.js';

describe('AuditLogger', () => {
  let logger: AuditLogger;
  let tempFile: string;

  beforeEach(() => {
    tempFile = path.join(os.tmpdir(), `openclaw-sec-test-${Date.now()}.jsonl`);
    logger = new AuditLogger();
    logger.addAdapter(new LocalFileAdapter(tempFile));
  });

  it('writes audit entries to file', async () => {
    await logger.log({
      sessionKey: 'test-session',
      event: 'test:event',
      metadata: { foo: 'bar' },
    });

    await logger.flush();

    const content = fs.readFileSync(tempFile, 'utf-8').trim();
    const entry = JSON.parse(content);

    expect(entry.sessionKey).toBe('test-session');
    expect(entry.event).toBe('test:event');
    expect(entry.id).toBeDefined();
    expect(entry.timestamp).toBeDefined();
  });

  it('includes scan results when provided', async () => {
    await logger.log({
      sessionKey: 'test-session',
      event: 'outbound:secret_detected',
      scanResult: {
        hasFindings: true,
        findings: [
          { type: 'secret', label: 'OpenAI API Key', match: 'sk-xxx', redacted: '[REDACTED]', patternId: 'openai-api-key' },
        ],
        redactedText: '[REDACTED]',
        originalText: 'sk-xxx',
      },
    });

    await logger.flush();

    const content = fs.readFileSync(tempFile, 'utf-8').trim();
    const entry = JSON.parse(content);

    expect(entry.scanResult).toBeDefined();
    expect(entry.scanResult.findingCount).toBe(1);
    expect(entry.scanResult.redacted).toBe(true);
    // Original secret value must NOT appear in audit log
    expect(content).not.toContain('sk-xxx');
  });

  it('queries entries by sessionKey', async () => {
    await logger.log({ sessionKey: 'a', event: 'test' });
    await logger.log({ sessionKey: 'b', event: 'test' });
    await logger.log({ sessionKey: 'a', event: 'test2' });
    await logger.flush();

    const results = await logger.query({ sessionKey: 'a' });
    expect(results.length).toBe(2);
  });

  it('closes gracefully', async () => {
    await logger.log({ sessionKey: 'test', event: 'close-test' });
    await logger.close();

    const content = fs.readFileSync(tempFile, 'utf-8').trim();
    expect(content).toContain('close-test');
  });
});
