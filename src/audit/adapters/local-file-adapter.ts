import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditEntry, AuditFilter, AuditStorageAdapter } from '../../types/index.js';

export class LocalFileAdapter implements AuditStorageAdapter {
  private readonly filePath: string;
  private writeStream: fs.WriteStream | null = null;

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    this.ensureDirectory();
  }

  async write(entry: AuditEntry): Promise<void> {
    const stream = this.getWriteStream();
    const line = JSON.stringify(entry) + '\n';

    return new Promise((resolve, reject) => {
      const canContinue = stream.write(line, 'utf-8');
      if (canContinue) {
        resolve();
      } else {
        stream.once('drain', resolve);
        stream.once('error', reject);
      }
    });
  }

  async query(filter: AuditFilter): Promise<AuditEntry[]> {
    if (!fs.existsSync(this.filePath)) return [];

    const content = fs.readFileSync(this.filePath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    let entries: AuditEntry[] = lines.map(line => JSON.parse(line) as AuditEntry);

    if (filter.sessionKey) entries = entries.filter(e => e.sessionKey === filter.sessionKey);
    if (filter.event) entries = entries.filter(e => e.event === filter.event);
    if (filter.from) entries = entries.filter(e => e.timestamp >= filter.from!);
    if (filter.to) entries = entries.filter(e => e.timestamp <= filter.to!);
    if (filter.limit) entries = entries.slice(-filter.limit);

    return entries;
  }

  async flush(): Promise<void> {
    return new Promise((resolve) => {
      if (this.writeStream) {
        this.writeStream.once('finish', resolve);
        this.writeStream.end();
        this.writeStream = null;
      } else {
        resolve();
      }
    });
  }

  async close(): Promise<void> {
    await this.flush();
  }

  private getWriteStream(): fs.WriteStream {
    if (!this.writeStream) {
      this.writeStream = fs.createWriteStream(this.filePath, { flags: 'a', encoding: 'utf-8' });
    }
    return this.writeStream;
  }

  private ensureDirectory(): void {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }
}
