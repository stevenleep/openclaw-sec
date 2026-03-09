import * as fs from 'node:fs';
import * as path from 'node:path';
import yaml from 'js-yaml';
import type { SecurityConfig } from '../types/index.js';

export const loadConfigFromFile = (configPath: string): SecurityConfig => {
  const absolutePath = path.resolve(configPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Security config file not found: ${absolutePath}`);
  }

  const content = fs.readFileSync(absolutePath, 'utf-8');
  const ext = path.extname(absolutePath).toLowerCase();

  if (ext === '.yaml' || ext === '.yml') {
    return yaml.load(content) as SecurityConfig;
  }
  if (ext === '.json') {
    return JSON.parse(content) as SecurityConfig;
  }

  throw new Error(`Unsupported config file format: ${ext}. Use .yaml, .yml, or .json`);
};

export const resolveConfig = (
  configPath?: string,
  overrides?: Partial<SecurityConfig>,
): SecurityConfig => {
  const defaults: SecurityConfig = {
    audit: { adapter: 'local', path: './logs/openclaw-sec-audit.jsonl' },
    actions: {
      onSecretDetected: 'redact',
      onChainThreat: 'warn',
      onLLMUnsafe: 'warn',
    },
  };

  let config = { ...defaults };

  if (configPath) {
    const fileConfig = loadConfigFromFile(configPath);
    config = { ...config, ...fileConfig };
  }

  if (overrides) {
    config = { ...config, ...overrides };
  }

  return config;
};
