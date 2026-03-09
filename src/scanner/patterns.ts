import type { DetectionPattern } from '../types/index.js';

export const BUILT_IN_PATTERNS: DetectionPattern[] = [
  // --- API Keys & Tokens ---
  {
    id: 'openai-api-key',
    label: 'OpenAI API Key',
    type: 'secret',
    regex: /sk-[A-Za-z0-9]{20,}/g,
  },
  {
    id: 'anthropic-api-key',
    label: 'Anthropic API Key',
    type: 'secret',
    regex: /sk-ant-[A-Za-z0-9\-_]{20,}/g,
  },
  {
    id: 'github-pat',
    label: 'GitHub Personal Access Token',
    type: 'secret',
    regex: /ghp_[A-Za-z0-9]{36,}/g,
  },
  {
    id: 'github-oauth',
    label: 'GitHub OAuth Token',
    type: 'secret',
    regex: /gho_[A-Za-z0-9]{36,}/g,
  },
  {
    id: 'github-fine-grained',
    label: 'GitHub Fine-grained Token',
    type: 'secret',
    regex: /github_pat_[A-Za-z0-9_]{20,}/g,
  },
  {
    id: 'aws-access-key',
    label: 'AWS Access Key ID',
    type: 'secret',
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    id: 'aws-secret-key',
    label: 'AWS Secret Access Key',
    type: 'secret',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[=:\s]+[A-Za-z0-9/+=]{40}/gi,
  },
  {
    id: 'google-api-key',
    label: 'Google API Key',
    type: 'secret',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
  },
  {
    id: 'slack-token',
    label: 'Slack Token',
    type: 'secret',
    regex: /xox[bporas]-[0-9A-Za-z\-]{10,}/g,
  },
  {
    id: 'stripe-key',
    label: 'Stripe API Key',
    type: 'secret',
    regex: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g,
  },
  {
    id: 'bearer-token',
    label: 'Bearer Token',
    type: 'credential',
    regex: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}/gi,
  },
  {
    id: 'generic-api-key',
    label: 'Generic API Key Assignment',
    type: 'secret',
    regex: /(?:api[_-]?key|apikey|api_secret)[=:\s]+['"]?[A-Za-z0-9\-._~+/]{16,}['"]?/gi,
  },

  // --- Private Keys ---
  {
    id: 'private-key-pem',
    label: 'Private Key (PEM)',
    type: 'secret',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    id: 'ssh-private-key',
    label: 'SSH Private Key Header',
    type: 'secret',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
  },

  // --- Connection Strings ---
  {
    id: 'database-url',
    label: 'Database Connection String',
    type: 'credential',
    regex: /(?:mongodb|postgres|mysql|redis|amqp|mssql):\/\/[^\s'"]+/gi,
  },

  // --- PII ---
  {
    id: 'email-address',
    label: 'Email Address',
    type: 'pii',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}\b/gi,
  },
  {
    id: 'phone-number',
    label: 'Phone Number (International)',
    type: 'pii',
    regex: /\+[1-9]\d{6,14}/g,
  },
  {
    id: 'ssn-us',
    label: 'US Social Security Number',
    type: 'pii',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    id: 'credit-card',
    label: 'Credit Card Number',
    type: 'pii',
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
  },
  {
    id: 'ipv4-private',
    label: 'Private IPv4 Address',
    type: 'pii',
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
  },

  // --- Passwords in config/commands ---
  {
    id: 'password-assignment',
    label: 'Password Assignment',
    type: 'credential',
    regex: /(?:password|passwd|pwd)[=:\s]+['"]?[^\s'"]{8,}['"]?/gi,
  },
  {
    id: 'auth-header',
    label: 'Authorization Header',
    type: 'credential',
    regex: /Authorization:\s*(?:Basic|Bearer|Token)\s+[A-Za-z0-9\-._~+/=]{10,}/gi,
  },

  // --- Environment variable leaks ---
  {
    id: 'env-secret-value',
    label: 'Environment Secret Value',
    type: 'secret',
    regex: /(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_KEY)[=]\s*[^\s]{8,}/gi,
  },

  // --- JWT ---
  {
    id: 'jwt-token',
    label: 'JWT Token',
    type: 'credential',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },

  // --- Chinese PII ---
  {
    id: 'china-id-card',
    label: '中国居民身份证号',
    type: 'pii',
    regex: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
  },
  {
    id: 'china-phone',
    label: '中国手机号',
    type: 'pii',
    regex: /\b1[3-9]\d{9}\b/g,
  },
  {
    id: 'china-bank-card',
    label: '中国银行卡号',
    type: 'pii',
    regex: /\b(?:62|4|5[1-5])\d{14,18}\b/g,
  },
  {
    id: 'china-passport',
    label: '中国护照号',
    type: 'pii',
    regex: /\b[EeGg]\d{8}\b/g,
  },
  {
    id: 'china-unified-social-credit',
    label: '统一社会信用代码',
    type: 'pii',
    regex: /\b[0-9A-HJ-NP-RTUW-Y]{2}\d{6}[0-9A-HJ-NP-RTUW-Y]{10}\b/g,
  },

  // --- Korea / Japan PII ---
  {
    id: 'korea-rrn',
    label: 'Korean Resident Registration Number',
    type: 'pii',
    regex: /\b\d{6}-[1-4]\d{6}\b/g,
  },
  {
    id: 'japan-my-number',
    label: 'Japan My Number',
    type: 'pii',
    regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
  },
];
