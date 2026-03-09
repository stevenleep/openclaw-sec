/**
 * Sensitive path and command protection.
 *
 * Identifies access to dangerous file paths and evaluates command risk levels.
 */

export type PathRiskLevel = 'safe' | 'caution' | 'dangerous' | 'critical';

export interface PathCheckResult {
  path: string;
  risk: PathRiskLevel;
  reason: string;
  category: string;
}

export interface CommandRiskResult {
  command: string;
  risk: PathRiskLevel;
  reasons: string[];
  destructive: boolean;
  requiresElevation: boolean;
  networkAccess: boolean;
}

// --- Sensitive path patterns ---

interface PathRule {
  pattern: RegExp;
  risk: PathRiskLevel;
  reason: string;
  category: string;
}

const PATH_RULES: PathRule[] = [
  // Critical: secrets and keys
  { pattern: /(?:^|\/)\.(env|env\.\w+)$/i, risk: 'critical', reason: 'Environment file with secrets', category: 'secrets' },
  { pattern: /(?:^|\/)\.ssh\b/i, risk: 'critical', reason: 'SSH key directory', category: 'secrets' },
  { pattern: /(?:^|\/)\.gnupg\b/i, risk: 'critical', reason: 'GPG key directory', category: 'secrets' },
  { pattern: /(?:^|\/)\.aws\b/i, risk: 'critical', reason: 'AWS credentials directory', category: 'secrets' },
  { pattern: /(?:^|\/)\.gcloud\b/i, risk: 'critical', reason: 'Google Cloud credentials', category: 'secrets' },
  { pattern: /(?:^|\/)\.azure\b/i, risk: 'critical', reason: 'Azure credentials', category: 'secrets' },
  { pattern: /(?:^|\/)\.docker\/config\.json$/i, risk: 'critical', reason: 'Docker registry credentials', category: 'secrets' },
  { pattern: /(?:^|\/)\.npmrc$/i, risk: 'critical', reason: 'npm credentials (may contain auth tokens)', category: 'secrets' },
  { pattern: /(?:^|\/)\.pypirc$/i, risk: 'critical', reason: 'PyPI credentials', category: 'secrets' },
  { pattern: /(?:^|\/)\.netrc$/i, risk: 'critical', reason: 'Network credentials', category: 'secrets' },
  { pattern: /(?:^|\/)credentials?(?:\.json|\.yaml|\.yml|\.xml|\.ini|\.conf)?$/i, risk: 'critical', reason: 'Credentials file', category: 'secrets' },
  { pattern: /\.(?:pem|key|pfx|p12|jks)$/i, risk: 'critical', reason: 'Private key / certificate file', category: 'secrets' },
  { pattern: /(?:^|\/)\.kube\/config$/i, risk: 'critical', reason: 'Kubernetes credentials', category: 'secrets' },
  { pattern: /(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?$/i, risk: 'critical', reason: 'SSH key file', category: 'secrets' },

  // Dangerous: system files
  { pattern: /^\/etc\/shadow$/i, risk: 'critical', reason: 'System password hashes', category: 'system' },
  { pattern: /^\/etc\/passwd$/i, risk: 'dangerous', reason: 'System user list', category: 'system' },
  { pattern: /^\/etc\/sudoers/i, risk: 'critical', reason: 'Sudo configuration', category: 'system' },
  { pattern: /^\/etc\/(?:ssl|pki)\b/i, risk: 'dangerous', reason: 'System SSL certificates', category: 'system' },
  { pattern: /^\/(?:proc|sys|dev)\//i, risk: 'dangerous', reason: 'System virtual filesystem', category: 'system' },
  { pattern: /(?:^|\/)\/var\/log\b/i, risk: 'caution', reason: 'System logs (may contain sensitive data)', category: 'system' },

  // Dangerous: browser/app data
  { pattern: /(?:^|\/)(?:\.chrome|\.mozilla|\.firefox|\.safari)\b/i, risk: 'dangerous', reason: 'Browser data directory', category: 'browser' },
  { pattern: /(?:Cookies|Login Data|Web Data)$/i, risk: 'critical', reason: 'Browser credential storage', category: 'browser' },
  { pattern: /(?:^|\/)Keychain\b/i, risk: 'critical', reason: 'macOS Keychain', category: 'secrets' },

  // Caution: git
  { pattern: /(?:^|\/)\.git\/config$/i, risk: 'caution', reason: 'Git config (may contain credentials)', category: 'vcs' },
  { pattern: /(?:^|\/)\.git-credentials$/i, risk: 'critical', reason: 'Git stored credentials', category: 'secrets' },

  // Caution: databases
  { pattern: /\.(?:sqlite|sqlite3|db|mdb)$/i, risk: 'caution', reason: 'Database file', category: 'data' },
  { pattern: /(?:^|\/)\.(?:mysql_history|psql_history|mongo_history)$/i, risk: 'dangerous', reason: 'Database command history', category: 'data' },
];

// --- Dangerous command patterns ---

interface CommandRule {
  pattern: RegExp;
  risk: PathRiskLevel;
  reason: string;
  destructive?: boolean;
  requiresElevation?: boolean;
  networkAccess?: boolean;
}

const COMMAND_RULES: CommandRule[] = [
  // Critical: destructive
  { pattern: /\brm\s+(?:-[a-z]*)?(?:r|R)(?:[a-z]*)?\s+(?:\/|~|\$HOME)/i, risk: 'critical', reason: 'Recursive deletion from root or home', destructive: true },
  { pattern: /\bmkfs\b/i, risk: 'critical', reason: 'Filesystem formatting', destructive: true },
  { pattern: /\bdd\s+(?:.*\s)?if=/i, risk: 'critical', reason: 'Raw disk write', destructive: true },
  { pattern: />\s*\/dev\/(?:sd|hd|nvme|vd)[a-z]/i, risk: 'critical', reason: 'Direct device write', destructive: true },
  { pattern: /:()\s*{\s*:\|\s*:&\s*}\s*;?\s*:/i, risk: 'critical', reason: 'Fork bomb', destructive: true },

  // Critical: remote code execution
  { pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh|python|perl|ruby)/i, risk: 'critical', reason: 'Pipe remote content to shell', networkAccess: true },
  { pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh|python|perl|ruby)/i, risk: 'critical', reason: 'Pipe remote content to shell', networkAccess: true },
  { pattern: /\beval\s*\(?\s*\$\(/i, risk: 'critical', reason: 'Dynamic code evaluation', destructive: true },

  // Dangerous: system control
  { pattern: /\bshutdown\b/i, risk: 'dangerous', reason: 'System shutdown' },
  { pattern: /\breboot\b/i, risk: 'dangerous', reason: 'System reboot' },
  { pattern: /\binit\s+[06]\b/i, risk: 'dangerous', reason: 'System runlevel change' },
  { pattern: /\bchmod\s+(?:.*\s)?(?:777|a\+rwx)\b/i, risk: 'dangerous', reason: 'Overly permissive file permissions' },
  { pattern: /\bchown\s+(?:.*\s)?root\b/i, risk: 'dangerous', reason: 'Ownership change to root', requiresElevation: true },
  { pattern: /\bkillall\b/i, risk: 'dangerous', reason: 'Kill all processes by name' },
  { pattern: /\bkill\s+-9\s+(?:1|-1)\b/i, risk: 'critical', reason: 'Kill init or all processes', destructive: true },

  // Dangerous: privilege escalation
  { pattern: /\bsudo\b/i, risk: 'dangerous', reason: 'Privilege escalation via sudo', requiresElevation: true },
  { pattern: /\bdoas\b/i, risk: 'dangerous', reason: 'Privilege escalation via doas', requiresElevation: true },
  { pattern: /\bsu\s+-/i, risk: 'dangerous', reason: 'Switch to root user', requiresElevation: true },

  // Dangerous: network exfiltration
  { pattern: /\bcurl\b.*-[a-z]*d\b/i, risk: 'caution', reason: 'curl sending data', networkAccess: true },
  { pattern: /\bcurl\b.*--upload-file\b/i, risk: 'dangerous', reason: 'curl file upload', networkAccess: true },
  { pattern: /\bnc\s+(?:-[a-z]*\s+)*\S+\s+\d+/i, risk: 'dangerous', reason: 'Netcat connection (potential exfiltration)', networkAccess: true },
  { pattern: /\bscp\b/i, risk: 'caution', reason: 'Remote file copy', networkAccess: true },
  { pattern: /\brsync\b.*(?:\S+:)/i, risk: 'caution', reason: 'Remote sync', networkAccess: true },

  // Caution: database destructive
  { pattern: /\bDROP\s+(?:DATABASE|TABLE|SCHEMA)\b/i, risk: 'critical', reason: 'Database drop', destructive: true },
  { pattern: /\bTRUNCATE\s+TABLE\b/i, risk: 'dangerous', reason: 'Table truncation', destructive: true },
  { pattern: /\bDELETE\s+FROM\s+\w+\s*(?:;|$)/i, risk: 'dangerous', reason: 'DELETE without WHERE clause', destructive: true },
];

export class SensitivePathGuard {
  checkPath(filePath: string): PathCheckResult {
    for (const rule of PATH_RULES) {
      if (rule.pattern.test(filePath)) {
        return {
          path: filePath,
          risk: rule.risk,
          reason: rule.reason,
          category: rule.category,
        };
      }
    }
    return { path: filePath, risk: 'safe', reason: '', category: '' };
  }

  checkPaths(paths: string[]): PathCheckResult[] {
    return paths.map(p => this.checkPath(p)).filter(r => r.risk !== 'safe');
  }

  evaluateCommand(command: string): CommandRiskResult {
    const reasons: string[] = [];
    let maxRisk: PathRiskLevel = 'safe';
    let destructive = false;
    let requiresElevation = false;
    let networkAccess = false;

    const riskOrder: Record<PathRiskLevel, number> = { safe: 0, caution: 1, dangerous: 2, critical: 3 };

    for (const rule of COMMAND_RULES) {
      if (rule.pattern.test(command)) {
        reasons.push(rule.reason);
        if (riskOrder[rule.risk] > riskOrder[maxRisk]) maxRisk = rule.risk;
        if (rule.destructive) destructive = true;
        if (rule.requiresElevation) requiresElevation = true;
        if (rule.networkAccess) networkAccess = true;
      }
    }

    return { command, risk: maxRisk, reasons, destructive, requiresElevation, networkAccess };
  }
}

export const checkSensitivePath = (filePath: string): PathCheckResult => {
  const guard = new SensitivePathGuard();
  return guard.checkPath(filePath);
};

export const evaluateCommand = (command: string): CommandRiskResult => {
  const guard = new SensitivePathGuard();
  return guard.evaluateCommand(command);
};
