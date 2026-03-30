import type {
  CheckDefinition,
  ProjectCheck,
  LineCheck,
  LineMatch,
  Finding,
  ScanContext,
  FileEntry,
} from '../types.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Test whether a relative path matches any of the given glob-like suffixes. */
function matchesAny(relativePath: string, patterns: string[]): boolean {
  const lower = relativePath.toLowerCase();
  const base = lower.split('/').pop() ?? '';
  for (const pattern of patterns) {
    if (pattern.startsWith('*')) {
      // *.ext match
      if (base.endsWith(pattern.slice(1))) return true;
    } else {
      // exact basename match
      if (base === pattern.toLowerCase()) return true;
    }
  }
  return false;
}

/** Collect files from ctx.files whose relative path matches patterns. */
function findMatchingFiles(
  ctx: ScanContext,
  patterns: string[],
): FileEntry[] {
  const results: FileEntry[] = [];
  for (const [relPath, entry] of ctx.files) {
    if (matchesAny(relPath, patterns)) {
      results.push(entry);
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// GIT001 - Missing .gitignore
// ---------------------------------------------------------------------------

const GIT001: ProjectCheck = {
  level: 'project',
  id: 'GIT001',
  name: 'Missing .gitignore',
  description: 'Checks that the project has a .gitignore file to prevent accidental commits of secrets and temp files.',
  category: 'git',
  defaultSeverity: 'high',
  async analyze(ctx) {
    // Check if .gitignore exists via content or files map
    if (ctx.gitignoreContent !== null) return [];
    if (ctx.files.has('.gitignore')) return [];

    return [
      {
        checkId: 'GIT001',
        title: 'Missing .gitignore',
        message:
          'Your project has no .gitignore file. This means every file could accidentally get committed, including secrets and temp files.',
        severity: 'high',
        category: 'git',
        fix: 'Create a .gitignore file in your project root.',
        fixCode: [
          '# Dependencies',
          'node_modules/',
          '',
          '# Environment variables',
          '.env',
          '.env.*',
          '!.env.example',
          '',
          '# Build output',
          'dist/',
          'build/',
          '',
          '# OS files',
          '.DS_Store',
          'Thumbs.db',
          '',
          '# IDE files',
          '.idea/',
          '.vscode/',
          '*.swp',
          '*.swo',
          '',
          '# Logs',
          '*.log',
          '',
          '# Secrets & keys',
          '*.pem',
          '*.key',
          '*.pfx',
          '*.p12',
          'id_rsa',
          'id_ed25519',
          '',
          '# Databases',
          '*.sqlite',
          '*.sqlite3',
          '*.db',
        ].join('\n'),
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// GIT002 - .env Not in .gitignore
// ---------------------------------------------------------------------------

const GIT002: ProjectCheck = {
  level: 'project',
  id: 'GIT002',
  name: '.env Not in .gitignore',
  description: 'Checks that .env files are listed in .gitignore to prevent leaking secrets.',
  category: 'git',
  defaultSeverity: 'critical',
  async analyze(ctx) {
    const findings: Finding[] = [];

    // Find ALL .env files dynamically, not just a hardcoded list
    const envFiles: string[] = [];
    for (const relPath of ctx.files.keys()) {
      const base = relPath.split('/').pop() ?? '';
      if (/^\.env(?:\.|$)/.test(base) && !base.endsWith('.example') && !base.endsWith('.template') && !base.endsWith('.sample')) {
        envFiles.push(relPath);
      }
    }

    for (const envFile of envFiles) {
      // Only flag if the file actually exists
      const entry = ctx.files.get(envFile);
      if (!entry) continue;

      // Only flag if it's NOT gitignored
      if (ctx.isGitIgnored(envFile)) continue;

      findings.push({
        checkId: 'GIT002',
        title: '.env Not in .gitignore',
        message:
          `Your ${envFile} file isn't in .gitignore. This file typically has all your passwords and API keys.`,
        severity: 'critical',
        category: 'git',
        location: { filePath: envFile, startLine: 1 },
        fix: 'Add `.env*` to .gitignore and `!.env.example`',
        fixCode: '# Add to .gitignore\n.env*\n!.env.example',
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// GIT003 - Sensitive Files Not Gitignored
// ---------------------------------------------------------------------------

const SENSITIVE_PATTERNS = [
  { pattern: '*.pem', description: 'PEM certificate/key file' },
  { pattern: '*.key', description: 'Private key file' },
  { pattern: '*.pfx', description: 'PKCS#12 certificate bundle' },
  { pattern: '*.p12', description: 'PKCS#12 certificate bundle' },
  { pattern: 'id_rsa', description: 'SSH private key' },
  { pattern: 'id_ed25519', description: 'SSH private key' },
  { pattern: '*.ppk', description: 'PuTTY private key' },
  { pattern: 'credentials.json', description: 'Credentials file (likely cloud provider)' },
  { pattern: '*.keystore', description: 'Java/Android keystore' },
  { pattern: '.pypirc', description: 'PyPI credentials file' },
];

// firebase-adminsdk*.json needs special matching
function isFirebaseAdminSdk(basename: string): boolean {
  return basename.startsWith('firebase-adminsdk') && basename.endsWith('.json');
}

const GIT003: ProjectCheck = {
  level: 'project',
  id: 'GIT003',
  name: 'Sensitive Files Not Gitignored',
  description: 'Checks that private keys, certificates, and credential files are gitignored.',
  category: 'git',
  defaultSeverity: 'high',
  async analyze(ctx) {
    const findings: Finding[] = [];

    for (const [relPath, entry] of ctx.files) {
      if (ctx.isGitIgnored(relPath)) continue;

      let description: string | null = null;

      // Check fixed patterns
      for (const sens of SENSITIVE_PATTERNS) {
        if (matchesAny(relPath, [sens.pattern])) {
          description = sens.description;
          break;
        }
      }

      // Check firebase-adminsdk*.json
      if (!description && isFirebaseAdminSdk(entry.basename)) {
        description = 'Firebase Admin SDK service account key';
      }

      // Path-based matches for credential directories
      if (!description) {
        if (relPath.includes('.docker/') && entry.basename === 'config.json') {
          description = 'Docker registry credentials file';
        } else if (relPath.includes('.kube/') && entry.basename === 'config') {
          description = 'Kubernetes cluster credentials';
        } else if (relPath.includes('.aws/') && entry.basename === 'credentials') {
          description = 'AWS credentials file';
        }
      }

      if (description) {
        findings.push({
          checkId: 'GIT003',
          title: 'Sensitive File Not Gitignored',
          message:
            `${relPath} is a ${description} and is not in .gitignore. ` +
            'If committed, anyone with repo access can read your private credentials.',
          severity: 'high',
          category: 'git',
          location: { filePath: relPath, startLine: 1 },
          fix: `Add \`${entry.basename}\` (or a matching pattern) to .gitignore.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// GIT004 - SQLite Database in Repo
// ---------------------------------------------------------------------------

const DB_PATTERNS = ['*.sqlite', '*.sqlite3', '*.db'];

const GIT004: ProjectCheck = {
  level: 'project',
  id: 'GIT004',
  name: 'SQLite Database in Repo',
  description: 'Checks for database files that may contain sensitive data.',
  category: 'git',
  defaultSeverity: 'high',
  async analyze(ctx) {
    const matched = findMatchingFiles(ctx, DB_PATTERNS);
    return matched.map((entry) => ({
      checkId: 'GIT004',
      title: 'SQLite Database in Repo',
      message:
        `A database file is in your project (${entry.relativePath}). It likely contains user data or other sensitive information.`,
      severity: 'high' as const,
      category: 'git' as const,
      location: { filePath: entry.relativePath, startLine: 1 },
      fix: `Add \`${entry.basename}\` to .gitignore and remove it from tracking with \`git rm --cached ${entry.relativePath}\`.`,
    }));
  },
};

// ---------------------------------------------------------------------------
// GIT005 - Source Maps Present
// ---------------------------------------------------------------------------

const SOURCE_MAP_DIRS = ['public/', 'dist/', 'build/', '.next/'];

const GIT005: ProjectCheck = {
  level: 'project',
  id: 'GIT005',
  name: 'Source Maps Present',
  description: 'Checks for source map files in public-facing directories.',
  category: 'git',
  defaultSeverity: 'medium',
  async analyze(ctx) {
    const findings: Finding[] = [];

    for (const [relPath, entry] of ctx.files) {
      // Must be a .map file (js.map or css.map)
      if (!relPath.endsWith('.js.map') && !relPath.endsWith('.css.map')) continue;

      // Must be in one of the flagged directories
      const inFlaggedDir = SOURCE_MAP_DIRS.some((dir) => relPath.startsWith(dir));
      if (!inFlaggedDir) continue;

      findings.push({
        checkId: 'GIT005',
        title: 'Source Maps in Public Directory',
        message:
          `Source maps let anyone see your original source code. Found: ${relPath}`,
        severity: 'medium',
        category: 'git',
        location: { filePath: relPath, startLine: 1 },
        fix: `Remove ${entry.basename} from your deployed output, or add \`*.map\` to .gitignore.`,
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// GIT006 - Docker Secrets Exposed
// ---------------------------------------------------------------------------

const DOCKER_FILENAMES = new Set([
  'docker-compose.yml',
  'docker-compose.yaml',
  'dockerfile',
]);

const DOCKER_SECRET_PATTERN = /(?:password|secret|token|api_key)\s*[:=]\s*[^${\s].+/gi;

const GIT006: LineCheck = {
  level: 'line',
  id: 'GIT006',
  name: 'Docker Secrets Exposed',
  description: 'Detects hard-coded secrets in Docker Compose and Dockerfile files.',
  category: 'git',
  defaultSeverity: 'high',
  appliesTo: ['yml', 'yaml'],
  pattern: DOCKER_SECRET_PATTERN,
  analyze(match: LineMatch, ctx: ScanContext): Finding | null {
    // Only apply to docker-related files
    const base = match.file.basename.toLowerCase();
    if (!DOCKER_FILENAMES.has(base)) return null;

    // Skip if the value uses variable substitution like ${VAR}
    const matchedText = match.regexMatch[0];
    if (/\$\{/.test(matchedText)) return null;

    const lines = match.file.lines;
    const { snippet, contextBefore, contextAfter } = lines
      ? extractSnippet(lines, match.lineNumber, ctx.config.contextLines)
      : { snippet: match.line, contextBefore: [] as string[], contextAfter: [] as string[] };

    return {
      checkId: 'GIT006',
      title: 'Hard-coded Secret in Docker Config',
      message:
        `A secret value appears to be hard-coded in ${match.file.relativePath}. ` +
        'Use environment variable substitution (e.g. ${SECRET_VAR}) instead.',
      severity: 'high',
      category: 'git',
      location: {
        filePath: match.file.relativePath,
        startLine: match.lineNumber,
      },
      snippet,
      contextBefore,
      contextAfter,
      fix: 'Replace the hard-coded value with an environment variable reference like `${SECRET_VAR}`.',
    };
  },
};

// ---------------------------------------------------------------------------
// GIT007 - .npmrc with Auth Token
// ---------------------------------------------------------------------------

const NPMRC_AUTH_PATTERN = /_authToken\s*=\s*[A-Za-z0-9_-]{20,}/g;

const GIT007: LineCheck = {
  level: 'line',
  id: 'GIT007',
  name: '.npmrc Auth Token',
  description: 'Detects npm auth tokens stored in .npmrc files.',
  category: 'git',
  defaultSeverity: 'critical',
  appliesTo: ['npmrc'],
  pattern: NPMRC_AUTH_PATTERN,
  analyze(match: LineMatch, ctx: ScanContext): Finding | null {
    // Only .npmrc files
    if (match.file.basename !== '.npmrc') return null;

    const lines = match.file.lines;
    const { snippet, contextBefore, contextAfter } = lines
      ? extractSnippet(lines, match.lineNumber, ctx.config.contextLines)
      : { snippet: match.line, contextBefore: [] as string[], contextAfter: [] as string[] };

    return {
      checkId: 'GIT007',
      title: 'npm Auth Token in .npmrc',
      message:
        'Your npm config has an auth token. Someone could publish packages under your name.',
      severity: 'critical',
      category: 'git',
      location: {
        filePath: match.file.relativePath,
        startLine: match.lineNumber,
      },
      snippet,
      contextBefore,
      contextAfter,
      fix: 'Remove the auth token from .npmrc and use `npm login` or set the NPM_TOKEN environment variable instead. Add `.npmrc` to .gitignore.',
    };
  },
};

// ---------------------------------------------------------------------------
// GIT008 - Terraform State
// ---------------------------------------------------------------------------

const TFSTATE_PATTERNS = ['*.tfstate', '*.tfstate.backup'];

const GIT008: ProjectCheck = {
  level: 'project',
  id: 'GIT008',
  name: 'Terraform State in Repo',
  description: 'Checks for Terraform state files that contain infrastructure secrets.',
  category: 'git',
  defaultSeverity: 'critical',
  async analyze(ctx) {
    const matched = findMatchingFiles(ctx, TFSTATE_PATTERNS);
    return matched.map((entry) => ({
      checkId: 'GIT008',
      title: 'Terraform State File in Repo',
      message:
        `Terraform state files contain all your infrastructure secrets. Found: ${entry.relativePath}`,
      severity: 'critical' as const,
      category: 'git' as const,
      location: { filePath: entry.relativePath, startLine: 1 },
      fix: 'Add `*.tfstate` and `*.tfstate.backup` to .gitignore. Use a remote backend (S3, GCS, Terraform Cloud) to store state.',
    }));
  },
};

// ---------------------------------------------------------------------------
// GIT009 - Backup/Temp Files
// ---------------------------------------------------------------------------

const BACKUP_PATTERNS = ['*.bak', '*.backup', '*.tmp', '*.temp', '*.old', '*.orig', '*.sql'];

const GIT009: ProjectCheck = {
  level: 'project',
  id: 'GIT009',
  name: 'Backup/Temp Files in Repo',
  description: 'Checks for backup, temp, and database dump files that may contain sensitive data.',
  category: 'git',
  defaultSeverity: 'medium',
  async analyze(ctx) {
    const findings: Finding[] = [];

    for (const [relPath, entry] of ctx.files) {
      if (!matchesAny(relPath, BACKUP_PATTERNS)) continue;

      // Exclude .sql files that are intentional (migrations, schemas, seeds)
      if (relPath.endsWith('.sql')) {
        if (relPath.includes('migrations/') || relPath.includes('migration/')) continue;
        const sqlBase = entry.basename.toLowerCase();
        if (/schema|seed|init|setup|create|supabase/.test(sqlBase)) continue;
        if (relPath.includes('supabase/')) continue;
      }

      findings.push({
        checkId: 'GIT009',
        title: 'Backup/Temp File in Repo',
        message:
          `Backup files may contain old versions with exposed secrets or database dumps. Found: ${entry.relativePath}`,
        severity: 'medium',
        category: 'git',
        location: { filePath: relPath, startLine: 1 },
        fix: `Remove \`${entry.basename}\` and add \`${getPatternForExtension(entry.basename)}\` to .gitignore.`,
      });
    }

    return findings;
  },
};

function getPatternForExtension(filename: string): string {
  const dot = filename.lastIndexOf('.');
  if (dot === -1) return filename;
  return '*' + filename.slice(dot);
}

// ---------------------------------------------------------------------------
// GIT010 - IDE/OS Files
// ---------------------------------------------------------------------------

const IDE_OS_PATTERNS = ['.ds_store', 'thumbs.db', '*.swp', '*.swo'];

const GIT010: ProjectCheck = {
  level: 'project',
  id: 'GIT010',
  name: 'IDE/OS Files in Repo',
  description: 'Checks for IDE and OS-specific files that leak system info.',
  category: 'git',
  defaultSeverity: 'low',
  async analyze(ctx) {
    const findings: Finding[] = [];

    for (const [relPath, entry] of ctx.files) {
      if (!matchesAny(relPath, IDE_OS_PATTERNS)) continue;

      findings.push({
        checkId: 'GIT010',
        title: 'IDE/OS File in Repo',
        message:
          `IDE and OS files can leak file paths and system information. Found: ${entry.relativePath}`,
        severity: 'low',
        category: 'git',
        location: { filePath: relPath, startLine: 1 },
        fix: `Add \`${entry.basename}\` to .gitignore. Consider adding a global gitignore for OS files.`,
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// GIT011 - Real Secrets in .env.example
// ---------------------------------------------------------------------------

/** Patterns that look like real secret values (not placeholders). */
const SECRET_VALUE_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,                          // AWS Access Key
  /sk[-_]live[-_][A-Za-z0-9]{20,}/,             // Stripe secret key
  /sk[-_]test[-_][A-Za-z0-9]{20,}/,             // Stripe test key
  /ghp_[A-Za-z0-9]{36}/,                        // GitHub personal access token
  /github_pat_[A-Za-z0-9_]{20,}/,               // GitHub fine-grained PAT
  /xox[bporas]-[A-Za-z0-9-]{10,}/,              // Slack token
  /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]+/,  // JWT
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,    // Private key
  /[A-Za-z0-9+/]{40,}={0,2}/,                   // Long base64 blob (likely real key)
];

/** Patterns for placeholder values that are safe in example files. */
const PLACEHOLDER_PATTERNS = [
  /^['"]?(?:your[-_]|my[-_]|change[-_]|replace[-_]|xxx|TODO|CHANGEME|FILL_IN|REPLACE|INSERT|PLACEHOLDER)/i,
  /^['"]?(?:https?:\/\/example\.com|localhost|127\.0\.0\.1)/i,
  /^['"]?$/,  // empty value
];

const ENV_EXAMPLE_FILENAMES = new Set(['.env.example', '.env.sample']);

const GIT011: ProjectCheck = {
  level: 'project',
  id: 'GIT011',
  name: 'Real Secrets in .env.example',
  description: 'Checks if .env.example or .env.sample contains what looks like real secrets instead of placeholders.',
  category: 'git',
  defaultSeverity: 'critical',
  async analyze(ctx) {
    const findings: Finding[] = [];

    for (const [relPath, entry] of ctx.files) {
      if (!ENV_EXAMPLE_FILENAMES.has(entry.basename.toLowerCase())) continue;

      const content = await ctx.readFile(entry.absolutePath);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        // Skip comments and blank lines
        if (!line || line.startsWith('#')) continue;

        // Parse KEY=VALUE
        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) continue;

        const key = line.slice(0, eqIdx).trim();
        const value = line.slice(eqIdx + 1).trim();

        // Skip empty values
        if (!value || value === "''" || value === '""') continue;

        // Skip if value is a placeholder
        const isPlaceholder = PLACEHOLDER_PATTERNS.some((p) => p.test(value));
        if (isPlaceholder) continue;

        // Check if value matches a real secret pattern
        const looksLikeSecret = SECRET_VALUE_PATTERNS.some((p) => p.test(value));
        if (!looksLikeSecret) continue;

        findings.push({
          checkId: 'GIT011',
          title: 'Real Secrets in .env.example',
          message:
            `.env.example contains what appears to be a real secret for "${key}". Example files are committed to git and visible to everyone.`,
          severity: 'critical',
          category: 'git',
          location: { filePath: relPath, startLine: i + 1 },
          fix: `Replace the real value in .env.example with a placeholder like \`${key}=your_${key.toLowerCase()}_here\`.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const gitChecks: CheckDefinition[] = [
  GIT001,
  GIT002,
  GIT003,
  GIT004,
  GIT005,
  GIT006,
  GIT007,
  GIT008,
  GIT009,
  GIT010,
  GIT011,
];
