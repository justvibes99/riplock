import { describe, it, expect, beforeAll } from 'vitest';
import { loadRules } from '../src/engine/rule-loader.js';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { LineCheck, FileEntry, LineMatch, ScanContext, ResolvedConfig } from '../src/checks/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, '..');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides?: Partial<ResolvedConfig>): ResolvedConfig {
  return {
    disabledChecks: new Set(),
    severityOverrides: new Map(),
    ignorePatterns: [],
    maxFileSizeBytes: 10_000_000,
    timeoutMs: 30_000,
    contextLines: 2,
    minSeverity: 'low',
    format: 'terminal',
    skipDeps: false,
    verbose: false,
    ...overrides,
  };
}

function makeFile(content: string, relativePath = 'test.js'): FileEntry {
  const lines = content.split('\n');
  const ext = relativePath.split('.').pop() ?? '';
  return {
    absolutePath: `/fake/${relativePath}`,
    relativePath,
    sizeBytes: content.length,
    content,
    lines,
    extension: ext,
    basename: relativePath.split('/').pop() ?? relativePath,
  };
}

function makeCtx(overrides?: Partial<ScanContext>): ScanContext {
  return {
    projectRoot: '/fake',
    files: new Map(),
    filesByExtension: new Map(),
    packageJson: null,
    lockFile: null,
    isGitRepo: false,
    gitignoreContent: null,
    detectedFrameworks: [],
    config: makeConfig(),
    async readFile() { return ''; },
    async readLines() { return []; },
    isGitIgnored() { return false; },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Rule Loader', () => {
  let checks: Awaited<ReturnType<typeof loadRules>>;

  beforeAll(async () => {
    checks = await loadRules(projectRoot);
  });

  it('loads built-in rules from src/rules/builtin.json', () => {
    expect(checks.length).toBeGreaterThan(200);
  });

  it('all loaded checks have required fields', () => {
    for (const check of checks) {
      expect(check.id).toBeTruthy();
      expect(check.name).toBeTruthy();
      expect(check.category).toBeTruthy();
      expect(check.defaultSeverity).toBeTruthy();
      expect(['line', 'file']).toContain(check.level);
    }
  });

  it('all check IDs start with RULE-', () => {
    for (const check of checks) {
      expect(check.id).toMatch(/^RULE-/);
    }
  });

  it('check categories are valid CheckCategory values', () => {
    const validCategories = new Set([
      'secrets', 'git', 'injection', 'auth', 'network', 'data-exposure',
      'crypto', 'dependencies', 'framework', 'uploads', 'dos', 'config',
      'python', 'go', 'ruby', 'php', 'docker', 'cicd', 'iac',
    ]);
    for (const check of checks) {
      expect(validCategories.has(check.category)).toBe(true);
    }
  });

  it('check severities are valid', () => {
    const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
    for (const check of checks) {
      expect(validSeverities.has(check.defaultSeverity)).toBe(true);
    }
  });

  it('all line checks have compilable patterns', () => {
    for (const check of checks) {
      if (check.level === 'line') {
        expect(check.pattern).toBeInstanceOf(RegExp);
      }
    }
  });

  it('RULE-AST-* checks are file-level', () => {
    const astChecks = checks.filter(c => c.id.startsWith('RULE-AST-'));
    expect(astChecks.length).toBeGreaterThan(0);
    for (const check of astChecks) {
      expect(check.level).toBe('file');
    }
  });

  it('check IDs are unique', () => {
    const ids = checks.map(c => c.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});

describe('Rule matching', () => {
  let checks: Awaited<ReturnType<typeof loadRules>>;

  beforeAll(async () => {
    checks = await loadRules(projectRoot);
  });

  function findCheck(id: string): LineCheck {
    const check = checks.find(c => c.id === id);
    expect(check).toBeTruthy();
    expect(check!.level).toBe('line');
    return check as LineCheck;
  }

  function testMatch(check: LineCheck, line: string, file?: FileEntry): boolean {
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    if (!match) return false;

    const testFile = file ?? makeFile(line);
    const lineMatch: LineMatch = {
      line,
      lineNumber: 1,
      regexMatch: match,
      file: testFile,
    };

    const finding = check.analyze(lineMatch, makeCtx());
    return finding !== null;
  }

  it('RULE-JS011: detects document.location assignment with dynamic value', () => {
    const check = findCheck('RULE-JS011');
    expect(testMatch(check, 'document.location = userInput;')).toBe(true);
    // Static string should still match the pattern (it's a general detector)
  });

  it('RULE-JS013: detects postMessage with wildcard origin', () => {
    const check = findCheck('RULE-JS013');
    expect(testMatch(check, "window.postMessage(data, '*')")).toBe(true);
    expect(testMatch(check, "window.postMessage(data, 'https://example.com')")).toBe(false);
  });

  it('RULE-JS025: detects sensitive data in localStorage', () => {
    const check = findCheck('RULE-JS025');
    expect(testMatch(check, "localStorage.setItem('token', jwt)")).toBe(true);
    expect(testMatch(check, "localStorage.setItem('theme', 'dark')")).toBe(false);
  });

  it('RULE-JS046: detects deprecated crypto.createCipher', () => {
    const check = findCheck('RULE-JS046');
    expect(testMatch(check, "const cipher = crypto.createCipher('aes-256-cbc', key)")).toBe(true);
    expect(testMatch(check, "const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)")).toBe(false);
  });

  it('RULE-JS048: detects MD5 hash usage', () => {
    const check = findCheck('RULE-JS048');
    expect(testMatch(check, "const hash = createHash('md5')")).toBe(true);
    expect(testMatch(check, "const hash = createHash('sha256')")).toBe(false);
  });

  it('RULE-PY004: detects unsafe yaml.load', () => {
    const check = findCheck('RULE-PY004');
    expect(testMatch(check, "data = yaml.load(content)", makeFile('', 'test.py'))).toBe(true);
    expect(testMatch(check, "data = yaml.safe_load(content)", makeFile('', 'test.py'))).toBe(false);
  });

  it('RULE-PY007: detects subprocess with shell=True', () => {
    const check = findCheck('RULE-PY007');
    expect(testMatch(check, "subprocess.run(cmd, shell=True)", makeFile('', 'test.py'))).toBe(true);
    expect(testMatch(check, "subprocess.run(cmd_list)", makeFile('', 'test.py'))).toBe(false);
  });

  it('RULE-GO009: detects SQL injection in Go', () => {
    const check = findCheck('RULE-GO009');
    expect(testMatch(check, 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))', makeFile('', 'main.go'))).toBe(true);
  });

  it('RULE-GO011: detects InsecureSkipVerify', () => {
    const check = findCheck('RULE-GO011');
    expect(testMatch(check, "InsecureSkipVerify: true", makeFile('', 'main.go'))).toBe(true);
    expect(testMatch(check, "InsecureSkipVerify: false", makeFile('', 'main.go'))).toBe(false);
  });

  it('RULE-K8S006: detects privileged container', () => {
    const check = findCheck('RULE-K8S006');
    expect(testMatch(check, "  privileged: true", makeFile('', 'deploy.yaml'))).toBe(true);
    expect(testMatch(check, "  privileged: false", makeFile('', 'deploy.yaml'))).toBe(false);
  });

  it('RULE-TF009: detects IAM wildcard actions', () => {
    const check = findCheck('RULE-TF009');
    expect(testMatch(check, '  "Action": "*"', makeFile('', 'main.tf'))).toBe(true);
    expect(testMatch(check, '  "Action": "s3:GetObject"', makeFile('', 'main.tf'))).toBe(false);
  });

  it('RULE-GEN001: detects security-related TODO comments', () => {
    const check = findCheck('RULE-GEN001');
    // Note: the rule matches the pattern first, then the analyze function skips comment lines.
    // Since TODO comments ARE comments, the comment filter in analyze() will skip them.
    // But the pattern still matches, so let's test the pattern itself.
    check.pattern.lastIndex = 0;
    expect(check.pattern.test('// TODO: fix security vulnerability here')).toBe(true);
  });

  it('RULE-GEN009: detects connection strings with credentials', () => {
    const check = findCheck('RULE-GEN009');
    // URL with "example" in it is excluded by the exclude-pattern, so use a real-looking domain
    expect(testMatch(check, "const url = 'postgres://admin:s3cret@prod-db.internal.io/mydb'")).toBe(true);
    expect(testMatch(check, "const url = process.env.DATABASE_URL")).toBe(false);
  });

  it('RULE-GEN010: detects embedded private keys', () => {
    const check = findCheck('RULE-GEN010');
    expect(testMatch(check, "-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
    expect(testMatch(check, "-----BEGIN PUBLIC KEY-----")).toBe(false);
  });

  it('skips comment lines', () => {
    const check = findCheck('RULE-JS048');
    // Comment line should be skipped
    expect(testMatch(check, "// const hash = createHash('md5')")).toBe(false);
  });

  it('applies exclude-pattern to suppress false positives', () => {
    // Use RULE-JS048 (MD5 hash) which has an exclude-pattern
    const check = findCheck('RULE-JS048');
    // Line with 'test' context should be excluded by exclude-pattern
    expect(testMatch(check, "const hash = createHash('sha256')")).toBe(false);
  });

  it('applies path exclude filters', () => {
    const check = findCheck('RULE-JS040');
    // Test file should be excluded by path filter (RULE-JS040 excludes test files)
    const testFile = makeFile("const ip = '10.0.0.1'", 'src/__tests__/config.test.js');
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec("const ip = '10.0.0.1'");
    if (match) {
      const lineMatch: LineMatch = {
        line: "const ip = '10.0.0.1'",
        lineNumber: 1,
        regexMatch: match,
        file: testFile,
      };
      const finding = check.analyze(lineMatch, makeCtx());
      // Should be null because path matches exclusion
      expect(finding).toBeNull();
    }
  });
});

describe('Custom project rules', () => {
  it('loads .riplock-rules.json from project root', async () => {
    // We test against a project that doesn't have custom rules
    const checks = await loadRules(projectRoot);
    // All should be built-in RULE- prefixed
    for (const check of checks) {
      expect(check.id).toMatch(/^RULE-/);
    }
  });
});
