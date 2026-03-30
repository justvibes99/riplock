import { describe, it, expect } from 'vitest';
import { gitChecks } from '../../src/checks/git/index.js';
import { defaultConfig } from '../../src/config/defaults.js';
import type {
  FileEntry,
  LineCheck,
  ScanContext,
} from '../../src/checks/types.js';
import { testLine, testProjectCheck } from '../helpers.js';

// ---------------------------------------------------------------------------
// GIT001 - Missing .gitignore
// ---------------------------------------------------------------------------

describe('GIT001 - Missing .gitignore', () => {
  it('produces a finding when no .gitignore exists', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT001', { files: { 'index.js': 'console.log("hello")' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT001');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('gitignore');
    expect(findings[0].fix).toBeTruthy();
  });

  it('produces no finding when .gitignore exists in files map', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT001', {
      files: { '.gitignore': 'node_modules/', 'index.js': '' },
    });
    expect(findings).toHaveLength(0);
  });

  it('produces no finding when gitignoreContent is provided', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT001', { files: { 'index.js': '' }, gitignore: 'node_modules/' });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GIT002 - .env Not in .gitignore
// ---------------------------------------------------------------------------

describe('GIT002 - .env Not in .gitignore', () => {
  it('flags .env when it exists and is not gitignored (CRITICAL)', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT002', { files: { '.env': 'SECRET=abc', 'index.js': '' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT002');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('.env');
    expect(findings[0].fix).toBeTruthy();
  });

  it('does not flag .env when it is gitignored', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT002', {
      files: { '.env': 'SECRET=abc', '.gitignore': '.env', 'index.js': '' },
      gitignore: '.env',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag when no .env file exists', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT002', { files: { 'index.js': '' } });
    expect(findings).toHaveLength(0);
  });

  it('flags .env.local when it exists and is not gitignored', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT002', { files: { '.env.local': 'KEY=val' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT002');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('.env.local');
  });
});

// ---------------------------------------------------------------------------
// GIT003 - Sensitive Files Not Gitignored
// ---------------------------------------------------------------------------

describe('GIT003 - Sensitive Files Not Gitignored', () => {
  it('flags id_rsa when it exists and is not gitignored', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT003', { files: { 'id_rsa': 'private key content' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT003');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('SSH private key');
  });

  it('does not flag id_rsa when gitignored', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT003', {
      files: { 'id_rsa': 'key', '.gitignore': 'id_rsa' },
      gitignore: 'id_rsa',
    });
    expect(findings).toHaveLength(0);
  });

  it('flags .pem files', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT003', { files: { 'server.pem': 'cert' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT003');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('PEM');
  });
});

// ---------------------------------------------------------------------------
// GIT004 - SQLite Database in Repo
// ---------------------------------------------------------------------------

describe('GIT004 - SQLite Database in Repo', () => {
  it('flags database.sqlite', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT004', { files: { 'database.sqlite': '' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT004');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('git');
  });

  it('flags .db files', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT004', { files: { 'data.db': '' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT004');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('git');
  });

  it('does not flag when no database files exist', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT004', { files: { 'index.js': '' } });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GIT008 - Terraform State in Repo
// ---------------------------------------------------------------------------

describe('GIT008 - Terraform State in Repo', () => {
  it('flags terraform.tfstate', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT008', { files: { 'terraform.tfstate': '{}' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT008');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('git');
  });

  it('does not flag when no tfstate files exist', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT008', { files: { 'main.tf': 'resource {}' } });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GIT010 - IDE/OS Files in Repo
// ---------------------------------------------------------------------------

describe('GIT010 - IDE/OS Files in Repo', () => {
  it('flags .DS_Store (LOW severity)', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT010', { files: { '.DS_Store': '' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT010');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].category).toBe('git');
  });

  it('flags Thumbs.db', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT010', { files: { 'Thumbs.db': '' } });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT010');
    expect(findings[0].severity).toBe('low');
    expect(findings[0].category).toBe('git');
  });

  it('does not flag normal files', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT010', { files: { 'index.js': '' } });
    expect(findings).toHaveLength(0);
  });

  // GIT005 - Source Maps Present
  it('GIT005: flags source maps in public directories', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT005', { files: { 'public/app.js.map': '{}', 'index.js': '' } });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('GIT005');
    expect(findings[0].category).toBe('git');
  });

  it('GIT005: skips source maps outside public dirs', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT005', { files: { 'src/app.js.map': '{}', 'index.js': '' } });
    expect(findings).toHaveLength(0);
  });

  // GIT006 - Docker Secrets Exposed
  it('GIT006: flags hardcoded password in docker-compose', () => {
    const check = gitChecks.find(c => c.id === 'GIT006') as LineCheck;
    const line = '  password: mysecretpass123';
    const file: FileEntry = {
      absolutePath: '/test/docker-compose.yml',
      relativePath: 'docker-compose.yml',
      sizeBytes: 100, extension: 'yml', basename: 'docker-compose.yml',
      content: line, lines: [line],
    };
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    expect(match).not.toBeNull();
    const ctx = { config: defaultConfig() } as ScanContext;
    const finding = check.analyze({ line, lineNumber: 1, regexMatch: match!, file }, ctx);
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GIT006');
    expect(finding!.category).toBe('git');
  });

  it('GIT006: skips env variable references', () => {
    const check = gitChecks.find(c => c.id === 'GIT006') as LineCheck;
    const line = '  password: ${DB_PASSWORD}';
    const file: FileEntry = {
      absolutePath: '/test/docker-compose.yml',
      relativePath: 'docker-compose.yml',
      sizeBytes: 100, extension: 'yml', basename: 'docker-compose.yml',
      content: line, lines: [line],
    };
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    if (!match) { expect(true).toBe(true); return; }
    const ctx = { config: defaultConfig() } as ScanContext;
    const finding = check.analyze({ line, lineNumber: 1, regexMatch: match, file }, ctx);
    expect(finding).toBeNull();
  });

  // GIT007 - .npmrc Auth Token
  it('GIT007: flags auth token in npmrc', () => {
    const check = gitChecks.find(c => c.id === 'GIT007') as LineCheck;
    const line = '//registry.npmjs.org/:_authToken=npm_ABCDEFghijklmnop1234';
    const file: FileEntry = {
      absolutePath: '/test/.npmrc',
      relativePath: '.npmrc',
      sizeBytes: 100, extension: 'npmrc', basename: '.npmrc',
      content: line, lines: [line],
    };
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    expect(match).not.toBeNull();
    const ctx = { config: defaultConfig() } as ScanContext;
    const finding = check.analyze({ line, lineNumber: 1, regexMatch: match!, file }, ctx);
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GIT007');
    expect(finding!.category).toBe('git');
  });

  it('GIT007: skips env var token', () => {
    const check = gitChecks.find(c => c.id === 'GIT007') as LineCheck;
    const line = '//registry.npmjs.org/:_authToken=${NPM_TOKEN}';
    const file: FileEntry = {
      absolutePath: '/test/.npmrc',
      relativePath: '.npmrc',
      sizeBytes: 100, extension: 'npmrc', basename: '.npmrc',
      content: line, lines: [line],
    };
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    if (!match) { expect(true).toBe(true); return; }
    const ctx = { config: defaultConfig() } as ScanContext;
    const finding = check.analyze({ line, lineNumber: 1, regexMatch: match, file }, ctx);
    expect(finding).toBeNull();
  });

  // GIT009 - Backup/Temp Files
  it('GIT009: flags .bak files', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT009', { files: { 'config.bak': 'old config', 'index.js': '' } });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('GIT009');
    expect(findings[0].category).toBe('git');
  });

  it('GIT009: skips when no backup files present', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT009', { files: { 'index.js': '', 'package.json': '{}' } });
    expect(findings).toHaveLength(0);
  });

  it('GIT009: does not flag SQL schema files', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT009', { files: { 'supabase_schema.sql': 'CREATE TABLE users(...)', 'index.js': '' } });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GIT011 - Real Secrets in .env.example
// ---------------------------------------------------------------------------

describe('GIT011 - Real Secrets in .env.example', () => {
  it('flags .env.example with real AWS key', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT011', {
      files: {
        '.env.example': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE1',
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('GIT011');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('git');
    expect(findings[0].message).toContain('AWS_ACCESS_KEY_ID');
  });

  it('does not flag .env.example with placeholder values', async () => {
    const findings = await testProjectCheck(gitChecks, 'GIT011', {
      files: {
        '.env.example': 'AWS_ACCESS_KEY_ID=your_aws_key_here',
      },
    });
    expect(findings).toHaveLength(0);
  });
});
