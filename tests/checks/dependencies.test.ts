import { describe, it, expect } from 'vitest';
import type {
  CheckDefinition,
  DependencyCheck,
  ProjectCheck,
  PackageJsonData,
  LockFileData,
  ScanContext,
  Finding,
} from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';
import { dependencyChecks } from '../../src/checks/dependencies/index.js';

function makeScanContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    projectRoot: '/test',
    files: new Map(),
    filesByExtension: new Map(),
    packageJson: null,
    lockFile: null,
    isGitRepo: true,
    gitignoreContent: null,
    detectedFrameworks: [],
    config: defaultConfig(),
    readFile: async () => '',
    readLines: async () => [],
    isGitIgnored: () => false,
    ...overrides,
  };
}

function findCheck(id: string): CheckDefinition {
  const check = dependencyChecks.find(c => c.id === id);
  if (!check) throw new Error(`Check ${id} not found`);
  return check;
}

describe('dependency checks', () => {
  describe('DEP002 - Compromised or Sabotaged Package', () => {
    it('flags event-stream as compromised', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'event-stream': '3.3.6' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP002') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP002');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('event-stream');
      expect(findings[0].fix).toBeTruthy();
    });

    it('does not flag lodash (not compromised)', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'lodash': '4.17.21' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP002') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP003 - No Package Lock File', () => {
    it('flags when no lock file is present', async () => {
      const check = findCheck('DEP003') as ProjectCheck;
      const ctx = makeScanContext({
        packageJson: {
          dependencies: {},
          devDependencies: {},
          scripts: {},
          raw: {},
        },
        lockFile: null,
      });
      const findings = await check.analyze(ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP003');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('lock');
      expect(findings[0].fix).toBeTruthy();
    });
  });

  describe('DEP004 - Prototype Pollution Vulnerability', () => {
    it('flags lodash 4.17.20 (vulnerable)', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'lodash': '4.17.20' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP004') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP004');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('lodash');
    });

    it('does not flag lodash 4.17.21 (fixed)', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'lodash': '4.17.21' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP004') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP005 - Critically Vulnerable Package Version', () => {
    it('flags next 14.0.0 (vulnerable)', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'next': '14.0.0' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP005') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP005');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('next');
    });

    it('does not flag next 15.3.0 (safe)', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'next': '15.3.0' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP005') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP006 - Inherently Unsafe Serialization Package', () => {
    it('flags node-serialize at any version', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'node-serialize': '0.0.4' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP006') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP006');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('node-serialize');
    });
  });

  describe('DEP007 - Permissive Version Range', () => {
    it('flags wildcard version range', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'lodash': '*' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP007') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP007');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('dependencies');
      expect(findings[0].message).toContain('lodash');
    });

    it('does not flag caret version range', async () => {
      const pkg: PackageJsonData = {
        dependencies: { 'lodash': '^4.17.21' },
        devDependencies: {},
        scripts: {},
        raw: {},
      };
      const check = findCheck('DEP007') as DependencyCheck;
      const ctx = makeScanContext();
      const findings = await check.analyze(pkg, null, ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP008 - Python Requirements with Known Vulnerabilities', () => {
    it('flags vulnerable django version', async () => {
      const check = findCheck('DEP008') as ProjectCheck;
      const files = new Map<string, any>();
      const reqContent = `django==4.2.5\nrequests==2.31.0\n`;
      files.set('requirements.txt', {
        absolutePath: '/test/requirements.txt',
        relativePath: 'requirements.txt',
        sizeBytes: reqContent.length,
        extension: 'txt',
        basename: 'requirements.txt',
        content: reqContent,
        lines: reqContent.split('\n'),
      });
      const ctx = makeScanContext({
        files,
        readFile: async () => reqContent,
      });
      const findings = await check.analyze(ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP008');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].message).toContain('django');
    });

    it('does not flag safe django version', async () => {
      const check = findCheck('DEP008') as ProjectCheck;
      const files = new Map<string, any>();
      const reqContent = `django==4.2.8\n`;
      files.set('requirements.txt', {
        absolutePath: '/test/requirements.txt',
        relativePath: 'requirements.txt',
        sizeBytes: reqContent.length,
        extension: 'txt',
        basename: 'requirements.txt',
        content: reqContent,
        lines: reqContent.split('\n'),
      });
      const ctx = makeScanContext({
        files,
        readFile: async () => reqContent,
      });
      const findings = await check.analyze(ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP009 - Gemfile Without Bundle Audit', () => {
    it('flags Gemfile without bundler-audit', async () => {
      const check = findCheck('DEP009') as ProjectCheck;
      const files = new Map<string, any>();
      const gemContent = `source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n`;
      files.set('Gemfile', {
        absolutePath: '/test/Gemfile',
        relativePath: 'Gemfile',
        sizeBytes: gemContent.length,
        extension: '',
        basename: 'Gemfile',
        content: gemContent,
        lines: gemContent.split('\n'),
      });
      const ctx = makeScanContext({
        files,
        readFile: async () => gemContent,
      });
      const findings = await check.analyze(ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP009');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].message).toContain('bundle-audit');
    });

    it('does not flag Gemfile with bundler-audit', async () => {
      const check = findCheck('DEP009') as ProjectCheck;
      const files = new Map<string, any>();
      const gemContent = `source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\ngem 'bundler-audit', group: :development\n`;
      files.set('Gemfile', {
        absolutePath: '/test/Gemfile',
        relativePath: 'Gemfile',
        sizeBytes: gemContent.length,
        extension: '',
        basename: 'Gemfile',
        content: gemContent,
        lines: gemContent.split('\n'),
      });
      const ctx = makeScanContext({
        files,
        readFile: async () => gemContent,
      });
      const findings = await check.analyze(ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe('DEP010 - Python Without pip-audit', () => {
    it('flags Python project with requirements.txt', async () => {
      const check = findCheck('DEP010') as ProjectCheck;
      const files = new Map<string, any>();
      files.set('requirements.txt', {
        absolutePath: '/test/requirements.txt',
        relativePath: 'requirements.txt',
        sizeBytes: 10,
        extension: 'txt',
        basename: 'requirements.txt',
      });
      const ctx = makeScanContext({ files });
      const findings = await check.analyze(ctx);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('DEP010');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].message).toContain('pip-audit');
    });
  });

  describe('DEP001 - npm audit', () => {
    it('skips when no lock file is present', async () => {
      const check = dependencyChecks.find(c => c.id === 'DEP001') as DependencyCheck;
      const findings = await check.analyze(
        { dependencies: {}, devDependencies: {}, scripts: {}, raw: {} },
        null,
        { config: defaultConfig(), projectRoot: '/nonexistent' } as unknown as ScanContext,
      );
      expect(findings).toHaveLength(0);
    });

    it('skips for non-npm lock files', async () => {
      const check = dependencyChecks.find(c => c.id === 'DEP001') as DependencyCheck;
      const findings = await check.analyze(
        { dependencies: {}, devDependencies: {}, scripts: {}, raw: {} },
        { type: 'yarn-lock', filePath: '/test/yarn.lock' },
        { config: defaultConfig(), projectRoot: '/nonexistent' } as unknown as ScanContext,
      );
      expect(findings).toHaveLength(0);
    });
  });
});
