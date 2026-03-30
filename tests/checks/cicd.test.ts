import { describe, it, expect } from 'vitest';
import { cicdChecks } from '../../src/checks/cicd/index.js';
import { testFileCheck } from '../helpers.js';
import type { LineCheck, FileEntry, Finding, ScanContext } from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';

// ---------------------------------------------------------------------------
// Helper: test a CI/CD line check with a GitHub workflow file entry
// ---------------------------------------------------------------------------

function testWorkflowLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = cicdChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const file: FileEntry = {
    absolutePath: '/test/.github/workflows/ci.yml',
    relativePath: '.github/workflows/ci.yml',
    sizeBytes: line.length,
    extension: 'yml',
    basename: 'ci.yml',
    content: line,
    lines: [line],
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 1, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

// ---------------------------------------------------------------------------
// CICD001 - GitHub Actions Script Injection
// ---------------------------------------------------------------------------

describe('CICD001 - GitHub Actions Script Injection', () => {
  it('detects untrusted input in run expression', () => {
    const finding = testWorkflowLine(
      'CICD001',
      'run: echo "${{ github.event.issue.title }}"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CICD001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('cicd');
  });

  it('does not flag safe github context usage', () => {
    const finding = testWorkflowLine(
      'CICD001',
      'run: echo "${{ github.sha }}"',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CICD002 - Unpinned GitHub Actions
// ---------------------------------------------------------------------------

describe('CICD002 - Unpinned GitHub Actions', () => {
  it('detects action pinned to branch name', () => {
    const finding = testWorkflowLine(
      'CICD002',
      'uses: actions/checkout@main',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CICD002');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('cicd');
  });

  it('does not flag action pinned to full SHA', () => {
    const finding = testWorkflowLine(
      'CICD002',
      'uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CICD003 - pull_request_target with Checkout (FileCheck)
// ---------------------------------------------------------------------------

describe('CICD003 - pull_request_target with Checkout', () => {
  it('flags workflow with pull_request_target and PR checkout', async () => {
    const content = `name: PR Check
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test`;
    const findings = await testFileCheck(cicdChecks, 'CICD003', content, {
      relativePath: '.github/workflows/pr.yml',
      extension: 'yml',
      basename: 'pr.yml',
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('CICD003');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('cicd');
  });

  it('does not flag workflow without pull_request_target', async () => {
    const content = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test`;
    const findings = await testFileCheck(cicdChecks, 'CICD003', content, {
      relativePath: '.github/workflows/ci.yml',
      extension: 'yml',
      basename: 'ci.yml',
    });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// CICD004 - Overly Permissive Workflow Permissions
// ---------------------------------------------------------------------------

describe('CICD004 - Overly Permissive Workflow Permissions', () => {
  it('detects permissions: write-all', () => {
    const finding = testWorkflowLine(
      'CICD004',
      'permissions: write-all',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CICD004');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('cicd');
  });

  it('does not flag restrictive permissions', () => {
    const finding = testWorkflowLine(
      'CICD004',
      'permissions: read-all',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CICD005 - Secret Echoed to Log
// ---------------------------------------------------------------------------

describe('CICD005 - Secret Echoed to Log', () => {
  it('detects echo of secrets', () => {
    const finding = testWorkflowLine(
      'CICD005',
      'echo ${{ secrets.TOKEN }}',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CICD005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('cicd');
  });

  it('does not flag echo without secrets', () => {
    const finding = testWorkflowLine(
      'CICD005',
      'echo "Build complete"',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CICD006 - GitHub Actions Without Permissions Block
// ---------------------------------------------------------------------------

describe('CICD006 - GitHub Actions Without Permissions Block', () => {
  it('flags workflow without permissions block', async () => {
    const content = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test`;
    const findings = await testFileCheck(cicdChecks, 'CICD006', content, {
      relativePath: '.github/workflows/ci.yml',
      extension: 'yml',
      basename: 'ci.yml',
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('CICD006');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].category).toBe('cicd');
  });

  it('does not flag workflow with permissions block', async () => {
    const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test`;
    const findings = await testFileCheck(cicdChecks, 'CICD006', content, {
      relativePath: '.github/workflows/ci.yml',
      extension: 'yml',
      basename: 'ci.yml',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag workflow with per-job permissions', async () => {
    const content = `name: CI
on: push
jobs:
  build:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4`;
    const findings = await testFileCheck(cicdChecks, 'CICD006', content, {
      relativePath: '.github/workflows/ci.yml',
      extension: 'yml',
      basename: 'ci.yml',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag non-workflow yaml files', async () => {
    const content = `name: config
runs-on: something
key: value`;
    const findings = await testFileCheck(cicdChecks, 'CICD006', content, {
      relativePath: 'config/settings.yml',
      extension: 'yml',
      basename: 'settings.yml',
    });
    expect(findings).toHaveLength(0);
  });
});
