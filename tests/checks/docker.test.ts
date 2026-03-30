import { describe, it, expect } from 'vitest';
import { dockerChecks } from '../../src/checks/docker/index.js';
import { testFileCheck } from '../helpers.js';
import type { LineCheck, FileEntry, Finding, ScanContext } from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';

// ---------------------------------------------------------------------------
// Helper: test a Docker line check with a Dockerfile file entry
// ---------------------------------------------------------------------------

function testDockerLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = dockerChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const file: FileEntry = {
    absolutePath: '/test/Dockerfile',
    relativePath: 'Dockerfile',
    sizeBytes: line.length,
    extension: '',
    basename: 'Dockerfile',
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
// DOCKER001 - Container Runs as Root (FileCheck)
// ---------------------------------------------------------------------------

describe('DOCKER001 - Container Runs as Root', () => {
  it('flags Dockerfile with FROM but no USER', async () => {
    const content = `FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]`;
    const findings = await testFileCheck(dockerChecks, 'DOCKER001', content, {
      relativePath: 'Dockerfile',
      basename: 'Dockerfile',
      extension: '',
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('DOCKER001');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('docker');
  });

  it('does not flag Dockerfile with USER directive', async () => {
    const content = `FROM node:18-alpine
WORKDIR /app
COPY . .
RUN addgroup --system app && adduser --system --ingroup app app
USER app
CMD ["node", "index.js"]`;
    const findings = await testFileCheck(dockerChecks, 'DOCKER001', content, {
      relativePath: 'Dockerfile',
      basename: 'Dockerfile',
      extension: '',
    });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DOCKER002 - Secrets in Dockerfile ENV
// ---------------------------------------------------------------------------

describe('DOCKER002 - Secrets in Dockerfile ENV', () => {
  it('detects ENV with secret key name', () => {
    const finding = testDockerLine('DOCKER002', 'ENV SECRET_KEY=abc123');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('DOCKER002');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('docker');
  });

  it('does not flag ENV with non-secret name', () => {
    const finding = testDockerLine('DOCKER002', 'ENV NODE_ENV=production');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// DOCKER003 - COPY Sensitive Files
// ---------------------------------------------------------------------------

describe('DOCKER003 - COPY Sensitive Files into Image', () => {
  it('detects COPY .env into image', () => {
    const finding = testDockerLine('DOCKER003', 'COPY .env /app/');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('DOCKER003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('docker');
  });

  it('does not flag COPY of package.json', () => {
    const finding = testDockerLine('DOCKER003', 'COPY package.json /app/');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// DOCKER004 - Unpinned Base Image Tag
// ---------------------------------------------------------------------------

describe('DOCKER004 - Unpinned Base Image Tag', () => {
  it('detects FROM with :latest tag', () => {
    const finding = testDockerLine('DOCKER004', 'FROM node:latest');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('DOCKER004');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('docker');
  });

  it('skips when file is not a Dockerfile', () => {
    // The validate function requires the file to be a Dockerfile
    const check = dockerChecks.find((c) => c.id === 'DOCKER004') as LineCheck;
    const line = 'FROM node:latest';
    const file: FileEntry = {
      absolutePath: '/test/notes.txt',
      relativePath: 'notes.txt',
      sizeBytes: line.length,
      extension: 'txt',
      basename: 'notes.txt',
      content: line,
      lines: [line],
    };
    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(line);
    expect(match).not.toBeNull();
    const finding = check.analyze(
      { line, lineNumber: 1, regexMatch: match!, file },
      { config: defaultConfig() } as ScanContext,
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// DOCKER005 - ADD with Remote URL
// ---------------------------------------------------------------------------

describe('DOCKER005 - ADD with Remote URL', () => {
  it('detects ADD with https URL', () => {
    const finding = testDockerLine('DOCKER005', 'ADD https://example.com/file.tar.gz /app/');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('DOCKER005');
    expect(finding!.severity).toBe('low');
    expect(finding!.category).toBe('docker');
  });

  it('does not flag ADD with local file', () => {
    const finding = testDockerLine('DOCKER005', 'ADD ./local-file.tar.gz /app/');
    expect(finding).toBeNull();
  });
});
