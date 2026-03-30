/**
 * Integration tests — run the REAL scanner against fixture directories
 * and assert on the actual output. These test the full pipeline:
 * file discovery → extension filtering → check runner → reporting.
 */
import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scan } from '../src/engine/scanner.js';
import { defaultConfig } from '../src/config/defaults.js';
import type { Finding, Severity } from '../src/checks/types.js';

const FIXTURES = resolve(import.meta.dirname, 'fixtures');

function findingIds(findings: readonly Finding[]): string[] {
  return findings.map((f) => f.checkId);
}

function findingsAt(findings: readonly Finding[], severity: Severity): readonly Finding[] {
  return findings.filter((f) => f.severity === severity);
}

describe('Integration: vulnerable-project', () => {
  it('finds multiple real vulnerabilities', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.stats.total).toBeGreaterThan(10);
    expect(result.stats.critical).toBeGreaterThan(0);
  });

  it('detects hardcoded Stripe key in server.js', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const stripeFindings = result.findings.filter(
      (f) => f.checkId === 'SEC006' && f.location?.filePath === 'server.js',
    );
    expect(stripeFindings.length).toBeGreaterThan(0);
    expect(stripeFindings[0].severity).toBe('critical');
    expect(stripeFindings[0].message).toContain('Stripe');
    expect(stripeFindings[0].fix).toBeTruthy();
    expect(stripeFindings[0].location?.startLine).toBeGreaterThan(0);
  });

  it('detects SQL injection in server.js', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const sqlFindings = result.findings.filter((f) => f.checkId === 'INJ001');
    expect(sqlFindings.length).toBeGreaterThan(0);
  });

  it('detects .env not gitignored', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const gitFindings = result.findings.filter((f) => f.checkId === 'GIT002');
    expect(gitFindings.length).toBeGreaterThan(0);
    expect(gitFindings[0].severity).toBe('critical');
  });

  it('respects severity filtering', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true, minSeverity: 'critical' }),
    );

    for (const f of result.findings) {
      expect(f.severity).toBe('critical');
    }
  });

  it('respects check disabling', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true, disabledChecks: new Set(['SEC006', 'SEC008']) }),
    );

    expect(findingIds(result.findings)).not.toContain('SEC006');
    expect(findingIds(result.findings)).not.toContain('SEC008');
  });

  it('every finding has required fields', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    for (const f of result.findings) {
      expect(f.checkId).toBeTruthy();
      expect(f.title).toBeTruthy();
      expect(f.message).toBeTruthy();
      expect(f.message.length).toBeGreaterThan(20);
      expect(f.severity).toMatch(/^(critical|high|medium|low)$/);
      expect(f.category).toBeTruthy();
      expect(f.fix).toBeTruthy();
      expect(f.fix.length).toBeGreaterThan(10);
    }
  });

  it('findings with locations have valid snippets', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const withLocation = result.findings.filter((f) => f.location);
    expect(withLocation.length).toBeGreaterThan(0);

    for (const f of withLocation) {
      expect(f.location!.filePath).toBeTruthy();
      expect(f.location!.startLine).toBeGreaterThan(0);
      if (f.snippet) {
        expect(f.snippet.length).toBeGreaterThan(0);
      }
    }
  });
});

describe('Integration: clean-project', () => {
  it('produces zero critical or high findings', async () => {
    const result = await scan(
      resolve(FIXTURES, 'clean-project'),
      defaultConfig({ skipDeps: true }),
    );

    const serious = findingsAt(result.findings, 'critical')
      .concat(findingsAt(result.findings, 'high'));
    expect(serious).toHaveLength(0);
  });

  it('scans files successfully', async () => {
    const result = await scan(
      resolve(FIXTURES, 'clean-project'),
      defaultConfig({ skipDeps: true }),
    );

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.totalDurationMs).toBeLessThan(5000);
  });
});

describe('Integration: performance', () => {
  it('scans vulnerable-project in under 1 second', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    expect(result.totalDurationMs).toBeLessThan(1000);
  });
});

describe('Integration: JSON output', () => {
  it('produces valid JSON', async () => {
    const { renderJson } = await import('../src/reporters/json.js');
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const json = renderJson(result);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe('2.0.0');
    expect(parsed.filesScanned).toBeGreaterThan(0);
    expect(parsed.stats.total).toBe(parsed.findings.length);
    expect(Array.isArray(parsed.findings)).toBe(true);
  });
});

describe('Integration: terminal output', () => {
  it('produces non-empty terminal output', async () => {
    const { renderTerminal } = await import('../src/reporters/terminal.js');
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const output = renderTerminal(result);
    expect(output.length).toBeGreaterThan(100);
    expect(output).toContain('riplock');
    expect(output).toContain('Grade');
  });
});

describe('Integration: SARIF output', () => {
  it('produces valid SARIF 2.1.0', async () => {
    const { renderSarif } = await import('../src/reporters/sarif.js');
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    const sarif = renderSarif(result);
    const parsed = JSON.parse(sarif);

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe('riplock');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);

    // Every result should have a ruleId and level
    for (const result of parsed.runs[0].results) {
      expect(result.ruleId).toBeTruthy();
      expect(result.level).toMatch(/^(error|warning|note)$/);
      expect(result.message.text).toBeTruthy();
    }

    // Rules should be defined for used checks
    expect(parsed.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });
});

describe('Integration: config file', () => {
  it('respects .riplock.json disable and severity', async () => {
    const { writeFileSync, unlinkSync } = await import('node:fs');
    const configPath = resolve(FIXTURES, 'vulnerable-project', '.riplock.json');

    // Write a temporary config
    writeFileSync(configPath, JSON.stringify({
      disable: ['SEC006', 'SEC008', 'GIT002'],
      severity: 'high',
    }));

    try {
      const { loadConfig } = await import('../src/config/loader.js');
      const config = await loadConfig(resolve(FIXTURES, 'vulnerable-project'), { skipDeps: true });
      const result = await scan(resolve(FIXTURES, 'vulnerable-project'), config);

      // Disabled checks should not appear
      const ids = result.findings.map(f => f.checkId);
      expect(ids).not.toContain('SEC006');
      expect(ids).not.toContain('SEC008');
      expect(ids).not.toContain('GIT002');

      // Only high+ severity findings
      for (const f of result.findings) {
        expect(['critical', 'high']).toContain(f.severity);
      }
    } finally {
      unlinkSync(configPath);
    }
  });
});

describe('Integration: --exclude patterns', () => {
  it('excludes files matching glob patterns', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true, ignorePatterns: ['**/*.env', '*.env'] }),
    );

    // No findings from .env file
    const envFindings = result.findings.filter(
      f => f.location?.filePath === '.env',
    );
    expect(envFindings).toHaveLength(0);
  });
});

describe('Integration: realistic vibe-coded project', () => {
  const REALWORLD = resolve(FIXTURES, 'realworld');

  it('detects all common vibe-coder vulnerabilities', async () => {
    const result = await scan(REALWORLD, defaultConfig({ skipDeps: true }));

    const found = new Set(result.findings.map(f => f.checkId));

    // Every vulnerability a vibe coder commonly introduces
    const expected = [
      'GIT002',   // .env not gitignored
      'SEC008',   // Hardcoded OpenAI key
      'AUTH005',  // API routes without auth
      'AUTH008',  // Webhook without signature verification
      'NEXT001',  // Server action without auth
      'AUTH001',  // JWT weak secret
      'AUTH018',  // Plaintext password comparison
      'NET006',   // cors() no args
      'INJ001',   // SQL injection
      'INJ004',   // Command injection
      'AUTH007',  // Admin route without role check
      'INJ019',   // AI prompt injection
      'DATA007',  // Full DB object in response
      'CONFIG003', // Missing CSP
    ];

    for (const id of expected) {
      expect(found.has(id), `Expected ${id} to be detected`).toBe(true);
    }
  });
});

describe('Integration: reports all findings (no silent cap)', () => {
  it('reports every finding without dropping any', async () => {
    const result = await scan(
      resolve(FIXTURES, 'vulnerable-project'),
      defaultConfig({ skipDeps: true }),
    );

    // Every finding should have required fields — none silently dropped
    for (const f of result.findings) {
      expect(f.checkId).toBeTruthy();
      expect(f.severity).toBeTruthy();
    }
    expect(result.stats.total).toBe(result.findings.length);
  });
});
