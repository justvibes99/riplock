/**
 * SARIF 2.1.0 reporter for GitHub Code Scanning integration.
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import type { Finding, ScanResult, Severity } from '../checks/types.js';
import { allChecks } from '../checks/index.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fixes?: SarifFix[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: {
      startLine: number;
      startColumn?: number;
      snippet?: { text: string };
    };
  };
}

interface SarifFix {
  description: { text: string };
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

export function renderSarif(result: ScanResult, version = '1.0.0'): string {
  // Build rule definitions from all registered checks
  const usedCheckIds = new Set(result.findings.map((f) => f.checkId));
  const rules: SarifRule[] = allChecks
    .filter((c) => usedCheckIds.has(c.id))
    .map((c) => ({
      id: c.id,
      name: c.name,
      shortDescription: { text: c.name },
      fullDescription: { text: c.description },
      defaultConfiguration: { level: SEVERITY_TO_SARIF_LEVEL[c.defaultSeverity] },
    }));

  // Build results from findings
  const results: SarifResult[] = result.findings.map((f) => ({
    ruleId: f.checkId,
    level: SEVERITY_TO_SARIF_LEVEL[f.severity],
    message: { text: `${f.message}\n\nFix: ${f.fix}` },
    locations: f.location
      ? [
          {
            physicalLocation: {
              artifactLocation: { uri: f.location.filePath },
              region: {
                startLine: f.location.startLine,
                startColumn: f.location.startColumn,
                snippet: f.snippet ? { text: f.snippet } : undefined,
              },
            },
          },
        ]
      : [],
    fixes: f.fixCode
      ? [{ description: { text: f.fixCode } }]
      : undefined,
  }));

  const sarif: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'riplock',
            version,
            informationUri: 'https://github.com/justvibes99/riplock',
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
