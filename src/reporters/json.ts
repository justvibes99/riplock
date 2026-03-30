import type { ScanResult } from '../checks/types.js';

export function renderJson(result: ScanResult, version = '2.0.0'): string {
  return JSON.stringify(
    {
      version,
      projectRoot: result.projectRoot,
      filesScanned: result.filesScanned,
      checksRun: result.checksRun,
      durationMs: Math.round(result.totalDurationMs),
      stats: result.stats,
      findings: result.findings.map((f) => ({
        checkId: f.checkId,
        severity: f.severity,
        category: f.category,
        title: f.title,
        message: f.message,
        location: f.location ?? null,
        snippet: f.snippet ?? null,
        fix: f.fix,
        fixCode: f.fixCode ?? null,
      })),
    },
    null,
    2,
  );
}
