import type { ResolvedConfig, Severity } from '../checks/types.js';

export function defaultConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    disabledChecks: new Set(),
    severityOverrides: new Map(),
    ignorePatterns: [],
    maxFileSizeBytes: 1_048_576, // 1MB
    timeoutMs: 30_000,
    contextLines: 2,
    minSeverity: 'low' as Severity,
    format: 'terminal',
    skipDeps: false,
    verbose: false,
    ...overrides,
  };
}

export function severityFromString(s: string): Severity | null {
  const normalized = s.toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
    return normalized as Severity;
  }
  return null;
}
