import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ResolvedConfig, Severity } from '../checks/types.js';
import { defaultConfig, severityFromString } from './defaults.js';

interface RiplockConfigFile {
  severity?: string;
  disable?: string[];
  skipDeps?: boolean;
  exclude?: string[];
  maxFileSize?: number;
}

const CONFIG_NAMES = ['.riplock.json', '.riplockrc.json', '.riplockrc'];

/**
 * Load and merge .riplock.json config file with CLI options.
 * CLI options take precedence over config file values.
 */
export async function loadConfig(
  projectRoot: string,
  cliOverrides: Partial<ResolvedConfig> = {},
): Promise<ResolvedConfig> {
  const fileConfig = await loadConfigFile(projectRoot);

  // Merge disabled checks: file config + CLI
  const disabledChecks = new Set<string>([
    ...(fileConfig.disable ?? []),
    ...(cliOverrides.disabledChecks ?? []),
  ]);

  // Min severity: CLI overrides file
  const fileSeverity = fileConfig.severity
    ? severityFromString(fileConfig.severity)
    : null;
  const minSeverity = cliOverrides.minSeverity ?? fileSeverity ?? 'low';

  // Ignore patterns from file
  const ignorePatterns = [
    ...(fileConfig.exclude ?? []),
    ...(cliOverrides.ignorePatterns ?? []),
  ];

  return defaultConfig({
    ...cliOverrides,
    disabledChecks,
    minSeverity,
    ignorePatterns,
    skipDeps: cliOverrides.skipDeps ?? fileConfig.skipDeps ?? false,
    maxFileSizeBytes: fileConfig.maxFileSize ?? cliOverrides.maxFileSizeBytes,
  });
}

async function loadConfigFile(projectRoot: string): Promise<RiplockConfigFile> {
  for (const name of CONFIG_NAMES) {
    try {
      const content = await readFile(join(projectRoot, name), 'utf-8');
      return JSON.parse(content) as RiplockConfigFile;
    } catch {
      continue;
    }
  }
  return {};
}
