import { Command } from 'commander';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Severity } from './checks/types.js';
import { defaultConfig, severityFromString } from './config/defaults.js';
import { loadConfig } from './config/loader.js';
import { scan } from './engine/scanner.js';
import { renderTerminal } from './reporters/terminal.js';
import { renderJson } from './reporters/json.js';
import { renderSarif } from './reporters/sarif.js';
import { allChecks } from './checks/index.js';
import { scanPackages } from './commands/scan-pkg.js';

function getVersion(): string {
  try {
    // Works in both dev (tsx) and built (dist/) contexts
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version ?? '2.0.0';
  } catch {
    return '2.0.0';
  }
}

const VERSION = getVersion();

export async function run(argv: string[]): Promise<void> {
  const program = new Command()
    .name('riplock')
    .description('Security scanner for vibe coders — we\'re watching your back so you can let it rip')
    .version(VERSION);

  // Default command: scan a directory
  program
    .command('scan', { isDefault: true })
    .description('Scan a directory for security issues')
    .argument('[directory]', 'Directory to scan', '.')
    .option('--json', 'Output as JSON')
    .option('--sarif', 'Output as SARIF 2.1.0 (for GitHub Code Scanning)')
    .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)')
    .option('--ignore <checkId...>', 'Check IDs to skip')
    .option('--exclude <patterns...>', 'Glob patterns to exclude')
    .option('--no-deps', 'Skip dependency audit')
    .option('--scan-deps', 'Scan installed dependencies for supply chain attack indicators')
    .option('--verbose', 'Show timing and file list')
    .option('--list-checks', 'List all available checks and exit')
    .action(async (directory: string, opts: Record<string, unknown>) => {
      await runScan(directory, opts);
    });

  // scan-pkg: download and scan packages before installation
  program
    .command('scan-pkg')
    .description('Download and scan packages for supply chain attacks before installing')
    .argument('<packages...>', 'Package specifiers (e.g., express@4.18.2, requests==2.31.0)')
    .option('--json', 'Output as JSON')
    .option('--pip', 'Force pip package manager')
    .option('--npm', 'Force npm package manager')
    .action(async (packages: string[], opts: Record<string, unknown>) => {
      const manager = opts.pip ? 'pip' : opts.npm ? 'npm' : undefined;
      const json = !!opts.json;
      const exitCode = await scanPackages(packages, { manager: manager as 'npm' | 'pip' | undefined, json, version: VERSION });
      process.exit(exitCode);
    });

  await program.parseAsync(argv);
}

async function runScan(dir: string, opts: Record<string, unknown>): Promise<void> {
  // --list-checks: print check catalog and exit
  if (opts.listChecks) {
    printCheckCatalog();
    process.exit(0);
  }

  const directory = resolve(dir);

  // Validate directory exists
  if (!existsSync(directory)) {
    console.error(`riplock: directory not found: ${directory}`);
    process.exit(2);
  }
  if (!statSync(directory).isDirectory()) {
    console.error(`riplock: not a directory: ${directory}`);
    process.exit(2);
  }

  // Build config: file config merged with CLI options
  const cliOverrides = {
    disabledChecks: new Set<string>((opts.ignore ?? []) as string[]),
    minSeverity: (opts.severity
      ? (severityFromString(opts.severity as string) ?? 'low')
      : undefined) as Severity | undefined,
    format: (opts.sarif ? 'sarif' : opts.json ? 'json' : 'terminal') as 'terminal' | 'json' | 'sarif',
    skipDeps: opts.deps === false,
    scanDeps: (opts.scanDeps ?? false) as boolean,
    verbose: (opts.verbose ?? false) as boolean,
    ignorePatterns: (opts.exclude ?? []) as string[],
    // scan-deps mode uses a higher file size limit (2MB) since deps can be larger
    ...(opts.scanDeps ? { maxFileSizeBytes: 2_097_152 } : {}),
  };

  const config = await loadConfig(directory, cliOverrides);

  try {
    const result = await scan(directory, config);

    // Warn on empty projects
    if (result.filesScanned === 0 && config.format !== 'json') {
      console.error('riplock: no files found to scan in ' + directory);
      process.exit(0);
    }

    if (config.format === 'sarif') {
      console.log(renderSarif(result, VERSION));
    } else if (config.format === 'json') {
      console.log(renderJson(result, VERSION));
    } else {
      console.log(renderTerminal(result, VERSION));
    }

    // Exit code: 1 if findings at medium+ severity
    const hasMediumPlus = result.stats.critical > 0 || result.stats.high > 0 || result.stats.medium > 0;
    process.exit(hasMediumPlus ? 1 : 0);
  } catch (err) {
    console.error('riplock error:', err instanceof Error ? err.message : err);
    process.exit(2);
  }
}

function printCheckCatalog(): void {
  const categories = new Map<string, typeof allChecks>();
  for (const check of allChecks) {
    const list = categories.get(check.category) ?? [];
    list.push(check);
    categories.set(check.category, list);
  }

  console.log(`\nriplock v${VERSION} — ${allChecks.length} security checks\n`);

  const categoryOrder = [
    'secrets', 'git', 'injection', 'auth', 'network',
    'data-exposure', 'crypto', 'dependencies', 'framework',
    'uploads', 'dos', 'config',
    'python', 'go', 'ruby', 'php', 'docker', 'cicd', 'iac',
    'supply-chain',
  ];

  for (const cat of categoryOrder) {
    const checks = categories.get(cat);
    if (!checks) continue;
    console.log(`  ${cat.toUpperCase()} (${checks.length})`);
    for (const check of checks) {
      const sev = check.defaultSeverity.toUpperCase().padEnd(8);
      console.log(`    ${check.id.padEnd(14)} ${sev} ${check.name}`);
    }
    console.log();
  }
}
