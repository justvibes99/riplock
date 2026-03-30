import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type {
  FileEntry,
  Finding,
  LockFileData,
  PackageJsonData,
  ResolvedConfig,
  ScanContext,
  ScanResult,
  ScanStats,
} from '../checks/types.js';
import { allChecks, supplyChainChecks } from '../checks/index.js';
import { discoverFiles, discoverDepFiles, groupByExtension, loadFileContent, loadFileLines } from './file-discovery.js';
import { runChecks } from './check-runner.js';
import { loadGitignore, compileGitignore } from '../utils/gitignore.js';
import { detectFrameworks } from '../utils/frameworks.js';
import { loadRules } from './rule-loader.js';

export async function scan(projectRoot: string, config: ResolvedConfig): Promise<ScanResult> {
  const start = performance.now();
  const root = resolve(projectRoot);

  // Enforce scan timeout
  const timeoutMs = config.timeoutMs;
  const checkTimeout = () => {
    if (performance.now() - start > timeoutMs) {
      throw new Error(`Scan timed out after ${(timeoutMs / 1000).toFixed(0)}s`);
    }
  };

  // Discover files: dep scan uses a separate discovery function
  const files = config.scanDeps
    ? await discoverDepFiles(root, config)
    : await discoverFiles(root, config);
  const filesByExtension = groupByExtension(files);

  // Load project metadata
  const packageJson = await loadPackageJson(root);
  const lockFile = detectLockFile(root);
  const gitignoreContent = await loadGitignore(root);
  const gitignoreMatcher = compileGitignore(gitignoreContent);
  const isGitRepo = existsSync(join(root, '.git'));
  const detectedFrameworks = detectFrameworks(packageJson);

  // Pre-compute absolute path lookup (O(1) instead of O(n))
  const absPathIndex = new Map<string, FileEntry>();
  for (const entry of files.values()) {
    absPathIndex.set(entry.absolutePath, entry);
  }

  function resolveEntry(filePath: string): FileEntry | undefined {
    return files.get(filePath) ?? absPathIndex.get(filePath);
  }

  // Build scan context
  const ctx: ScanContext = {
    projectRoot: root,
    files,
    filesByExtension,
    packageJson,
    lockFile,
    isGitRepo,
    gitignoreContent,
    detectedFrameworks,
    config,
    async readFile(filePath: string) {
      const entry = resolveEntry(filePath);
      if (!entry) throw new Error(`File not found: ${filePath}`);
      return loadFileContent(entry);
    },
    async readLines(filePath: string) {
      const entry = resolveEntry(filePath);
      if (!entry) throw new Error(`File not found: ${filePath}`);
      return loadFileLines(entry);
    },
    isGitIgnored(relativePath: string) {
      return gitignoreMatcher(relativePath);
    },
  };

  // Select checks: in scan-deps mode, only run supply-chain checks
  let checksToRun;
  if (config.scanDeps) {
    checksToRun = [...supplyChainChecks];
  } else {
    const ruleChecks = await loadRules(root);
    checksToRun = [...allChecks, ...ruleChecks];
  }

  checkTimeout();

  // Run checks
  const findings = await runChecks(checksToRun, ctx);

  checkTimeout();

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Deduplicate: when both a regex and AST finding exist at the same location+category, keep only the AST finding
  const deduplicated = deduplicateFindings(findings);

  // Compute stats
  const stats: ScanStats = { critical: 0, high: 0, medium: 0, low: 0, total: deduplicated.length };
  for (const f of deduplicated) {
    stats[f.severity]++;
  }

  return {
    findings: deduplicated,
    stats,
    totalDurationMs: performance.now() - start,
    filesScanned: files.size,
    checksRun: checksToRun.length,
    projectRoot: root,
    scanDeps: config.scanDeps || undefined,
  };
}

/**
 * Deduplicate findings: when both a regex finding and an AST finding exist
 * at the same file:line with the same category, keep only the AST finding
 * (higher confidence).
 */
/** Check if a finding comes from a high-confidence AST source */
function isHighConfidenceAst(checkId: string): boolean {
  return checkId.startsWith('AST-') || checkId.startsWith('RULE-AST-');
}

/** Check if a finding comes from the regex rule engine (RULE- prefix, but not RULE-AST-) */
function isRegexRule(checkId: string): boolean {
  return checkId.startsWith('RULE-') && !checkId.startsWith('RULE-AST-');
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  // Build a set of keys covered by high-confidence AST findings
  const astKeys = new Set<string>();
  for (const f of findings) {
    if (isHighConfidenceAst(f.checkId) && f.location) {
      astKeys.add(`${f.location.filePath}:${f.location.startLine}:${f.category}`);
    }
  }

  if (astKeys.size === 0) return findings;

  return findings.filter(f => {
    // Keep all AST findings
    if (isHighConfidenceAst(f.checkId)) return true;
    // Only drop regex *rule-engine* findings that overlap with an AST finding
    // at the same location+category. Built-in checks (INJ001, AUTH001, etc.)
    // are kept since they may detect different aspects.
    if (isRegexRule(f.checkId) && f.location) {
      const key = `${f.location.filePath}:${f.location.startLine}:${f.category}`;
      if (astKeys.has(key)) return false;
    }
    return true;
  });
}

async function loadPackageJson(root: string): Promise<PackageJsonData | null> {
  const pkgPath = join(root, 'package.json');
  try {
    const raw = JSON.parse(await readFile(pkgPath, 'utf-8'));
    return {
      name: raw.name,
      version: raw.version,
      dependencies: raw.dependencies ?? {},
      devDependencies: raw.devDependencies ?? {},
      scripts: raw.scripts ?? {},
      raw,
    };
  } catch {
    return null;
  }
}

function detectLockFile(root: string): LockFileData | null {
  const lockFiles: [string, LockFileData['type']][] = [
    ['package-lock.json', 'package-lock'],
    ['yarn.lock', 'yarn-lock'],
    ['pnpm-lock.yaml', 'pnpm-lock'],
    ['bun.lockb', 'bun-lock'],
  ];
  for (const [file, type] of lockFiles) {
    if (existsSync(join(root, file))) {
      return { type, filePath: join(root, file) };
    }
  }
  return null;
}
