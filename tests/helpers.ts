/**
 * Shared test helpers for RipLock check tests.
 * Import this instead of duplicating helpers in every test file.
 */
import type {
  CheckDefinition,
  DependencyCheck,
  FileCheck,
  FileEntry,
  Finding,
  LineCheck,
  LockFileData,
  PackageJsonData,
  ProjectCheck,
  ScanContext,
} from '../src/checks/types.js';
import { defaultConfig } from '../src/config/defaults.js';
import { compileGitignore } from '../src/utils/gitignore.js';

/**
 * Test a LineCheck against a single line of code.
 * Returns the Finding if the check fires, null if it doesn't.
 */
export function testLine(
  checks: CheckDefinition[],
  checkId: string,
  line: string,
  extension = 'js',
): Finding | null {
  const check = checks.find((c) => c.id === checkId);
  if (!check) throw new Error(`Check ${checkId} not found`);
  if (check.level !== 'line') throw new Error(`Check ${checkId} is ${check.level}, not line`);
  const lc = check as LineCheck;

  const file: FileEntry = {
    absolutePath: '/test/file.' + extension,
    relativePath: 'file.' + extension,
    sizeBytes: line.length,
    extension,
    basename: 'file.' + extension,
    content: line,
    lines: [line],
  };

  lc.pattern.lastIndex = 0;
  const match = lc.pattern.exec(line);
  if (!match) return null;

  const ctx = { config: defaultConfig() } as ScanContext;
  return lc.analyze({ line, lineNumber: 1, regexMatch: match, file }, ctx);
}

/**
 * Test a FileCheck against file content.
 */
export async function testFileCheck(
  checks: CheckDefinition[],
  checkId: string,
  content: string,
  opts?: { relativePath?: string; extension?: string; basename?: string },
): Promise<Finding[]> {
  const check = checks.find((c) => c.id === checkId);
  if (!check) throw new Error(`Check ${checkId} not found`);
  if (check.level !== 'file') throw new Error(`Check ${checkId} is ${check.level}, not file`);
  const fc = check as FileCheck;

  const relPath = opts?.relativePath ?? 'file.ts';
  const ext = opts?.extension ?? relPath.split('.').pop() ?? 'ts';
  const base = opts?.basename ?? relPath.split('/').pop() ?? 'file.ts';

  const file: FileEntry = {
    absolutePath: '/test/' + relPath,
    relativePath: relPath,
    sizeBytes: content.length,
    extension: ext,
    basename: base,
    content,
    lines: content.split('\n'),
  };

  const ctx = {
    config: defaultConfig(),
    projectRoot: '/test',
    files: new Map([[relPath, file]]),
    filesByExtension: new Map(),
    packageJson: null,
    lockFile: null,
    isGitRepo: false,
    gitignoreContent: null,
    detectedFrameworks: [],
    readFile: async () => content,
    readLines: async () => content.split('\n'),
    isGitIgnored: () => false,
  } as unknown as ScanContext;

  return fc.analyze(file, ctx);
}

/**
 * Test a ProjectCheck with a file map and optional config.
 */
export async function testProjectCheck(
  checks: CheckDefinition[],
  checkId: string,
  opts: {
    files?: Record<string, string>;
    gitignore?: string | null;
    packageJson?: Partial<PackageJsonData> | null;
    detectedFrameworks?: string[];
  } = {},
): Promise<Finding[]> {
  const check = checks.find((c) => c.id === checkId);
  if (!check) throw new Error(`Check ${checkId} not found`);
  if (check.level !== 'project') throw new Error(`Check ${checkId} is ${check.level}, not project`);
  const pc = check as ProjectCheck;

  const fileMap = new Map<string, FileEntry>();
  for (const [path, content] of Object.entries(opts.files ?? {})) {
    fileMap.set(path, {
      absolutePath: '/test/' + path,
      relativePath: path,
      sizeBytes: content.length,
      extension: path.split('.').pop() ?? '',
      basename: path.split('/').pop() ?? path,
      content,
      lines: content.split('\n'),
    });
  }

  const gitignoreContent = opts.gitignore ?? null;
  const matcher = compileGitignore(gitignoreContent);

  const pkg = opts.packageJson === null ? null : {
    dependencies: {},
    devDependencies: {},
    scripts: {},
    raw: {},
    ...opts.packageJson,
  } as PackageJsonData;

  // Build a reverse lookup so readFile works with both relative and absolute paths
  const absToRel = new Map<string, string>();
  for (const [relPath, entry] of fileMap) {
    absToRel.set(entry.absolutePath, relPath);
  }

  const lookupFile = (p: string) => fileMap.get(p) ?? fileMap.get(absToRel.get(p) ?? '');

  const ctx: ScanContext = {
    projectRoot: '/test',
    files: fileMap,
    filesByExtension: new Map(),
    packageJson: pkg,
    lockFile: null,
    isGitRepo: true,
    gitignoreContent,
    detectedFrameworks: opts.detectedFrameworks ?? [],
    config: defaultConfig(),
    readFile: async (p) => lookupFile(p)?.content ?? '',
    readLines: async (p) => lookupFile(p)?.lines ?? [],
    isGitIgnored: (p) => matcher(p),
  };

  return pc.analyze(ctx);
}

/**
 * Test a DependencyCheck with package data.
 */
export async function testDepCheck(
  checks: CheckDefinition[],
  checkId: string,
  pkg: Partial<PackageJsonData>,
  lockFile: LockFileData | null = null,
): Promise<Finding[]> {
  const check = checks.find((c) => c.id === checkId);
  if (!check) throw new Error(`Check ${checkId} not found`);
  if (check.level !== 'dependency') throw new Error(`Check ${checkId} is ${check.level}, not dependency`);
  const dc = check as DependencyCheck;

  const fullPkg: PackageJsonData = {
    dependencies: {},
    devDependencies: {},
    scripts: {},
    raw: {},
    ...pkg,
  };

  const ctx = {
    config: defaultConfig(),
    projectRoot: '/test',
  } as unknown as ScanContext;

  return dc.analyze(fullPkg, lockFile, ctx);
}
