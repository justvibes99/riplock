export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type CheckCategory =
  | 'secrets'
  | 'git'
  | 'injection'
  | 'auth'
  | 'network'
  | 'data-exposure'
  | 'crypto'
  | 'dependencies'
  | 'framework'
  | 'uploads'
  | 'dos'
  | 'config'
  | 'python'
  | 'go'
  | 'ruby'
  | 'php'
  | 'docker'
  | 'cicd'
  | 'iac';

export interface SourceLocation {
  filePath: string;
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

export interface Finding {
  checkId: string;
  title: string;
  message: string;
  severity: Severity;
  category: CheckCategory;
  location?: SourceLocation;
  snippet?: string;
  contextBefore?: string[];
  contextAfter?: string[];
  fix: string;
  fixCode?: string;
  /** For AST taint-tracked findings: the data flow path from source to sink */
  taintFlow?: string[];
  /** Detection confidence: 'high' for AST taint-tracked, 'medium' for regex */
  confidence?: 'high' | 'medium' | 'low';
}

export interface FileEntry {
  absolutePath: string;
  relativePath: string;
  sizeBytes: number;
  content?: string;
  lines?: readonly string[];
  extension: string;
  basename: string;
}

export interface PackageJsonData {
  name?: string;
  version?: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  raw: Record<string, unknown>;
}

export interface LockFileData {
  type: 'package-lock' | 'yarn-lock' | 'pnpm-lock' | 'bun-lock';
  filePath: string;
}

export interface ScanContext {
  projectRoot: string;
  files: ReadonlyMap<string, FileEntry>;
  filesByExtension: ReadonlyMap<string, readonly FileEntry[]>;
  packageJson: PackageJsonData | null;
  lockFile: LockFileData | null;
  isGitRepo: boolean;
  gitignoreContent: string | null;
  detectedFrameworks: readonly string[];
  config: ResolvedConfig;
  readFile(filePath: string): Promise<string>;
  readLines(filePath: string): Promise<readonly string[]>;
  isGitIgnored(relativePath: string): boolean;
}

export interface ResolvedConfig {
  disabledChecks: ReadonlySet<string>;
  severityOverrides: ReadonlyMap<string, Severity>;
  ignorePatterns: readonly string[];
  maxFileSizeBytes: number;
  timeoutMs: number;
  contextLines: number;
  minSeverity: Severity;
  format: 'terminal' | 'json' | 'sarif';
  skipDeps: boolean;
  verbose: boolean;
}

// --- Check definitions ---

interface CheckBase {
  id: string;
  name: string;
  description: string;
  category: CheckCategory;
  defaultSeverity: Severity;
  appliesTo?: string[];
  tags?: string[];
}

export interface LineMatch {
  line: string;
  lineNumber: number;
  regexMatch: RegExpExecArray;
  file: FileEntry;
}

export interface LineCheck extends CheckBase {
  level: 'line';
  pattern: RegExp;
  analyze(match: LineMatch, ctx: ScanContext): Finding | null;
}

export interface FileCheck extends CheckBase {
  level: 'file';
  fastFilter?: string | RegExp;
  analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]>;
}

export interface ProjectCheck extends CheckBase {
  level: 'project';
  analyze(ctx: ScanContext): Promise<Finding[]>;
}

export interface DependencyCheck extends CheckBase {
  level: 'dependency';
  analyze(
    packageJson: PackageJsonData,
    lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]>;
}

// --- AST check definitions (tree-sitter powered) ---

export type AstLanguage = 'javascript' | 'typescript' | 'tsx' | 'python' | 'go' | 'ruby' | 'php';

export interface TaintNode {
  expression: string;
  line: number;
  column: number;
  /** File path for cross-file taint nodes (relative to project root) */
  filePath?: string;
}

export interface TaintPath {
  source: TaintNode;
  intermediates: TaintNode[];
  sink: TaintNode;
  sinkCategory: string;
}

export type SinkCategory =
  | 'sql-query'
  | 'shell-exec'
  | 'ssrf'
  | 'xss'
  | 'path-traversal'
  | 'redirect'
  | 'eval';

export interface TaintQueryOpts {
  sinkCategories: SinkCategory[];
  maxDepth?: number;
}

export interface AstCheckContext {
  rootNode: unknown;
  file: FileEntry;
  language: AstLanguage;
  ctx: ScanContext;
  findTaintPaths(opts: TaintQueryOpts): TaintPath[];
}

export interface AstCheck extends CheckBase {
  level: 'ast';
  languages: AstLanguage[];
  sinkCategories?: SinkCategory[];
  analyze(astCtx: AstCheckContext): Finding[];
}

export type CheckDefinition = LineCheck | FileCheck | ProjectCheck | DependencyCheck | AstCheck;

export interface ScanResult {
  findings: readonly Finding[];
  stats: ScanStats;
  totalDurationMs: number;
  filesScanned: number;
  checksRun: number;
  projectRoot: string;
}

export interface ScanStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}
