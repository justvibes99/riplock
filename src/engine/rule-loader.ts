/**
 * Rule engine: loads JSON rule definitions from built-in rules and
 * project-level custom rules, converting them into CheckDefinition objects.
 *
 * Supports:
 *   - Built-in rules from src/rules/builtin.json (bundled)
 *   - Project-level rules from .riplock-rules.json or rules/*.json
 *
 * Rule format (JSON):
 *   {
 *     "rules": [
 *       {
 *         "id": "CUSTOM-001",
 *         "message": "Description of the issue",
 *         "severity": "high",
 *         "category": "injection",
 *         "languages": ["javascript", "typescript"],
 *         "pattern": "regex string",
 *         "exclude-pattern": "optional regex to exclude false positives",
 *         "fix": "How to fix",
 *         "fixCode": "Optional code example",
 *         "paths": { "include": ["glob"], "exclude": ["glob"] }
 *       }
 *     ]
 *   }
 */

import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  AstLanguage,
  CheckCategory,
  CheckDefinition,
  FileEntry,
  Finding,
  LineCheck,
  FileCheck,
  LineMatch,
  ScanContext,
  Severity,
} from '../checks/types.js';
import { extractSnippet } from '../utils/snippet.js';
import { isCommentLine } from '../checks/shared.js';
import { isAstGrepPattern, matchAstPattern, extractFastFilter } from './ast-pattern.js';
import type { RulePattern, CompoundRuleOpts } from './ast-pattern.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RuleDefinition {
  id: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  languages?: string[];
  /** Regex or $METAVAR pattern. Optional for kind-based rules (Python/Go/Ruby). */
  pattern?: string;
  'pattern-mode'?: 'ast' | 'regex';
  'exclude-pattern'?: string;
  fix: string;
  fixCode?: string;
  paths?: { include?: string[]; exclude?: string[] };

  // Compound operators (ast-grep rule composition)
  inside?: RulePattern;
  has?: RulePattern;
  'has-not'?: RulePattern;
  not?: RulePattern;
  follows?: RulePattern;
  precedes?: RulePattern;
  all?: RulePattern[];
  any?: RulePattern[];
  kind?: string;
  regex?: string;
}

/**
 * Returns true if a rule definition uses any compound operator.
 */
function hasCompoundOps(rule: RuleDefinition): boolean {
  return !!(
    rule.inside || rule.has || rule['has-not'] || rule.not ||
    rule.follows || rule.precedes || rule.all || rule.any ||
    rule.kind || rule.regex
  );
}

/**
 * Builds a CompoundRuleOpts from a RuleDefinition's compound fields.
 */
function extractCompoundOpts(rule: RuleDefinition): CompoundRuleOpts | undefined {
  if (!hasCompoundOps(rule)) return undefined;

  const opts: CompoundRuleOpts = {};
  if (rule.inside) opts.inside = rule.inside;
  if (rule.has) opts.has = rule.has;
  if (rule['has-not']) opts.hasNot = rule['has-not'];
  if (rule.not) opts.not = rule.not;
  if (rule.follows) opts.follows = rule.follows;
  if (rule.precedes) opts.precedes = rule.precedes;
  if (rule.all) opts.all = rule.all;
  if (rule.any) opts.any = rule.any;
  if (rule.kind) opts.kind = rule.kind;
  if (rule.regex) opts.regex = rule.regex;
  return opts;
}

interface RulesFile {
  rules: RuleDefinition[];
}

// ---------------------------------------------------------------------------
// Language → file extension mapping
// ---------------------------------------------------------------------------

const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: ['js', 'jsx', 'mjs', 'cjs'],
  typescript: ['ts', 'tsx', 'mts', 'cts'],
  python: ['py'],
  go: ['go'],
  ruby: ['rb'],
  php: ['php'],
  java: ['java'],
  csharp: ['cs'],
  rust: ['rs'],
  terraform: ['tf', 'hcl'],
  kubernetes: ['yml', 'yaml'],
  docker: ['Dockerfile'],
  shell: ['sh', 'bash', 'zsh'],
  html: ['html', 'htm'],
  css: ['css', 'scss', 'less'],
  yaml: ['yml', 'yaml'],
  json: ['json'],
  // Generic matches everything
  generic: [],
};

function languagesToExtensions(languages?: string[]): string[] | undefined {
  if (!languages || languages.length === 0) return undefined;

  const exts = new Set<string>();
  for (const lang of languages) {
    const mapped = LANGUAGE_EXTENSIONS[lang.toLowerCase()];
    if (mapped) {
      for (const ext of mapped) exts.add(ext);
    }
  }
  return exts.size > 0 ? [...exts] : undefined;
}

// ---------------------------------------------------------------------------
// Category mapping: map free-form category strings to CheckCategory
// ---------------------------------------------------------------------------

const CATEGORY_MAP: Record<string, CheckCategory> = {
  injection: 'injection',
  xss: 'injection',
  sqli: 'injection',
  'sql-injection': 'injection',
  'command-injection': 'injection',
  ssrf: 'injection',
  secrets: 'secrets',
  secret: 'secrets',
  credentials: 'secrets',
  auth: 'auth',
  authentication: 'auth',
  authorization: 'auth',
  network: 'network',
  'data-exposure': 'data-exposure',
  'data-leak': 'data-exposure',
  exposure: 'data-exposure',
  crypto: 'crypto',
  cryptography: 'crypto',
  encryption: 'crypto',
  dependencies: 'dependencies',
  deps: 'dependencies',
  framework: 'framework',
  uploads: 'uploads',
  dos: 'dos',
  'denial-of-service': 'dos',
  redos: 'dos',
  config: 'config',
  configuration: 'config',
  python: 'python',
  go: 'go',
  ruby: 'ruby',
  php: 'php',
  docker: 'docker',
  cicd: 'cicd',
  'ci-cd': 'cicd',
  ci: 'cicd',
  iac: 'iac',
  terraform: 'iac',
  kubernetes: 'iac',
  infrastructure: 'iac',
  git: 'git',
  generic: 'config',
  compliance: 'config',
  logging: 'config',
  'error-handling': 'config',
  validation: 'injection',
  deserialization: 'injection',
  cookie: 'network',
  csrf: 'auth',
  cors: 'network',
  'file-system': 'injection',
  websocket: 'network',
  graphql: 'network',
  'rate-limiting': 'dos',
};

function mapCategory(category: string): CheckCategory {
  const lower = category.toLowerCase();
  return CATEGORY_MAP[lower] ?? 'config';
}

// ---------------------------------------------------------------------------
// Pattern compilation
// ---------------------------------------------------------------------------

/**
 * Converts a rule pattern string to a compiled RegExp.
 * Patterns are already regex strings — we just compile them.
 * Supports $VAR metavariables: replaced with identifier capture groups.
 * Supports ... ellipsis: replaced with non-greedy any-match.
 */
function compilePattern(pattern: string): RegExp {
  // If pattern contains regex metacharacters like \s, \(, [^...], it's a raw regex
  // If pattern contains $VAR or literal ..., it's a DSL pattern
  const isRawRegex = /\\[sSwWdDbB()\[\]]|(?:\[[\^]|\(\?[:!=])/.test(pattern);

  if (isRawRegex) {
    // Treat as raw regex — compile directly
    return new RegExp(pattern, 'gi');
  }

  // DSL pattern: replace $VAR metavariables and ... ellipsis
  let regexStr = pattern;
  regexStr = regexStr.replace(/\$[A-Z_][A-Z0-9_]*/g, '([A-Za-z_$][A-Za-z0-9_$.]*)');
  regexStr = regexStr.replace(/\.\.\./g, '[\\s\\S]*?');
  return new RegExp(regexStr, 'g');
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

function compileGlobToRegex(glob: string): RegExp {
  let regex = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // escape regex chars (not * and ?)
    .replace(/\*\*/g, '__DOUBLESTAR__')
    .replace(/\*/g, '[^/]*')
    .replace(/__DOUBLESTAR__/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(regex);
}

function matchesPathFilter(
  filePath: string,
  paths?: { include?: string[]; exclude?: string[] },
): boolean {
  if (!paths) return true;

  if (paths.include && paths.include.length > 0) {
    const included = paths.include.some(glob => compileGlobToRegex(glob).test(filePath));
    if (!included) return false;
  }

  if (paths.exclude && paths.exclude.length > 0) {
    const excluded = paths.exclude.some(glob => compileGlobToRegex(glob).test(filePath));
    if (excluded) return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Rule → CheckDefinition conversion
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Extension → AstLanguage mapping (reverse of LANGUAGE_EXTENSIONS)
// ---------------------------------------------------------------------------

const EXT_TO_AST_LANGUAGE: Record<string, AstLanguage> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'tsx',
  py: 'python',
  go: 'go',
  rb: 'ruby',
};

// ---------------------------------------------------------------------------
// AST pattern check (file-level, structural matching via ast-grep)
// ---------------------------------------------------------------------------

function ruleToAstPatternCheck(rule: RuleDefinition): FileCheck {
  const excludeRe = rule['exclude-pattern'] ? new RegExp(rule['exclude-pattern']) : null;
  const appliesTo = languagesToExtensions(rule.languages);
  const category = mapCategory(rule.category);
  const paths = rule.paths;
  const fastFilter = rule.pattern ? extractFastFilter(rule.pattern) : undefined;
  const compoundOpts = extractCompoundOpts(rule);
  const pattern = rule.pattern ?? '';

  const check: FileCheck = {
    level: 'file',
    id: rule.id,
    name: rule.message.slice(0, 60),
    description: rule.message,
    category,
    defaultSeverity: rule.severity,
    appliesTo,
    fastFilter,

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Apply path filters
      if (paths && !matchesPathFilter(file.relativePath, paths)) return [];

      // Determine the AST language from the file extension
      const astLang = EXT_TO_AST_LANGUAGE[file.extension];
      if (!astLang) return [];

      // Load file content
      const content = file.content ?? await ctx.readFile(file.relativePath);
      const lines = file.lines ?? await ctx.readLines(file.relativePath);

      // Run ast-grep structural matching with compound operators
      const matches = await matchAstPattern(content, astLang, pattern, compoundOpts);
      const findings: Finding[] = [];

      for (const match of matches) {
        // Skip matches that are entirely on comment lines
        const matchLine = lines[match.startLine - 1] ?? '';
        if (isCommentLine(matchLine)) continue;

        // Apply exclude-pattern on matched text
        if (excludeRe && excludeRe.test(match.text)) continue;

        const { snippet, contextBefore, contextAfter } = extractSnippet(
          lines,
          match.startLine,
          ctx.config.contextLines,
        );

        const severity = ctx.config.severityOverrides.get(rule.id) ?? rule.severity;

        findings.push({
          checkId: rule.id,
          title: rule.message.slice(0, 80),
          message: rule.message,
          severity,
          category,
          location: {
            filePath: file.relativePath,
            startLine: match.startLine,
            startColumn: match.startColumn,
            endLine: match.endLine,
            endColumn: match.endColumn,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: rule.fix,
          fixCode: rule.fixCode,
          confidence: 'high',
        });
      }

      return findings;
    },
  };

  return check;
}

// ---------------------------------------------------------------------------
// Regex rule check (line-level, pattern-per-line matching)
// ---------------------------------------------------------------------------

/**
 * Returns true if a rule should use kind-based AST matching.
 * Kind-based rules have a `kind` field and target Python/Go/Ruby
 * where $METAVAR syntax doesn't work.
 */
function isKindBasedRule(rule: RuleDefinition): boolean {
  return !!(rule.kind && rule['pattern-mode'] === 'ast');
}

function ruleToCheck(rule: RuleDefinition): CheckDefinition {
  // Kind-based AST rules (Python/Go/Ruby) — no pattern needed
  if (isKindBasedRule(rule)) {
    return ruleToAstPatternCheck(rule);
  }

  // Dispatch to AST pattern check if the pattern qualifies
  if (rule.pattern && isAstGrepPattern(rule.pattern, rule['pattern-mode'])) {
    return ruleToAstPatternCheck(rule);
  }

  // Regex rules require a pattern string
  if (!rule.pattern) {
    throw new Error(`Rule ${rule.id} has no pattern`);
  }

  const compiledPattern = compilePattern(rule.pattern);
  const excludeRe = rule['exclude-pattern'] ? new RegExp(rule['exclude-pattern']) : null;
  const appliesTo = languagesToExtensions(rule.languages);
  const category = mapCategory(rule.category);
  const paths = rule.paths;

  // Regex rules become LineChecks (pattern-per-line matching)
  const check: LineCheck = {
    level: 'line',
    id: rule.id,
    name: rule.message.slice(0, 60),
    description: rule.message,
    category,
    defaultSeverity: rule.severity,
    appliesTo,
    pattern: compiledPattern,
    analyze(match: LineMatch, ctx: ScanContext): Finding | null {
      // Skip comment lines
      if (isCommentLine(match.line)) return null;

      // Apply exclude-pattern
      if (excludeRe && excludeRe.test(match.line)) return null;

      // Apply path filters
      if (paths && !matchesPathFilter(match.file.relativePath, paths)) return null;

      const lines = match.file.lines ?? [];
      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        match.lineNumber,
        ctx.config.contextLines,
      );

      const severity = ctx.config.severityOverrides.get(rule.id) ?? rule.severity;

      return {
        checkId: rule.id,
        title: rule.message.slice(0, 80),
        message: rule.message,
        severity,
        category,
        location: {
          filePath: match.file.relativePath,
          startLine: match.lineNumber,
          startColumn: match.regexMatch.index,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: rule.fix,
        fixCode: rule.fixCode,
        confidence: 'medium',
      };
    },
  };

  return check;
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

async function loadJsonRulesFile(filePath: string): Promise<RuleDefinition[]> {
  try {
    const content = await readFile(filePath, 'utf-8');
    const parsed: RulesFile = JSON.parse(content);
    if (!parsed.rules || !Array.isArray(parsed.rules)) {
      return [];
    }
    return parsed.rules.filter(
      (r) => r.id && r.message && r.severity && r.category && (r.pattern || r.kind),
    );
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Loads all rules from:
 *   1. Built-in rules (src/rules/builtin.json, resolved relative to this module)
 *   2. Project-level rules (.riplock-rules.json in projectRoot)
 *   3. Project-level rules directory (rules/*.json in projectRoot)
 */
export async function loadRules(projectRoot: string): Promise<CheckDefinition[]> {
  const allRules: RuleDefinition[] = [];

  // 1. Load built-in rules
  // Try multiple paths: dist/rules/builtin.json (production) and src/rules/builtin.json (dev)
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  let builtinPath = join(moduleDir, 'rules', 'builtin.json');
  if (!existsSync(builtinPath)) {
    builtinPath = join(moduleDir, '..', 'rules', 'builtin.json');
  }
  const builtinRules = await loadJsonRulesFile(builtinPath);
  allRules.push(...builtinRules);

  // 2. Load project-level rules from .riplock-rules.json
  const projectRulesPath = join(projectRoot, '.riplock-rules.json');
  if (existsSync(projectRulesPath)) {
    const projectRules = await loadJsonRulesFile(projectRulesPath);
    allRules.push(...projectRules);
  }

  // 3. Load project-level rules from rules/ directory
  const rulesDir = join(projectRoot, 'rules');
  if (existsSync(rulesDir)) {
    const { readdir } = await import('node:fs/promises');
    try {
      const entries = await readdir(rulesDir);
      for (const entry of entries) {
        if (entry.endsWith('.json')) {
          const rules = await loadJsonRulesFile(join(rulesDir, entry));
          allRules.push(...rules);
        }
      }
    } catch {
      // Ignore errors reading the rules directory
    }
  }

  // Convert all rules to CheckDefinitions
  const checks: CheckDefinition[] = [];
  for (const rule of allRules) {
    try {
      checks.push(ruleToCheck(rule));
    } catch {
      // Skip rules with invalid patterns
    }
  }

  return checks;
}
