/**
 * ast-grep pattern matching integration for RipLock.
 *
 * Uses @ast-grep/napi to perform structural (AST-level) pattern matching
 * on JavaScript, TypeScript, TSX, Python, Go, and Ruby files.
 *
 * For JS/TS/TSX, $METAVAR syntax works because $ is a valid identifier char.
 * For Python/Go/Ruby, kind-based matching is used instead: rules specify
 * `kind` + `regex` + `has` to match AST nodes without needing metavariables.
 *
 * Supports compound operators (inside, has, not, follows, precedes, all, any)
 * which compose recursively for Semgrep-level expressiveness.
 */

import { join } from 'node:path';
import { createRequire } from 'node:module';
import { platform, arch } from 'node:os';
import type { AstLanguage } from '../checks/types.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface AstPatternMatch {
  text: string;
  startLine: number;   // 1-indexed
  startColumn: number; // 0-indexed
  endLine: number;
  endColumn: number;
  metaVariables: Map<string, string>;
}

/**
 * A recursive sub-pattern used in compound operators.
 * Each field mirrors the ast-grep rule config — they compose recursively.
 */
export interface RulePattern {
  pattern?: string;
  kind?: string;
  regex?: string;
  inside?: RulePattern;
  has?: RulePattern;
  'has-not'?: RulePattern;
  not?: RulePattern;
  follows?: RulePattern;
  precedes?: RulePattern;
  all?: RulePattern[];
  any?: RulePattern[];
}

/**
 * Options for compound rule operators passed alongside the primary pattern.
 */
export interface CompoundRuleOpts {
  inside?: RulePattern;
  has?: RulePattern;
  hasNot?: RulePattern;
  not?: RulePattern;
  follows?: RulePattern;
  precedes?: RulePattern;
  all?: RulePattern[];
  any?: RulePattern[];
  kind?: string;
  regex?: string;
}

// ---------------------------------------------------------------------------
// Lazy import of @ast-grep/napi
// ---------------------------------------------------------------------------

let _astGrep: typeof import('@ast-grep/napi') | null = null;

async function getAstGrep() {
  if (!_astGrep) {
    _astGrep = await import('@ast-grep/napi');
  }
  return _astGrep;
}

// ---------------------------------------------------------------------------
// Language mapping
// ---------------------------------------------------------------------------

// JS/TS/TSX use ast-grep's built-in Lang enum ($METAVAR works natively).
// Python/Go/Ruby use dynamic language registration (kind-based matching).
const BUILTIN_LANGUAGES = new Set<AstLanguage>(['javascript', 'typescript', 'tsx']);
const DYNAMIC_LANGUAGES = new Set<AstLanguage>(['python', 'go', 'ruby']);
const ALL_AST_LANGUAGES = new Set<AstLanguage>([...BUILTIN_LANGUAGES, ...DYNAMIC_LANGUAGES]);

function mapBuiltinLanguage(lang: AstLanguage): string | null {
  switch (lang) {
    case 'javascript': return 'JavaScript';
    case 'typescript': return 'TypeScript';
    case 'tsx': return 'Tsx';
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// Dynamic language registration (Python, Go, Ruby)
// ---------------------------------------------------------------------------

/**
 * Resolve the path to a tree-sitter grammar's prebuilt .node file
 * for the current platform (e.g., darwin-arm64, linux-x64).
 */
function resolvePrebuild(packageName: string, binaryName: string): string {
  const require = createRequire(import.meta.url);
  const pkgDir = join(require.resolve(`${packageName}/package.json`), '..');
  const platformArch = `${platform()}-${arch()}`;
  return join(pkgDir, 'prebuilds', platformArch, `${binaryName}.node`);
}

const DYNAMIC_LANG_CONFIGS: Record<string, {
  packageName: string;
  binaryName: string;
  languageSymbol: string;
  extensions: string[];
}> = {
  python: {
    packageName: 'tree-sitter-python',
    binaryName: 'tree-sitter-python',
    languageSymbol: 'tree_sitter_python',
    extensions: ['py'],
  },
  go: {
    packageName: 'tree-sitter-go',
    binaryName: 'tree-sitter-go',
    languageSymbol: 'tree_sitter_go',
    extensions: ['go'],
  },
  ruby: {
    packageName: 'tree-sitter-ruby',
    binaryName: 'tree-sitter-ruby',
    languageSymbol: 'tree_sitter_ruby',
    extensions: ['rb'],
  },
};

let _dynamicLanguagesRegistered = false;

/**
 * Register Python, Go, and Ruby with ast-grep's dynamic language system.
 * Called once lazily on first use. Uses the prebuilt .node files from
 * the tree-sitter grammar packages.
 */
async function ensureDynamicLanguages(): Promise<void> {
  if (_dynamicLanguagesRegistered) return;

  const ag = await getAstGrep();
  const registrations: Record<string, {
    libraryPath: string;
    extensions: string[];
    languageSymbol: string;
  }> = {};

  for (const [name, config] of Object.entries(DYNAMIC_LANG_CONFIGS)) {
    try {
      registrations[name] = {
        libraryPath: resolvePrebuild(config.packageName, config.binaryName),
        extensions: config.extensions,
        languageSymbol: config.languageSymbol,
      };
    } catch {
      // Grammar package not installed — skip this language
    }
  }

  if (Object.keys(registrations).length > 0) {
    ag.registerDynamicLanguage(registrations);
  }
  _dynamicLanguagesRegistered = true;
}

/**
 * Exported for testing: reset the registration flag so tests can re-register.
 * @internal
 */
export function _resetDynamicLanguages(): void {
  _dynamicLanguagesRegistered = false;
}

// ---------------------------------------------------------------------------
// Pattern classification
// ---------------------------------------------------------------------------

/** Regex metacharacters that indicate a pattern is a regex, not code */
const REGEX_META_RE = /\\[sSwWdDbB]|\[\^|(?:\(\?[:!=<])/;

/** Metavariable pattern: $UPPERCASE_NAME */
const METAVAR_RE = /\$[A-Z][A-Z0-9_]*/;

/**
 * Check if a pattern should use ast-grep (structural matching) vs regex.
 *
 * Returns true if:
 *   - explicitMode is 'ast', OR
 *   - The pattern contains $METAVAR tokens AND does NOT contain regex metacharacters
 */
export function isAstGrepPattern(pattern: string, explicitMode?: 'ast' | 'regex'): boolean {
  if (explicitMode === 'ast') return true;
  if (explicitMode === 'regex') return false;
  return METAVAR_RE.test(pattern) && !REGEX_META_RE.test(pattern);
}

// ---------------------------------------------------------------------------
// Extract metavariable names from a pattern
// ---------------------------------------------------------------------------

const METAVAR_NAMES_RE = /\$([A-Z][A-Z0-9_]*)/g;

function extractMetaVarNames(pattern: string): string[] {
  const names: string[] = [];
  let m: RegExpExecArray | null;
  METAVAR_NAMES_RE.lastIndex = 0;
  while ((m = METAVAR_NAMES_RE.exec(pattern)) !== null) {
    if (!names.includes(m[1])) {
      names.push(m[1]);
    }
  }
  return names;
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Build ast-grep rule config from a RulePattern
// ---------------------------------------------------------------------------

/**
 * Recursively converts a RulePattern into the flat rule object format
 * that ast-grep's NAPI expects for compound operators.
 *
 * Relational operators (inside, has, follows, precedes) automatically
 * get `stopBy: 'end'` to traverse the full ancestor/descendant chain
 * rather than only checking the immediate parent/child.
 */
function buildRuleConfig(rp: RulePattern): Record<string, unknown> {
  const rule: Record<string, unknown> = {};

  if (rp.pattern) rule.pattern = rp.pattern;
  if (rp.kind) rule.kind = rp.kind;
  if (rp.regex) rule.regex = rp.regex;

  // Relational operators: flat sub-rule + stopBy: 'end'
  if (rp.inside) rule.inside = { ...buildRuleConfig(rp.inside), stopBy: 'end' };
  if (rp.has) rule.has = { ...buildRuleConfig(rp.has), stopBy: 'end' };
  if (rp.follows) rule.follows = { ...buildRuleConfig(rp.follows), stopBy: 'end' };
  if (rp.precedes) rule.precedes = { ...buildRuleConfig(rp.precedes), stopBy: 'end' };

  // has-not: expressed as not: { has: { sub, stopBy: 'end' } }
  if (rp['has-not'] || (rp as any).hasNot) {
    const sub = rp['has-not'] ?? (rp as any).hasNot;
    rule.not = { has: { ...buildRuleConfig(sub), stopBy: 'end' } };
  }

  // Logical operators: flat sub-rules (no wrapper)
  if (rp.not) rule.not = buildRuleConfig(rp.not);
  if (rp.all) rule.all = rp.all.map(sub => buildRuleConfig(sub));
  if (rp.any) rule.any = rp.any.map(sub => buildRuleConfig(sub));

  return rule;
}

/**
 * Resolve the ast-grep language identifier for a given AstLanguage.
 * For built-in languages, returns the Lang enum value.
 * For dynamic languages, returns the registered name string.
 */
async function resolveLanguage(language: AstLanguage): Promise<string | null> {
  if (BUILTIN_LANGUAGES.has(language)) {
    const langStr = mapBuiltinLanguage(language);
    if (!langStr) return null;
    const ag = await getAstGrep();
    const Lang = ag.Lang as Record<string, string>;
    return Lang[langStr] ?? null;
  }

  if (DYNAMIC_LANGUAGES.has(language)) {
    await ensureDynamicLanguages();
    // Dynamic languages are registered under their lowercase name
    return language;
  }

  return null;
}

/**
 * Match a structural pattern against source code using ast-grep.
 *
 * Returns all matches with their locations (1-indexed lines) and
 * captured metavariable bindings.
 *
 * Supports all languages: JS/TS/TSX via $METAVAR patterns,
 * Python/Go/Ruby via kind-based matching.
 *
 * Returns an empty array for unsupported languages (php).
 *
 * When `ruleOpts` is provided, compound operators (inside, has, not, etc.)
 * are merged into the ast-grep rule config for Semgrep-level expressiveness.
 */
export async function matchAstPattern(
  code: string,
  language: AstLanguage,
  pattern: string,
  ruleOpts?: CompoundRuleOpts,
): Promise<AstPatternMatch[]> {
  // Unsupported languages fall through to regex
  if (!ALL_AST_LANGUAGES.has(language)) {
    return [];
  }

  // For dynamic languages (Python/Go/Ruby), pattern-based matching with
  // $METAVAR won't work — require kind-based ruleOpts instead
  if (DYNAMIC_LANGUAGES.has(language) && !ruleOpts?.kind && !ruleOpts?.regex) {
    return [];
  }

  const lang = await resolveLanguage(language);
  if (!lang) return [];

  const ag = await getAstGrep();

  // Build the rule config, merging compound operators if present
  const rule: Record<string, unknown> = {};

  // For built-in languages, pattern with $METAVAR works directly.
  // For dynamic languages, only use pattern if it doesn't contain $METAVAR.
  if (pattern && (BUILTIN_LANGUAGES.has(language) || !METAVAR_RE.test(pattern))) {
    rule.pattern = pattern;
  }

  if (ruleOpts) {
    if (ruleOpts.kind) rule.kind = ruleOpts.kind;
    if (ruleOpts.regex) rule.regex = ruleOpts.regex;

    // Relational operators: flat sub-rule + stopBy: 'end'
    if (ruleOpts.inside) rule.inside = { ...buildRuleConfig(ruleOpts.inside), stopBy: 'end' };
    if (ruleOpts.has) rule.has = { ...buildRuleConfig(ruleOpts.has), stopBy: 'end' };
    if (ruleOpts.follows) rule.follows = { ...buildRuleConfig(ruleOpts.follows), stopBy: 'end' };
    if (ruleOpts.precedes) rule.precedes = { ...buildRuleConfig(ruleOpts.precedes), stopBy: 'end' };

    // has-not: not: { has: { sub, stopBy: 'end' } }
    if (ruleOpts.hasNot) {
      rule.not = { has: { ...buildRuleConfig(ruleOpts.hasNot), stopBy: 'end' } };
    }
    if (ruleOpts.not && !ruleOpts.hasNot) {
      rule.not = buildRuleConfig(ruleOpts.not);
    }
    // If both not and hasNot are present, combine via `all`
    if (ruleOpts.not && ruleOpts.hasNot) {
      const allRules: Record<string, unknown>[] = [];
      allRules.push({ not: buildRuleConfig(ruleOpts.not) });
      allRules.push({ not: { has: { ...buildRuleConfig(ruleOpts.hasNot), stopBy: 'end' } } });
      if (ruleOpts.all) {
        for (const sub of ruleOpts.all) {
          allRules.push(buildRuleConfig(sub));
        }
      }
      rule.all = allRules;
    } else if (ruleOpts.all) {
      rule.all = ruleOpts.all.map(sub => buildRuleConfig(sub));
    }

    if (ruleOpts.any) rule.any = ruleOpts.any.map(sub => buildRuleConfig(sub));
  }

  const root = ag.parse(lang as any, code);
  const nodes = root.root().findAll({ rule });

  const metaVarNames = pattern ? extractMetaVarNames(pattern) : [];
  const results: AstPatternMatch[] = [];

  for (const node of nodes) {
    const range = node.range();
    const metaVariables = new Map<string, string>();

    for (const name of metaVarNames) {
      const captured = node.getMatch(name);
      if (captured) {
        metaVariables.set(name, captured.text());
      }
    }

    results.push({
      text: node.text(),
      startLine: range.start.line + 1,   // convert 0-indexed to 1-indexed
      startColumn: range.start.column,
      endLine: range.end.line + 1,
      endColumn: range.end.column,
      metaVariables,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Fast filter extraction
// ---------------------------------------------------------------------------

/**
 * Extract the longest literal substring from a pattern for pre-filtering.
 * Strips $METAVAR tokens and returns the longest remaining word-like fragment.
 */
export function extractFastFilter(pattern: string): string | undefined {
  // Remove metavariables
  const stripped = pattern.replace(/\$[A-Z][A-Z0-9_]*/g, ' ');
  // Split on whitespace and non-word chars, find longest chunk
  const chunks = stripped.split(/[\s(){}[\]=,;:+\-*/<>!&|^~?@#]+/).filter(Boolean);
  if (chunks.length === 0) return undefined;

  let longest = '';
  for (const chunk of chunks) {
    // Only consider chunks that are meaningful identifiers or keywords (>= 2 chars)
    if (chunk.length > longest.length && chunk.length >= 2) {
      longest = chunk;
    }
  }

  return longest || undefined;
}
