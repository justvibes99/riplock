import type {
  TaintPath,
  TaintNode,
  SinkCategory,
  FileEntry,
  AstLanguage,
} from '../checks/types.js';
import type { ParsedFile } from './ast-parser.js';
import { resolve, dirname, relative } from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────

export interface CrossFileTaintResult {
  paths: TaintPath[];
}

/** What a file exports: function name → AST node */
interface ExportedFunction {
  name: string;
  funcNode: any;
  filePath: string;
}

/** What a file imports from a relative project file */
interface ProjectImport {
  localName: string;
  exportedName: string;
  resolvedPath: string;  // absolute path of the source module
}

/** Taint signature for a single function */
interface FunctionTaintSig {
  name: string;
  filePath: string;
  /** parameter index → sink categories it reaches */
  paramSinks: Map<number, SinkCategory[]>;
}

// ── AST helpers (mirrored from taint-tracker to keep module self-contained) ──

function walkTree(node: any, callback: (n: any) => void): void {
  callback(node);
  const count: number = node.childCount;
  for (let i = 0; i < count; i++) {
    const child = node.child(i);
    if (child) walkTree(child, callback);
  }
}

function findNodes(node: any, type: string): any[] {
  const result: any[] = [];
  walkTree(node, (n) => {
    if (n.type === type) result.push(n);
  });
  return result;
}

function getMemberExpressionText(node: any): string {
  if (node.type === 'member_expression') {
    const obj = node.childForFieldName('object');
    const prop = node.childForFieldName('property');
    if (obj && prop) {
      return getMemberExpressionText(obj) + '.' + prop.text;
    }
  }
  return node.text;
}

function containsTaintedRef(node: any, taintedVars: Set<string>): string | null {
  if (node.type === 'identifier' && taintedVars.has(node.text)) {
    return node.text;
  }
  if (node.type === 'shorthand_property_identifier_pattern' && taintedVars.has(node.text)) {
    return node.text;
  }
  if (node.type === 'member_expression') {
    const fullText = getMemberExpressionText(node);
    if (taintedVars.has(fullText)) return fullText;
    if (/^req\.(body|params|query|headers|cookies)(\.|$|\[)/.test(fullText) ||
        /^request\.(body|params|query|headers|cookies)(\.|$|\[)/.test(fullText)) {
      return fullText;
    }
  }
  const count: number = node.childCount;
  for (let i = 0; i < count; i++) {
    const child = node.child(i);
    if (child) {
      const found = containsTaintedRef(child, taintedVars);
      if (found) return found;
    }
  }
  return null;
}

// ── Module resolution ──────────────────────────────────────────────────

/** Check if an import specifier is a relative project import (not node_modules). */
function isRelativeImport(specifier: string): boolean {
  return specifier.startsWith('./') || specifier.startsWith('../');
}

const JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];

/**
 * Resolve a relative import specifier to an absolute file path.
 * Tries the specifier as-is, then with common JS/TS extensions, then as /index.
 */
function resolveImportPath(
  specifier: string,
  importerPath: string,
  fileSet: ReadonlySet<string>,
): string | null {
  const base = resolve(dirname(importerPath), specifier);

  // Exact match
  if (fileSet.has(base)) return base;

  // Try with extensions
  for (const ext of JS_EXTENSIONS) {
    const withExt = base + ext;
    if (fileSet.has(withExt)) return withExt;
  }

  // Try as directory index
  for (const ext of JS_EXTENSIONS) {
    const indexPath = resolve(base, 'index' + ext);
    if (fileSet.has(indexPath)) return indexPath;
  }

  return null;
}

// ── Export collection ──────────────────────────────────────────────────

const FUNCTION_TYPES = new Set([
  'function_declaration',
  'arrow_function',
  'method_definition',
  'function',
  'function_expression',
  'function_definition',
]);

/**
 * Collect all exported function names from a file's AST.
 * Handles: export function, export const, export default, export { ... }, module.exports.
 */
function collectExports(rootNode: any): Map<string, any> {
  const exports = new Map<string, any>(); // exportedName → funcNode

  walkTree(rootNode, (node) => {
    // ES: export function foo() { ... }
    if (node.type === 'export_statement') {
      // Walk children to find the declaration
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;

        // export function foo() { ... }
        if (child.type === 'function_declaration') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) exports.set(nameNode.text, child);
        }

        // export const foo = (...) => { ... }
        if (child.type === 'lexical_declaration' || child.type === 'variable_declaration') {
          const declarators = findNodes(child, 'variable_declarator');
          for (const decl of declarators) {
            const nameNode = decl.childForFieldName('name');
            const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
            if (nameNode && valueNode && FUNCTION_TYPES.has(valueNode.type)) {
              exports.set(nameNode.text, valueNode);
            }
          }
        }

        // export default function() { ... } or export default (...) => { ... }
        if (child.type === 'function_declaration' || child.type === 'function' || FUNCTION_TYPES.has(child.type)) {
          // Already handled above for named ones; handle default
          if (!exports.has('default') && node.text.includes('default')) {
            const nameNode = child.childForFieldName('name');
            const name = nameNode ? nameNode.text : 'default';
            exports.set(name, child);
            if (name !== 'default') exports.set('default', child);
          }
        }

        // export { foo, bar } — these reference names already in the file
        if (child.type === 'export_clause') {
          walkTree(child, (spec) => {
            if (spec.type === 'export_specifier') {
              const nameField = spec.childForFieldName('name');
              const aliasField = spec.childForFieldName('alias');
              const localName = nameField?.text;
              const exportedName = aliasField ? aliasField.text : localName;
              if (localName && exportedName) {
                // We need to find the actual function node for this name
                // Just store the name for now; we'll resolve the function node below
                exports.set(exportedName, localName);
              }
            }
          });
        }
      }
    }

    // CommonJS: module.exports = { foo, bar } or module.exports.foo = function() { ... }
    if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (!left || !right) return;

      const leftText = getMemberExpressionText(left);

      // module.exports.foo = function(...) { ... }
      if (leftText.startsWith('module.exports.') || leftText.startsWith('exports.')) {
        const exportName = leftText.startsWith('module.exports.')
          ? leftText.slice('module.exports.'.length)
          : leftText.slice('exports.'.length);
        if (FUNCTION_TYPES.has(right.type)) {
          exports.set(exportName, right);
        }
      }

      // module.exports = { foo, bar }
      if (leftText === 'module.exports' && right.type === 'object') {
        walkTree(right, (child) => {
          if (child.type === 'shorthand_property') {
            const ident = child.childCount > 0 ? child.child(0) : null;
            if (ident && ident.type === 'identifier') {
              exports.set(ident.text, ident.text); // placeholder, resolve later
            }
          }
          if (child.type === 'pair') {
            const key = child.childForFieldName('key');
            const val = child.childForFieldName('value');
            if (key && val && FUNCTION_TYPES.has(val.type)) {
              exports.set(key.text, val);
            }
          }
        });
      }
    }
  });

  // Resolve string references to actual function nodes
  const allFunctions = new Map<string, any>();
  walkTree(rootNode, (node) => {
    if (FUNCTION_TYPES.has(node.type)) {
      const name = getFunctionName(node);
      if (name) allFunctions.set(name, node);
    }
  });

  for (const [exportName, value] of exports) {
    if (typeof value === 'string') {
      const funcNode = allFunctions.get(value);
      if (funcNode) {
        exports.set(exportName, funcNode);
      } else {
        exports.delete(exportName);
      }
    }
  }

  return exports;
}

// ── Import collection (for cross-file resolution) ──────────────────────

/**
 * Collect all imports from relative project files.
 * Returns a list of ProjectImport objects for project-local imports only.
 */
function collectProjectImports(
  rootNode: any,
  importerPath: string,
  fileSet: ReadonlySet<string>,
): ProjectImport[] {
  const imports: ProjectImport[] = [];

  walkTree(rootNode, (node) => {
    // ES import
    if (node.type === 'import_statement') {
      const source = node.childForFieldName('source');
      if (!source) return;
      const specifier = source.text.replace(/['"]/g, '');
      if (!isRelativeImport(specifier)) return;

      const resolved = resolveImportPath(specifier, importerPath, fileSet);
      if (!resolved) return;

      // Check for re-exports: export { foo } from './bar'
      // (these are also import_statement in tree-sitter for TS)

      walkTree(node, (child) => {
        // Default import
        if (child.type === 'identifier' && child.parent?.type === 'import_clause') {
          imports.push({
            localName: child.text,
            exportedName: 'default',
            resolvedPath: resolved,
          });
        }
        // Named imports: import { foo, bar as baz }
        if (child.type === 'import_specifier') {
          const name = child.childForFieldName('name');
          const alias = child.childForFieldName('alias');
          const localName = alias ? alias.text : name?.text;
          const exportedName = name?.text;
          if (localName && exportedName) {
            imports.push({
              localName,
              exportedName,
              resolvedPath: resolved,
            });
          }
        }
        // Namespace import: import * as X from './file'
        if (child.type === 'namespace_import') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) {
            imports.push({
              localName: nameNode.text,
              exportedName: '*',
              resolvedPath: resolved,
            });
          }
        }
      });
    }

    // CommonJS require
    if (node.type === 'variable_declarator') {
      const init = node.childForFieldName('value') ?? node.childForFieldName('init');
      if (!init || init.type !== 'call_expression') return;

      const fn = init.childForFieldName('function');
      if (!fn || fn.text !== 'require') return;

      const args = init.childForFieldName('arguments');
      if (!args) return;
      let specifier: string | null = null;
      for (let i = 0; i < args.childCount; i++) {
        const arg = args.child(i);
        if (arg && arg.isNamed) {
          specifier = arg.text.replace(/['"]/g, '');
          break;
        }
      }
      if (!specifier || !isRelativeImport(specifier)) return;

      const resolved = resolveImportPath(specifier, importerPath, fileSet);
      if (!resolved) return;

      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;

      if (nameNode.type === 'identifier') {
        // const utils = require('./utils') — treat as default import
        imports.push({
          localName: nameNode.text,
          exportedName: 'default',
          resolvedPath: resolved,
        });
      } else if (nameNode.type === 'object_pattern') {
        // const { foo, bar } = require('./utils')
        walkTree(nameNode, (child) => {
          if (child.type === 'shorthand_property_identifier_pattern') {
            imports.push({
              localName: child.text,
              exportedName: child.text,
              resolvedPath: resolved,
            });
          } else if (child.type === 'pair_pattern') {
            const key = child.childForFieldName('key');
            const val = child.childForFieldName('value');
            const localName = val?.type === 'identifier' ? val.text : key?.text;
            const exportedName = key?.text;
            if (localName && exportedName) {
              imports.push({
                localName,
                exportedName,
                resolvedPath: resolved,
              });
            }
          }
        });
      }
    }
  });

  return imports;
}

// ── Re-export handling ─────────────────────────────────────────────────

/**
 * Detect re-exports: export { foo } from './other'
 * Returns list of { exportedName, sourceSpecifier, sourceName } tuples.
 */
function collectReExports(rootNode: any): Array<{
  exportedName: string;
  sourceSpecifier: string;
  sourceName: string;
}> {
  const reExports: Array<{
    exportedName: string;
    sourceSpecifier: string;
    sourceName: string;
  }> = [];

  walkTree(rootNode, (node) => {
    if (node.type !== 'export_statement') return;

    // Must have a source (from '...')
    const source = node.childForFieldName('source');
    if (!source) return;
    const specifier = source.text.replace(/['"]/g, '');
    if (!isRelativeImport(specifier)) return;

    // Look for export clause: export { foo, bar as baz } from './other'
    walkTree(node, (child) => {
      if (child.type === 'export_specifier') {
        const name = child.childForFieldName('name');
        const alias = child.childForFieldName('alias');
        const sourceName = name?.text;
        const exportedName = alias ? alias.text : sourceName;
        if (sourceName && exportedName) {
          reExports.push({ exportedName, sourceSpecifier: specifier, sourceName });
        }
      }
    });

    // export * from './other' — we skip namespace re-exports for simplicity
  });

  return reExports;
}

// ── Function name/param helpers ────────────────────────────────────────

function getFunctionName(funcNode: any): string | null {
  if (funcNode.type === 'function_declaration' || funcNode.type === 'function_definition') {
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) return nameNode.text;
  }
  if (funcNode.type === 'method_definition') {
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) return nameNode.text;
  }
  if (funcNode.parent?.type === 'variable_declarator') {
    const nameNode = funcNode.parent.childForFieldName('name');
    if (nameNode && nameNode.type === 'identifier') return nameNode.text;
  }
  return null;
}

function getFunctionParams(funcNode: any): string[] {
  const params: string[] = [];
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return params;
  for (let i = 0; i < paramsNode.childCount; i++) {
    const child = paramsNode.child(i);
    if (child && child.isNamed && child.type === 'identifier') {
      params.push(child.text);
    }
    if (child && child.isNamed && child.type === 'required_parameter') {
      const pattern = child.childForFieldName('pattern');
      if (pattern && pattern.type === 'identifier') {
        params.push(pattern.text);
      }
    }
  }
  return params;
}

// ── Taint propagation (simplified from taint-tracker.ts) ───────────────

interface TaintInfo {
  varName: string;
  sourceExpr: string;
  sourceLine: number;
  sourceCol: number;
  hops: TaintNode[];
}

function isUserInputSource(node: any): string | null {
  if (!node) return null;
  const text = node.text;

  if (node.type === 'member_expression') {
    const fullText = getMemberExpressionText(node);
    if (/^req\.(body|params|query|headers|cookies)(\.|\[|$)/.test(fullText) ||
        /^request\.(body|params|query|headers|cookies)(\.|\[|$)/.test(fullText) ||
        /^ctx\.(request\.body|params|query)(\.|\[)?/.test(fullText)) {
      return fullText;
    }
  }

  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    if (fn) {
      const fnText = getMemberExpressionText(fn);
      if (/^(formData|searchParams|urlSearchParams)\.get$/.test(fnText) ||
          /^req\.(json|text|formData|blob|arrayBuffer)$/.test(fnText) ||
          /^request\.(json|text|formData|blob|arrayBuffer)$/.test(fnText)) {
        return text;
      }
    }
  }

  if (node.type === 'await_expression') {
    const inner = node.childCount > 0 ? node.child(node.childCount - 1) : null;
    if (inner) return isUserInputSource(inner);
  }

  return null;
}

function detectSources(functionNode: any): TaintInfo[] {
  const sources: TaintInfo[] = [];
  const body = functionNode.childForFieldName('body') ?? functionNode;
  const declarators = findNodes(body, 'variable_declarator');

  for (const decl of declarators) {
    const nameNode = decl.childForFieldName('name');
    const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
    if (!nameNode || !valueNode) continue;

    if (nameNode.type === 'identifier') {
      const sourceExpr = isUserInputSource(valueNode);
      if (sourceExpr) {
        sources.push({
          varName: nameNode.text,
          sourceExpr,
          sourceLine: nameNode.startPosition.row + 1,
          sourceCol: nameNode.startPosition.column,
          hops: [{ expression: sourceExpr, line: valueNode.startPosition.row + 1, column: valueNode.startPosition.column }],
        });
      }
    }

    if (nameNode.type === 'object_pattern') {
      const sourceExpr = isUserInputSource(valueNode);
      if (sourceExpr) {
        walkTree(nameNode, (child) => {
          if (child.type === 'shorthand_property_identifier_pattern' ||
              (child.type === 'identifier' && child.parent?.type === 'pair_pattern')) {
            sources.push({
              varName: child.text,
              sourceExpr: sourceExpr + '.' + child.text,
              sourceLine: child.startPosition.row + 1,
              sourceCol: child.startPosition.column,
              hops: [{ expression: sourceExpr + '.' + child.text, line: child.startPosition.row + 1, column: child.startPosition.column }],
            });
          }
        });
      }
    }
  }

  // Assignment expressions
  const assignExprs = findNodes(body, 'assignment_expression');
  for (const assign of assignExprs) {
    const left = assign.childForFieldName('left');
    const right = assign.childForFieldName('right');
    if (!left || !right) continue;

    if (left.type === 'identifier') {
      const sourceExpr = isUserInputSource(right);
      if (sourceExpr) {
        sources.push({
          varName: left.text,
          sourceExpr,
          sourceLine: left.startPosition.row + 1,
          sourceCol: left.startPosition.column,
          hops: [{ expression: sourceExpr, line: right.startPosition.row + 1, column: right.startPosition.column }],
        });
      }
    }

    if (left.type === 'member_expression') {
      const sourceExpr = isUserInputSource(right);
      if (sourceExpr) {
        const fullName = getMemberExpressionText(left);
        sources.push({
          varName: fullName,
          sourceExpr,
          sourceLine: left.startPosition.row + 1,
          sourceCol: left.startPosition.column,
          hops: [{ expression: sourceExpr, line: right.startPosition.row + 1, column: right.startPosition.column }],
        });
      }
    }
  }

  return sources;
}

function findAssignments(node: any): Array<{ name: string; value: any; line: number; col: number }> {
  const result: Array<{ name: string; value: any; line: number; col: number }> = [];

  const declarators = findNodes(node, 'variable_declarator');
  for (const decl of declarators) {
    const nameNode = decl.childForFieldName('name');
    const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
    if (nameNode && nameNode.type === 'identifier' && valueNode) {
      result.push({ name: nameNode.text, value: valueNode, line: nameNode.startPosition.row + 1, col: nameNode.startPosition.column });
    }
  }

  const assignments = findNodes(node, 'assignment_expression');
  for (const assign of assignments) {
    const left = assign.childForFieldName('left');
    const right = assign.childForFieldName('right');
    if (left && left.type === 'identifier' && right) {
      result.push({ name: left.text, value: right, line: left.startPosition.row + 1, col: left.startPosition.column });
    } else if (left && left.type === 'member_expression' && right) {
      const fullName = getMemberExpressionText(left);
      result.push({ name: fullName, value: right, line: left.startPosition.row + 1, col: left.startPosition.column });
    }
  }

  return result;
}

function propagateTaint(functionNode: any, sources: TaintInfo[], maxDepth: number): TaintInfo[] {
  const tainted = new Map<string, TaintInfo>();
  for (const src of sources) {
    tainted.set(src.varName, src);
  }

  const body = functionNode.childForFieldName('body') ?? functionNode;
  const assignments = findAssignments(body);

  let changed = true;
  let iterations = 0;
  while (changed && iterations < maxDepth) {
    changed = false;
    iterations++;
    for (const { name, value, line, col } of assignments) {
      if (tainted.has(name)) continue;
      const taintRef = containsTaintedRef(value, new Set(tainted.keys()));
      if (taintRef) {
        const upstream = tainted.get(taintRef)!;
        tainted.set(name, {
          varName: name,
          sourceExpr: upstream.sourceExpr,
          sourceLine: upstream.sourceLine,
          sourceCol: upstream.sourceCol,
          hops: [...upstream.hops, { expression: name, line, column: col }],
        });
        changed = true;
      }
    }
  }

  return [...tainted.values()];
}

// ── Sink detection (imports-aware) ─────────────────────────────────────

function isParameterizedQuery(callNode: any): boolean {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;
  const argChildren: any[] = [];
  for (let i = 0; i < args.childCount; i++) {
    const child = args.child(i);
    if (child && child.isNamed) argChildren.push(child);
  }
  if (argChildren.length < 2) return false;
  const queryText = argChildren[0].text;
  const hasPlaceholders = /(\$\d+|\?|:\w+)/.test(queryText);
  const isArray = argChildren[1].type === 'array';
  return hasPlaceholders && isArray;
}

function collectFileImports(rootNode: any): Map<string, string> {
  const imports = new Map<string, string>();
  walkTree(rootNode, (node) => {
    if (node.type === 'import_statement') {
      const source = node.childForFieldName('source');
      if (!source) return;
      const moduleName = source.text.replace(/['"]/g, '');
      walkTree(node, (child) => {
        if (child.type === 'identifier' && child.parent?.type === 'import_clause') {
          imports.set(child.text, moduleName);
        }
        if (child.type === 'import_specifier') {
          const name = child.childForFieldName('name');
          const alias = child.childForFieldName('alias');
          const localName = alias ? alias.text : name?.text;
          if (localName) imports.set(localName, moduleName);
        }
        if (child.type === 'namespace_import') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) imports.set(nameNode.text, moduleName);
        }
      });
    }
    if (node.type === 'variable_declarator') {
      const init = node.childForFieldName('value') ?? node.childForFieldName('init');
      if (!init || init.type !== 'call_expression') return;
      const fn = init.childForFieldName('function');
      if (!fn || fn.text !== 'require') return;
      const args = init.childForFieldName('arguments');
      if (!args) return;
      let requireModule: string | null = null;
      for (let i = 0; i < args.childCount; i++) {
        const arg = args.child(i);
        if (arg && arg.isNamed) { requireModule = arg.text.replace(/['"]/g, ''); break; }
      }
      if (!requireModule) return;
      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;
      if (nameNode.type === 'identifier') {
        imports.set(nameNode.text, requireModule);
      } else if (nameNode.type === 'object_pattern') {
        walkTree(nameNode, (child) => {
          if (child.type === 'shorthand_property_identifier_pattern') {
            imports.set(child.text, requireModule!);
          } else if (child.type === 'pair_pattern') {
            const val = child.childForFieldName('value');
            const key = child.childForFieldName('key');
            if (val?.type === 'identifier') imports.set(val.text, requireModule!);
            else if (key?.type === 'identifier') imports.set(key.text, requireModule!);
          }
        });
      }
    }
  });
  return imports;
}

interface SinkHit {
  category: SinkCategory;
  node: any;
  argNode: any;
  taintRef: string;
  line: number;
  col: number;
}

function detectSinks(
  functionNode: any,
  taintedVars: Map<string, TaintInfo>,
  imports: Map<string, string>,
  categories: Set<SinkCategory>,
): SinkHit[] {
  const hits: SinkHit[] = [];
  const body = functionNode.childForFieldName('body') ?? functionNode;
  const taintedNames = new Set(taintedVars.keys());
  const calls = findNodes(body, 'call_expression');

  for (const call of calls) {
    const fn = call.childForFieldName('function');
    if (!fn) continue;
    const fnText = getMemberExpressionText(fn);
    const args = call.childForFieldName('arguments');

    if (categories.has('sql-query') &&
        /\.(query|exec|execute|raw|whereRaw|orderByRaw|havingRaw|joinRaw|literal|\$queryRawUnsafe|\$executeRawUnsafe|prepare)$/.test(fnText)) {
      if (isParameterizedQuery(call)) continue;
      if (args) {
        const ref = containsTaintedRef(args, taintedNames);
        if (ref) hits.push({ category: 'sql-query', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
      }
    }

    if (categories.has('shell-exec') &&
        /^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$/.test(fnText)) {
      const moduleName = imports.get(fnText);
      if (moduleName === 'child_process' || moduleName === 'node:child_process') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames);
          if (ref) hits.push({ category: 'shell-exec', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
        }
      }
    }

    if (categories.has('shell-exec') &&
        /^(child_process|cp)\.(exec|execSync|execFile|execFileSync|spawn|spawnSync)$/.test(fnText)) {
      const objName = fnText.split('.')[0];
      const moduleName = imports.get(objName);
      if (moduleName === 'child_process' || moduleName === 'node:child_process') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames);
          if (ref) hits.push({ category: 'shell-exec', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
        }
      }
    }

    if (categories.has('ssrf')) {
      const isSsrf = fnText === 'fetch' ||
        /^(axios|got|http|https)\.(get|post|put|patch|delete|request)$/.test(fnText) ||
        fnText === 'got' || fnText === 'axios';
      if (isSsrf && args) {
        let firstArg: any = null;
        for (let i = 0; i < args.childCount; i++) {
          const child = args.child(i);
          if (child && child.isNamed) { firstArg = child; break; }
        }
        if (firstArg) {
          const ref = containsTaintedRef(firstArg, taintedNames);
          if (ref) hits.push({ category: 'ssrf', node: call, argNode: firstArg, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
        }
      }
    }

    if (categories.has('xss') && (fnText === 'document.write' || fnText === 'document.writeln')) {
      if (args) {
        const ref = containsTaintedRef(args, taintedNames);
        if (ref) hits.push({ category: 'xss', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
      }
    }

    if (categories.has('path-traversal')) {
      const fsOps = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream', 'readdir', 'readdirSync', 'stat', 'statSync', 'access', 'accessSync', 'unlink', 'unlinkSync']);
      if (fsOps.has(fnText)) {
        const moduleName = imports.get(fnText);
        if (moduleName === 'fs' || moduleName === 'node:fs' || moduleName === 'fs/promises' || moduleName === 'node:fs/promises') {
          if (args) {
            let firstArg: any = null;
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.isNamed) { firstArg = child; break; }
            }
            if (firstArg) {
              const ref = containsTaintedRef(firstArg, taintedNames);
              if (ref) hits.push({ category: 'path-traversal', node: call, argNode: firstArg, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
            }
          }
        }
      }
      const parts = fnText.split('.');
      if (parts.length === 2 && fsOps.has(parts[1])) {
        const moduleName = imports.get(parts[0]);
        if (moduleName === 'fs' || moduleName === 'node:fs' || moduleName === 'fs/promises' || moduleName === 'node:fs/promises') {
          if (args) {
            let firstArg: any = null;
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.isNamed) { firstArg = child; break; }
            }
            if (firstArg) {
              const ref = containsTaintedRef(firstArg, taintedNames);
              if (ref) hits.push({ category: 'path-traversal', node: call, argNode: firstArg, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
            }
          }
        }
      }
    }

    if (categories.has('redirect') && /^res\.redirect$/.test(fnText)) {
      if (args) {
        const ref = containsTaintedRef(args, taintedNames);
        if (ref) hits.push({ category: 'redirect', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
      }
    }

    if (categories.has('eval') && fnText === 'eval') {
      if (args) {
        const ref = containsTaintedRef(args, taintedNames);
        if (ref) hits.push({ category: 'eval', node: call, argNode: args, taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column });
      }
    }
  }

  // XSS: .innerHTML assignment
  if (categories.has('xss')) {
    const assignExprs = findNodes(body, 'assignment_expression');
    for (const assign of assignExprs) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && right && left.type === 'member_expression') {
        const prop = left.childForFieldName('property');
        if (prop && prop.text === 'innerHTML') {
          const ref = containsTaintedRef(right, taintedNames);
          if (ref) hits.push({ category: 'xss', node: assign, argNode: right, taintRef: ref, line: assign.startPosition.row + 1, col: assign.startPosition.column });
        }
      }
    }
  }

  return hits;
}

// ── Build taint signatures for exported functions ──────────────────────

function buildExportedFunctionSignatures(
  exportedFunctions: Map<string, any>,
  rootNode: any,
  categories: Set<SinkCategory>,
): Map<string, FunctionTaintSig> {
  const signatures = new Map<string, FunctionTaintSig>();
  const imports = collectFileImports(rootNode);

  for (const [exportName, funcNode] of exportedFunctions) {
    if (!funcNode || typeof funcNode !== 'object') continue;
    if (!FUNCTION_TYPES.has(funcNode.type)) continue;

    const paramNames = getFunctionParams(funcNode);
    if (paramNames.length === 0) continue;

    const paramSinks = new Map<number, SinkCategory[]>();

    for (let i = 0; i < paramNames.length; i++) {
      const hypotheticalSource: TaintInfo = {
        varName: paramNames[i],
        sourceExpr: paramNames[i],
        sourceLine: 0,
        sourceCol: 0,
        hops: [{ expression: paramNames[i], line: 0, column: 0 }],
      };

      const allTainted = propagateTaint(funcNode, [hypotheticalSource], 10);
      const taintedMap = new Map<string, TaintInfo>();
      for (const t of allTainted) {
        taintedMap.set(t.varName, t);
      }

      const sinkHits = detectSinks(funcNode, taintedMap, imports, categories);
      if (sinkHits.length > 0) {
        const reachedCategories = [...new Set(sinkHits.map(h => h.category))];
        paramSinks.set(i, reachedCategories);
      }
    }

    if (paramSinks.size > 0) {
      signatures.set(exportName, {
        name: exportName,
        filePath: '', // filled in by caller
        paramSinks,
      });
    }
  }

  return signatures;
}

// ── Main entry point ───────────────────────────────────────────────────

/**
 * Find cross-file taint paths: data flowing from a source in file A
 * through an imported function to a sink in file B.
 */
export async function findCrossFileTaintPaths(
  files: ReadonlyMap<string, FileEntry>,
  categories: Set<SinkCategory>,
  parseFileFn: (file: FileEntry) => Promise<ParsedFile | null>,
  maxTaintDepth: number = 3,
): Promise<CrossFileTaintResult> {
  const paths: TaintPath[] = [];
  const fileSet = new Set(files.keys());

  // Phase 1: Parse all files and collect exports + project imports
  const parsedFiles = new Map<string, ParsedFile>();
  const fileExports = new Map<string, Map<string, any>>(); // filePath → exportName → funcNode
  const fileProjectImports = new Map<string, ProjectImport[]>();
  const fileReExports = new Map<string, Array<{ exportedName: string; sourceSpecifier: string; sourceName: string }>>();

  // Determine which files import from other project files
  // First pass: parse everything and collect structure
  for (const [absPath, file] of files) {
    const parsed = await parseFileFn(file);
    if (!parsed) continue;
    parsedFiles.set(absPath, parsed);

    const exports = collectExports(parsed.rootNode);
    fileExports.set(absPath, exports);

    const projectImports = collectProjectImports(parsed.rootNode, absPath, fileSet);
    if (projectImports.length > 0) {
      fileProjectImports.set(absPath, projectImports);
    }

    const reExports = collectReExports(parsed.rootNode);
    if (reExports.length > 0) {
      fileReExports.set(absPath, reExports);
    }
  }

  // Phase 2: Resolve re-exports (follow chains, with cycle detection)
  function resolveExportedFunction(
    filePath: string,
    exportName: string,
    visited: Set<string>,
  ): { funcNode: any; filePath: string } | null {
    const visitKey = `${filePath}::${exportName}`;
    if (visited.has(visitKey)) return null; // cycle
    visited.add(visitKey);

    const exports = fileExports.get(filePath);
    if (!exports) return null;

    const funcNode = exports.get(exportName);
    if (funcNode && typeof funcNode === 'object') {
      return { funcNode, filePath };
    }

    // Check re-exports
    const reExports = fileReExports.get(filePath);
    if (reExports) {
      for (const re of reExports) {
        if (re.exportedName === exportName) {
          const resolved = resolveImportPath(re.sourceSpecifier, filePath, fileSet);
          if (resolved) {
            return resolveExportedFunction(resolved, re.sourceName, visited);
          }
        }
      }
    }

    return null;
  }

  // Phase 3: Build taint signatures for all exported functions
  const globalSignatures = new Map<string, FunctionTaintSig>(); // "filePath::exportName" → sig

  for (const [filePath, exports] of fileExports) {
    const parsed = parsedFiles.get(filePath);
    if (!parsed) continue;

    const sigs = buildExportedFunctionSignatures(exports, parsed.rootNode, categories);
    for (const [exportName, sig] of sigs) {
      sig.filePath = filePath;
      globalSignatures.set(`${filePath}::${exportName}`, sig);
    }
  }

  // Phase 3b: Iterative signature propagation (N-level deep)
  // If function A calls function B (from another file), and B's param M reaches a sink,
  // then A's param N (which flows to B's arg M) inherits that sink category.
  // Repeat until fixpoint or maxTaintDepth iterations.
  for (let depth = 0; depth < maxTaintDepth; depth++) {
    let changed = false;

    for (const [filePath, exports] of fileExports) {
      const parsed = parsedFiles.get(filePath);
      if (!parsed) continue;

      // Get this file's imports to resolve called function names
      const projectImports = fileProjectImports.get(filePath) ?? [];
      if (projectImports.length === 0) continue;

      // Build a map: localName → resolved signature key
      const importedSigMap = new Map<string, { sigKey: string; sig: FunctionTaintSig }>();
      for (const imp of projectImports) {
        if (imp.exportedName === '*') continue;
        const resolution = resolveExportedFunction(imp.resolvedPath, imp.exportedName, new Set());
        if (!resolution) continue;

        let sigKey = `${resolution.filePath}::${imp.exportedName}`;
        let sig = globalSignatures.get(sigKey);
        if (!sig) {
          const funcName = getFunctionName(resolution.funcNode);
          if (funcName) {
            sigKey = `${resolution.filePath}::${funcName}`;
            sig = globalSignatures.get(sigKey);
          }
        }
        if (sig) {
          importedSigMap.set(imp.localName, { sigKey, sig });
        }
      }
      if (importedSigMap.size === 0) continue;

      for (const [exportName, funcNode] of exports) {
        if (!funcNode || typeof funcNode !== 'object') continue;
        if (!FUNCTION_TYPES.has(funcNode.type)) continue;

        const paramNames = getFunctionParams(funcNode);
        if (paramNames.length === 0) continue;

        const myKey = `${filePath}::${exportName}`;

        // For each parameter, propagate taint and see if it reaches any imported function call
        for (let paramIdx = 0; paramIdx < paramNames.length; paramIdx++) {
          const hypotheticalSource: TaintInfo = {
            varName: paramNames[paramIdx],
            sourceExpr: paramNames[paramIdx],
            sourceLine: 0,
            sourceCol: 0,
            hops: [{ expression: paramNames[paramIdx], line: 0, column: 0 }],
          };

          const allTainted = propagateTaint(funcNode, [hypotheticalSource], 10);
          const taintedNames = new Set(allTainted.map(t => t.varName));

          const body = funcNode.childForFieldName('body') ?? funcNode;
          const callExprs = findNodes(body, 'call_expression');

          for (const call of callExprs) {
            const fn = call.childForFieldName('function');
            if (!fn) continue;

            let calledName: string | null = null;
            if (fn.type === 'identifier') {
              calledName = fn.text;
            }
            if (!calledName) continue;

            const entry = importedSigMap.get(calledName);
            if (!entry) continue;

            // Check if our tainted parameter flows to any of the called function's arguments
            const args = call.childForFieldName('arguments');
            if (!args) continue;

            const argNodes: any[] = [];
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.isNamed) argNodes.push(child);
            }

            for (const [targetParamIdx, sinkCategories] of entry.sig.paramSinks) {
              if (targetParamIdx >= argNodes.length) continue;
              const argNode = argNodes[targetParamIdx];
              const taintRef = containsTaintedRef(argNode, taintedNames);
              if (!taintRef) continue;

              // This function's paramIdx flows to the called function's targetParamIdx,
              // which reaches the listed sink categories. Inherit them.
              let mySig = globalSignatures.get(myKey);
              if (!mySig) {
                mySig = {
                  name: exportName,
                  filePath,
                  paramSinks: new Map(),
                };
                globalSignatures.set(myKey, mySig);
              }

              const existing = mySig.paramSinks.get(paramIdx) ?? [];
              const existingSet = new Set(existing);
              for (const cat of sinkCategories) {
                if (!existingSet.has(cat)) {
                  existing.push(cat);
                  existingSet.add(cat);
                  changed = true;
                }
              }
              if (existing.length > 0) {
                mySig.paramSinks.set(paramIdx, existing);
              }
            }
          }
        }
      }
    }

    if (!changed) break; // fixpoint reached
  }

  // Phase 4: For each file with project imports, check if tainted data flows
  // into imported functions that have dangerous taint signatures.
  for (const [importerPath, projectImports] of fileProjectImports) {
    const parsed = parsedFiles.get(importerPath);
    if (!parsed) continue;

    // Find all function scopes in the importing file
    const functionScopes: any[] = [];
    walkTree(parsed.rootNode, (node) => {
      if (FUNCTION_TYPES.has(node.type)) functionScopes.push(node);
    });

    // Build a map: localName → resolved FunctionTaintSig
    const importedSigs = new Map<string, { sig: FunctionTaintSig; imp: ProjectImport }>();

    for (const imp of projectImports) {
      // For namespace imports, skip for now (too complex)
      if (imp.exportedName === '*') continue;

      // Resolve through re-exports
      const resolution = resolveExportedFunction(imp.resolvedPath, imp.exportedName, new Set());
      if (!resolution) continue;

      const sigKey = `${resolution.filePath}::${imp.exportedName}`;
      let sig = globalSignatures.get(sigKey);

      // Also try with the original name from the source file
      if (!sig) {
        const funcName = getFunctionName(resolution.funcNode);
        if (funcName) {
          const altKey = `${resolution.filePath}::${funcName}`;
          sig = globalSignatures.get(altKey);
        }
      }

      if (sig) {
        importedSigs.set(imp.localName, { sig, imp });
      }
    }

    if (importedSigs.size === 0) continue;

    // For each function scope in the importer, check taint flow
    for (const funcNode of functionScopes) {
      const sources = detectSources(funcNode);
      if (sources.length === 0) continue;

      const allTainted = propagateTaint(funcNode, sources, 10);
      const taintedMap = new Map<string, TaintInfo>();
      for (const t of allTainted) {
        taintedMap.set(t.varName, t);
      }
      if (taintedMap.size === 0) continue;

      const taintedNames = new Set(taintedMap.keys());
      const body = funcNode.childForFieldName('body') ?? funcNode;
      const callExprs = findNodes(body, 'call_expression');

      for (const call of callExprs) {
        const fn = call.childForFieldName('function');
        if (!fn) continue;

        let calledName: string | null = null;
        if (fn.type === 'identifier') {
          calledName = fn.text;
        } else if (fn.type === 'member_expression') {
          // For namespace imports: ns.foo(...)
          const obj = fn.childForFieldName('object');
          const prop = fn.childForFieldName('property');
          if (obj && prop) {
            // Check if obj is a namespace import that resolves to a file
            // For now, check direct identifier calls
            calledName = null; // Skip member expressions for cross-file
          }
        }
        if (!calledName) continue;

        const entry = importedSigs.get(calledName);
        if (!entry) continue;

        const { sig, imp } = entry;

        // Check each argument against the signature
        const args = call.childForFieldName('arguments');
        if (!args) continue;

        const argNodes: any[] = [];
        for (let i = 0; i < args.childCount; i++) {
          const child = args.child(i);
          if (child && child.isNamed) argNodes.push(child);
        }

        for (const [paramIdx, sinkCategories] of sig.paramSinks) {
          if (paramIdx >= argNodes.length) continue;
          const argNode = argNodes[paramIdx];
          const taintRef = containsTaintedRef(argNode, taintedNames);
          if (!taintRef) continue;

          const taintInfo = taintedMap.get(taintRef);
          if (!taintInfo) continue;

          for (const sinkCat of sinkCategories) {
            if (!categories.has(sinkCat)) continue;

            const importerRelative = [...files.values()].find(f => f.absolutePath === importerPath)?.relativePath ?? importerPath;
            const targetRelative = [...files.values()].find(f => f.absolutePath === sig.filePath)?.relativePath ?? sig.filePath;

            const source: TaintNode = {
              expression: taintInfo.sourceExpr,
              line: taintInfo.sourceLine,
              column: taintInfo.sourceCol,
            };

            const callText = call.text;
            const sink: TaintNode = {
              expression: callText.length > 120 ? callText.slice(0, 120) + '...' : callText,
              line: call.startPosition.row + 1,
              column: call.startPosition.column,
            };

            const intermediates: TaintNode[] = [
              ...taintInfo.hops.slice(1),
              {
                expression: `cross-file: ${calledName}() in ${targetRelative} (param ${paramIdx} → ${sinkCat})`,
                line: call.startPosition.row + 1,
                column: call.startPosition.column,
              },
            ];

            // Avoid duplicates
            const isDuplicate = paths.some(
              p => p.source.expression === source.expression &&
                   p.sink.line === sink.line &&
                   p.sink.column === sink.column &&
                   p.sinkCategory === sinkCat,
            );
            if (!isDuplicate) {
              paths.push({ source, intermediates, sink, sinkCategory: sinkCat });
            }
          }
        }
      }
    }
  }

  return { paths };
}
