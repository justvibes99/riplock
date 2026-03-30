import type {
  TaintPath,
  TaintNode,
  SinkCategory,
  FileEntry,
  AstLanguage,
} from '../checks/types.js';
import type { ParsedFile } from './ast-parser.js';
import type { SyntaxNode } from './ast-helpers.js';
import { resolve, dirname, relative } from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────

export interface CrossFileTaintResult {
  paths: TaintPath[];
}

/** What a file exports: function name → AST node */
interface ExportedFunction {
  name: string;
  funcNode: SyntaxNode;
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

// ── Shared AST helpers ──
import { walkTree, findNodes, getMemberExpressionText, containsTaintedRef } from './ast-helpers.js';

// ── Taint sub-modules ──
import { detectSources } from './taint/sources.js';
import { propagateTaint } from './taint/propagation.js';
import { detectSinks } from './taint/sinks.js';
import { collectImports } from './taint/imports.js';
import { getFunctionName, getFunctionParams } from './taint/index.js';
import type { TaintInfo } from './taint/types.js';

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
function collectExports(rootNode: SyntaxNode): Map<string, SyntaxNode> {
  // Intermediate map: values are SyntaxNode (direct function exports) or string
  // (named references like `export { foo }` that get resolved to nodes at the end)
  const pending = new Map<string, SyntaxNode | string>();

  walkTree(rootNode, (node) => {
    // ES: export function foo() { ... }
    if (node.type === 'export_statement') {
      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (!child) continue;

        if (child.type === 'function_declaration') {
          const nameNode = child.childForFieldName('name');
          if (nameNode) pending.set(nameNode.text, child);
        }

        if (child.type === 'lexical_declaration' || child.type === 'variable_declaration') {
          const declarators = findNodes(child, 'variable_declarator');
          for (const decl of declarators) {
            const nameNode = decl.childForFieldName('name');
            const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
            if (nameNode && valueNode && FUNCTION_TYPES.has(valueNode.type)) {
              pending.set(nameNode.text, valueNode);
            }
          }
        }

        if (child.type === 'function_declaration' || child.type === 'function' || FUNCTION_TYPES.has(child.type)) {
          if (!pending.has('default') && node.text.includes('default')) {
            const nameNode = child.childForFieldName('name');
            const name = nameNode ? nameNode.text : 'default';
            pending.set(name, child);
            if (name !== 'default') pending.set('default', child);
          }
        }

        // export { foo, bar } — store name strings, resolved to nodes below
        if (child.type === 'export_clause') {
          walkTree(child, (spec) => {
            if (spec.type === 'export_specifier') {
              const nameField = spec.childForFieldName('name');
              const aliasField = spec.childForFieldName('alias');
              const localName = nameField?.text;
              const exportedName = aliasField ? aliasField.text : localName;
              if (localName && exportedName) {
                pending.set(exportedName, localName);
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

      if (leftText.startsWith('module.exports.') || leftText.startsWith('exports.')) {
        const exportName = leftText.startsWith('module.exports.')
          ? leftText.slice('module.exports.'.length)
          : leftText.slice('exports.'.length);
        if (FUNCTION_TYPES.has(right.type)) {
          pending.set(exportName, right);
        }
      }

      if (leftText === 'module.exports' && right.type === 'object') {
        walkTree(right, (child) => {
          if (child.type === 'shorthand_property') {
            const ident = child.childCount > 0 ? child.child(0) : null;
            if (ident && ident.type === 'identifier') {
              pending.set(ident.text, ident.text);
            }
          }
          if (child.type === 'pair') {
            const key = child.childForFieldName('key');
            const val = child.childForFieldName('value');
            if (key && val && FUNCTION_TYPES.has(val.type)) {
              pending.set(key.text, val);
            }
          }
        });
      }
    }
  });

  // Resolve string references to actual function nodes
  const allFunctions = new Map<string, SyntaxNode>();
  walkTree(rootNode, (node) => {
    if (FUNCTION_TYPES.has(node.type)) {
      const name = getFunctionName(node);
      if (name) allFunctions.set(name, node);
    }
  });

  const resolved = new Map<string, SyntaxNode>();
  for (const [exportName, value] of pending) {
    if (typeof value === 'string') {
      const funcNode = allFunctions.get(value);
      if (funcNode) resolved.set(exportName, funcNode);
    } else {
      resolved.set(exportName, value);
    }
  }

  return resolved;
}

// ── Import collection (for cross-file resolution) ──────────────────────

/**
 * Collect all imports from relative project files.
 * Returns a list of ProjectImport objects for project-local imports only.
 */
function collectProjectImports(
  rootNode: SyntaxNode,
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
function collectReExports(rootNode: SyntaxNode): Array<{
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

// ── Build taint signatures for exported functions ──────────────────────

function buildExportedFunctionSignatures(
  exportedFunctions: Map<string, SyntaxNode>,
  rootNode: SyntaxNode,
  categories: Set<SinkCategory>,
  sourceFilePath = '',
): Map<string, FunctionTaintSig> {
  const signatures = new Map<string, FunctionTaintSig>();
  const imports = collectImports(rootNode);

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
        filePath: sourceFilePath,
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
  const fileExports = new Map<string, Map<string, SyntaxNode>>(); // filePath → exportName → funcNode
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
  ): { funcNode: SyntaxNode; filePath: string } | null {
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

    const sigs = buildExportedFunctionSignatures(exports, parsed.rootNode, categories, filePath);
    for (const [exportName, sig] of sigs) {
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

            const argNodes: SyntaxNode[] = [];
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
    const functionScopes: SyntaxNode[] = [];
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

        const argNodes: SyntaxNode[] = [];
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
                filePath: targetRelative,
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
