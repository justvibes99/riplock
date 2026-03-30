/**
 * Intra-function taint tracking engine.
 *
 * Re-exports the public API from sub-modules:
 * - sources.ts — source detection (isUserInputSource, detectSources)
 * - sinks.ts — sink detection (detectSinks, isParameterizedQuery)
 * - sanitizers.ts — sanitizer detection
 * - propagation.ts — taint propagation (propagateTaint, findAssignments)
 * - imports.ts — import collection
 * - types.ts — shared types (TaintInfo, SinkHit, etc.)
 */
import type {
  TaintPath,
  TaintNode,
  TaintQueryOpts,
  SinkCategory,
  AstLanguage,
} from '../../checks/types.js';
import { walkTree, findNodes } from '../ast-helpers.js';
import { containsTaintedRef } from '../ast-helpers.js';
import { getMemberExpressionText } from '../ast-helpers.js';

import { collectImports } from './imports.js';
import { detectSources } from './sources.js';
import { detectSinks } from './sinks.js';
import { isSanitized } from './sanitizers.js';
import { propagateTaint } from './propagation.js';
import type { TaintInfo, FunctionTaintSignature } from './types.js';

// Re-export types for consumers
export type { TaintInfo, SinkHit, Assignment, FunctionTaintSignature } from './types.js';

// ── Function scope detection ─────────────────────────────────────────

const FUNCTION_TYPES = new Set([
  // JS/TS
  'function_declaration',
  'arrow_function',
  'method_definition',
  'function',
  'function_expression',
  // Python
  'function_definition',
  // Go
  // 'function_declaration' already included
  'method_declaration',       // Go method (func (t Type) Name() ...)
  // Ruby
  'method',                   // Ruby def ... end
  'singleton_method',         // Ruby def self.name ... end
  // PHP
  // 'function_definition' already included
  // 'method_declaration' already included
]);

/** Find all top-level function scopes in the AST. */
export function findFunctionScopes(rootNode: any): any[] {
  const scopes: any[] = [];
  walkTree(rootNode, (node) => {
    if (FUNCTION_TYPES.has(node.type)) {
      scopes.push(node);
    }
  });
  return scopes;
}

// ── Inter-function taint signatures ─────────────────────────────────

/**
 * Get the name of a function node, if it has one.
 * Handles function_declaration (name field), variable_declarator parent with arrow_function, etc.
 */
function getFunctionName(funcNode: any): string | null {
  // function_declaration: function foo() { ... } (JS/TS/Go/PHP)
  if (funcNode.type === 'function_declaration' || funcNode.type === 'function_definition') {
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) return nameNode.text;
  }
  // method_definition: foo() { ... } inside a class (JS/TS)
  if (funcNode.type === 'method_definition') {
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) return nameNode.text;
  }
  // Go: method_declaration: func (t Type) Name() { ... }
  if (funcNode.type === 'method_declaration') {
    const nameNode = funcNode.childForFieldName('name');
    if (nameNode) return nameNode.text;
  }
  // Ruby: method (def name ... end)
  if (funcNode.type === 'method' || funcNode.type === 'singleton_method') {
    const nameNode = funcNode.childForFieldName('name');
    if (!nameNode) {
      // Ruby methods may have the name as an identifier child
      for (let i = 0; i < funcNode.childCount; i++) {
        const child = funcNode.child(i);
        if (child && child.type === 'identifier') return child.text;
      }
    }
    if (nameNode) return nameNode.text;
  }
  // Arrow function or function expression assigned to a variable:
  // const foo = (...) => { ... }
  if (funcNode.parent?.type === 'variable_declarator') {
    const nameNode = funcNode.parent.childForFieldName('name');
    if (nameNode && nameNode.type === 'identifier') return nameNode.text;
  }
  return null;
}

/**
 * Get the parameter names of a function node as an ordered list.
 * Language-aware: handles different parameter node types.
 */
function getFunctionParams(funcNode: any, language?: AstLanguage): string[] {
  const params: string[] = [];
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return params;

  for (let i = 0; i < paramsNode.childCount; i++) {
    const child = paramsNode.child(i);
    if (!child || !child.isNamed) continue;

    // JS/TS: identifier
    if (child.type === 'identifier') {
      params.push(child.text);
    }
    // JS/TS: required_parameter (TypeScript typed params)
    if (child.type === 'required_parameter') {
      const pattern = child.childForFieldName('pattern');
      if (pattern && pattern.type === 'identifier') {
        params.push(pattern.text);
      }
    }
    // Go: parameter_declaration (name + type)
    if (child.type === 'parameter_declaration') {
      // Go parameter_declaration has identifier children for names
      for (let j = 0; j < child.childCount; j++) {
        const paramChild = child.child(j);
        if (paramChild && paramChild.type === 'identifier') {
          params.push(paramChild.text);
        }
      }
    }
    // PHP: simple_parameter ($name)
    if (child.type === 'simple_parameter') {
      const nameNode = child.childForFieldName('name');
      if (nameNode) params.push(nameNode.text);
    }
    // Ruby: identifiers within method parameters (already handled by 'identifier' above)
    // Python: identifiers within parameters
    if (child.type === 'default_parameter' || child.type === 'typed_parameter' || child.type === 'typed_default_parameter') {
      const nameNode = child.childForFieldName('name');
      if (nameNode && nameNode.type === 'identifier') {
        params.push(nameNode.text);
      }
    }
  }
  return params;
}

/**
 * Build function signatures for all named functions in the file.
 * For each function, treat every parameter as a hypothetical taint source,
 * then check which sinks it can reach.
 */
export function buildFunctionSignatures(
  rootNode: any,
  imports: Map<string, string>,
  categories: Set<SinkCategory>,
  language?: AstLanguage,
): Map<string, FunctionTaintSignature> {
  const signatures = new Map<string, FunctionTaintSignature>();
  const functions = findFunctionScopes(rootNode);

  for (const funcNode of functions) {
    const name = getFunctionName(funcNode);
    if (!name) continue;

    const paramNames = getFunctionParams(funcNode, language);
    if (paramNames.length === 0) continue;

    const paramSinks = new Map<number, SinkCategory[]>();

    // For each parameter, create a hypothetical taint source and see if it reaches a sink
    for (let i = 0; i < paramNames.length; i++) {
      const hypotheticalSource: TaintInfo = {
        varName: paramNames[i],
        sourceExpr: paramNames[i],
        sourceLine: 0,
        sourceCol: 0,
        hops: [{ expression: paramNames[i], line: 0, column: 0 }],
      };

      const allTainted = propagateTaint(funcNode, [hypotheticalSource], 10, language);
      const taintedMap = new Map<string, TaintInfo>();
      for (const t of allTainted) {
        taintedMap.set(t.varName, t);
      }

      const sinkHits = detectSinks(funcNode, taintedMap, imports, categories, language);
      if (sinkHits.length > 0) {
        const reachedCategories = [...new Set(sinkHits.map(h => h.category))];
        paramSinks.set(i, reachedCategories);
      }
    }

    if (paramSinks.size > 0) {
      signatures.set(name, { name, node: funcNode, paramSinks });
    }
  }

  return signatures;
}

// ── Main entry point ─────────────────────────────────────────────────

/**
 * Find all taint paths from user-input sources to dangerous sinks
 * within the given AST.
 */
export function findTaintPaths(
  rootNode: any,
  language: AstLanguage,
  opts: TaintQueryOpts,
): TaintPath[] {
  const paths: TaintPath[] = [];
  const maxDepth = opts.maxDepth ?? 10;
  const categories = new Set(opts.sinkCategories);

  // Collect file-level imports (needed for module-aware sink detection)
  const imports = collectImports(rootNode, language);

  // Find all function scopes
  const functions = findFunctionScopes(rootNode);

  // For PHP: also treat the top-level program/php_tag scope as a function scope
  // since PHP code often runs outside function definitions
  if (language === 'php' && !functions.some(f => f === rootNode)) {
    functions.push(rootNode);
  }

  for (const funcNode of functions) {
    // Step 2: Detect taint sources in this function
    const sources = detectSources(funcNode, language);

    // Step 3: Forward propagation (even with no sources, we still check sinks for direct refs)
    const allTainted = propagateTaint(funcNode, sources, maxDepth, language);
    const taintedMap = new Map<string, TaintInfo>();
    for (const t of allTainted) {
      taintedMap.set(t.varName, t);
    }

    // Step 4: Detect sinks with tainted arguments
    const sinkHits = detectSinks(funcNode, taintedMap, imports, categories, language);

    // Step 5: Filter out sanitized paths, then build TaintPath results
    for (const hit of sinkHits) {
      const taintInfo = taintedMap.get(hit.taintRef);
      // If taintInfo is null, the ref was a direct req.body.* expression (no variable indirection)
      const directSource = !taintInfo;

      // Check sanitization (skip for direct sources with no taintInfo)
      if (taintInfo && isSanitized(taintInfo, hit.category, funcNode)) continue;

      const source: TaintNode = directSource
        ? { expression: hit.taintRef, line: hit.line, column: hit.col }
        : { expression: taintInfo!.sourceExpr, line: taintInfo!.sourceLine, column: taintInfo!.sourceCol };

      const sink: TaintNode = {
        expression: hit.node.text.length > 120
          ? hit.node.text.slice(0, 120) + '...'
          : hit.node.text,
        line: hit.line,
        column: hit.col,
      };

      // Intermediates are the hops between source and sink (excluding the source hop itself)
      const intermediates: TaintNode[] = directSource ? [] : taintInfo!.hops.slice(1);

      paths.push({
        source,
        intermediates,
        sink,
        sinkCategory: hit.category,
      });
    }
  }

  // -- Phase 2: Inter-function taint (same file) --
  // Build signatures for all named functions, then re-scan scopes with
  // actual taint sources to find cross-function flows.
  const signatures = buildFunctionSignatures(rootNode, imports, categories, language);

  if (signatures.size > 0) {
    for (const funcNode of functions) {
      const sources = detectSources(funcNode, language);
      if (sources.length === 0) continue;

      const allTainted = propagateTaint(funcNode, sources, maxDepth, language);
      const taintedMap = new Map<string, TaintInfo>();
      for (const t of allTainted) {
        taintedMap.set(t.varName, t);
      }

      if (taintedMap.size === 0) continue;

      const body = funcNode.childForFieldName('body') ?? funcNode;
      const callExprs = findNodes(body, 'call_expression');
      const taintedNames = new Set(taintedMap.keys());

      for (const call of callExprs) {
        const fn = call.childForFieldName('function');
        if (!fn) continue;

        // Resolve called function name
        let calledName: string | null = null;
        if (fn.type === 'identifier') {
          calledName = fn.text;
        } else if (fn.type === 'member_expression') {
          // For method calls, check the property name
          const prop = fn.childForFieldName('property');
          if (prop) calledName = prop.text;
        }
        if (!calledName) continue;

        const sig = signatures.get(calledName);
        if (!sig) continue;

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
          const taintRef = containsTaintedRef(argNode, taintedNames, language);
          if (!taintRef) continue;

          const taintInfo = taintedMap.get(taintRef);
          if (!taintInfo) continue;

          for (const sinkCat of sinkCategories) {
            if (!categories.has(sinkCat)) continue;

            // Check sanitization
            if (isSanitized(taintInfo, sinkCat, funcNode)) continue;

            // Avoid duplicate paths (same source line + same sink line)
            const callLine = call.startPosition.row + 1;
            const callCol = call.startPosition.column;
            const isDuplicate = paths.some(
              p => p.source.expression === taintInfo.sourceExpr &&
                   p.sink.line === callLine && p.sink.column === callCol,
            );
            if (isDuplicate) continue;

            const source: TaintNode = {
              expression: taintInfo.sourceExpr,
              line: taintInfo.sourceLine,
              column: taintInfo.sourceCol,
            };

            const callText = call.text;
            const sink: TaintNode = {
              expression: callText.length > 120
                ? callText.slice(0, 120) + '...'
                : callText,
              line: callLine,
              column: callCol,
            };

            const intermediates: TaintNode[] = [
              ...taintInfo.hops.slice(1),
              {
                expression: `${calledName}(${sig.name} param ${paramIdx})`,
                line: callLine,
                column: callCol,
              },
            ];

            paths.push({
              source,
              intermediates,
              sink,
              sinkCategory: sinkCat,
            });
          }
        }
      }
    }
  }

  return paths;
}
