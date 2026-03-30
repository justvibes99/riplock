/**
 * Taint propagation engine.
 * Forward-propagates taint through assignments using fixpoint iteration.
 */
import type { AstLanguage } from '../../checks/types.js';
import type { SyntaxNode } from '../ast-helpers.js';
import { findNodes, getMemberExpressionText } from '../ast-helpers.js';
import { containsTaintedRef } from '../ast-helpers.js';
import type { TaintInfo, Assignment } from './types.js';

/**
 * Find all assignments in a subtree. Language-aware:
 * - JS/TS: variable_declarator, assignment_expression
 * - Python: assignment
 * - Go: short_var_declaration, assignment_statement
 * - Ruby: assignment
 * - PHP: assignment_expression
 */
export function findAssignments(node: SyntaxNode, language?: AstLanguage): Assignment[] {
  const result: Assignment[] = [];

  // JS/TS: variable_declarator: const x = ...
  if (!language || language === 'javascript' || language === 'typescript' || language === 'tsx') {
    const declarators = findNodes(node, 'variable_declarator');
    for (const decl of declarators) {
      const nameNode = decl.childForFieldName('name');
      const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
      if (nameNode && nameNode.type === 'identifier' && valueNode) {
        result.push({
          name: nameNode.text,
          value: valueNode,
          line: nameNode.startPosition.row + 1,
          col: nameNode.startPosition.column,
        });
      }
    }

    // assignment_expression: x = ... or obj.prop = ...
    const assignments = findNodes(node, 'assignment_expression');
    for (const assign of assignments) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && left.type === 'identifier' && right) {
        result.push({
          name: left.text,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      } else if (left && left.type === 'member_expression' && right) {
        const fullName = getMemberExpressionText(left);
        result.push({
          name: fullName,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      }
    }
  }

  // Python: assignment (q = ...)
  if (language === 'python') {
    const assignments = findNodes(node, 'assignment');
    for (const assign of assignments) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && left.type === 'identifier' && right) {
        result.push({
          name: left.text,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      } else if (left && left.type === 'attribute' && right) {
        const fullName = getMemberExpressionText(left);
        result.push({
          name: fullName,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      }
    }
  }

  // Go: short_var_declaration (id := ...)
  if (language === 'go') {
    const shortVars = findNodes(node, 'short_var_declaration');
    for (const decl of shortVars) {
      const children: SyntaxNode[] = [];
      for (let i = 0; i < decl.childCount; i++) {
        const child = decl.child(i);
        if (child && child.isNamed) children.push(child);
      }
      if (children.length >= 2) {
        const leftList = children[0];
        const rightList = children[1];
        const leftNames: SyntaxNode[] = [];
        const rightValues: SyntaxNode[] = [];
        for (let i = 0; i < leftList.childCount; i++) {
          const c = leftList.child(i);
          if (c && c.isNamed) leftNames.push(c);
        }
        for (let i = 0; i < rightList.childCount; i++) {
          const c = rightList.child(i);
          if (c && c.isNamed) rightValues.push(c);
        }
        for (let idx = 0; idx < Math.min(leftNames.length, rightValues.length); idx++) {
          if (leftNames[idx].type === 'identifier') {
            result.push({
              name: leftNames[idx].text,
              value: rightValues[idx],
              line: leftNames[idx].startPosition.row + 1,
              col: leftNames[idx].startPosition.column,
            });
          }
        }
      }
    }

    // assignment_statement: id = ...
    const goAssigns = findNodes(node, 'assignment_statement');
    for (const assign of goAssigns) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (!left || !right) continue;
      let nameNode: SyntaxNode | null = null;
      let valueNode: SyntaxNode | null = null;
      for (let i = 0; i < left.childCount; i++) {
        const c = left.child(i);
        if (c && c.isNamed) { nameNode = c; break; }
      }
      for (let i = 0; i < right.childCount; i++) {
        const c = right.child(i);
        if (c && c.isNamed) { valueNode = c; break; }
      }
      if (nameNode && valueNode && nameNode.type === 'identifier') {
        result.push({
          name: nameNode.text,
          value: valueNode,
          line: nameNode.startPosition.row + 1,
          col: nameNode.startPosition.column,
        });
      }
    }
  }

  // Ruby: assignment (id = ...)
  if (language === 'ruby') {
    const assignments = findNodes(node, 'assignment');
    for (const assign of assignments) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && left.type === 'identifier' && right) {
        result.push({
          name: left.text,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      }
    }
  }

  // PHP: assignment_expression ($id = ...)
  if (language === 'php') {
    const assignments = findNodes(node, 'assignment_expression');
    for (const assign of assignments) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && left.type === 'variable_name' && right) {
        result.push({
          name: left.text,
          value: right,
          line: left.startPosition.row + 1,
          col: left.startPosition.column,
        });
      }
    }
  }

  return result;
}

/**
 * Forward-propagate taint through assignments using fixpoint iteration.
 * Returns all tainted variables with their taint paths.
 */
export function propagateTaint(functionNode: SyntaxNode, sources: TaintInfo[], maxDepth: number, language?: AstLanguage): TaintInfo[] {
  const tainted = new Map<string, TaintInfo>();

  // Seed from sources
  for (const src of sources) {
    tainted.set(src.varName, src);
  }

  const body = functionNode.childForFieldName('body') ?? functionNode;
  const assignments = findAssignments(body, language);

  let changed = true;
  let iterations = 0;
  while (changed && iterations < maxDepth) {
    changed = false;
    iterations++;

    for (const { name, value, line, col } of assignments) {
      if (tainted.has(name)) continue;

      const taintRef = containsTaintedRef(value, new Set(tainted.keys()), language);
      if (taintRef) {
        const upstream = tainted.get(taintRef)!;
        tainted.set(name, {
          varName: name,
          sourceExpr: upstream.sourceExpr,
          sourceLine: upstream.sourceLine,
          sourceCol: upstream.sourceCol,
          hops: [
            ...upstream.hops,
            { expression: name, line, column: col },
          ],
        });
        changed = true;
      }
    }
  }

  // -- Callback taint propagation (JS/TS-specific) --
  // When a tainted variable is the receiver of .then/.map/.forEach/.filter,
  // or is passed as an argument to a call that chains one of those methods,
  // mark the callback's first parameter as tainted.
  if (!language || language === 'javascript' || language === 'typescript' || language === 'tsx') {
  const CALLBACK_METHODS = new Set(['then', 'catch', 'map', 'forEach', 'filter', 'flatMap']);
  const allCalls = findNodes(body, 'call_expression');

  for (const call of allCalls) {
    const fn = call.childForFieldName('function');
    if (!fn || fn.type !== 'member_expression') continue;

    const prop = fn.childForFieldName('property');
    if (!prop || !CALLBACK_METHODS.has(prop.text)) continue;

    const obj = fn.childForFieldName('object');
    if (!obj) continue;

    // Check if the receiver is tainted (e.g. taintedVar.then(...))
    // or if the receiver is a call that has a tainted argument (e.g. processAsync(taintedVar).then(...))
    let isTaintedChain = false;
    let upstreamInfo: TaintInfo | undefined;

    const taintedKeys = new Set(tainted.keys());
    const receiverTaintRef = containsTaintedRef(obj, taintedKeys, language);
    if (receiverTaintRef) {
      isTaintedChain = true;
      upstreamInfo = tainted.get(receiverTaintRef);
    } else if (obj.type === 'call_expression') {
      // e.g. someFunc(taintedVar).then(...)
      const callArgs = obj.childForFieldName('arguments');
      if (callArgs) {
        const argRef = containsTaintedRef(callArgs, taintedKeys, language);
        if (argRef) {
          isTaintedChain = true;
          upstreamInfo = tainted.get(argRef);
        }
      }
    }

    if (!isTaintedChain || !upstreamInfo) continue;

    // Get the first argument to .then/.map/etc. -- should be a function
    const args = call.childForFieldName('arguments');
    if (!args) continue;

    let callbackNode: SyntaxNode | null = null;
    for (let i = 0; i < args.childCount; i++) {
      const child = args.child(i);
      if (child && child.isNamed) {
        callbackNode = child;
        break;
      }
    }

    if (!callbackNode) continue;
    if (callbackNode.type !== 'arrow_function' && callbackNode.type !== 'function_expression' && callbackNode.type !== 'function') continue;

    // Get the first parameter of the callback
    let firstParam: SyntaxNode | null = null;

    // Arrow function with a single parameter (no parentheses) uses 'parameter' field
    if (callbackNode.type === 'arrow_function') {
      const paramNode = callbackNode.childForFieldName('parameter');
      if (paramNode && paramNode.type === 'identifier') {
        firstParam = paramNode;
      }
    }

    // Multi-param functions use 'parameters' field
    if (!firstParam) {
      const params = callbackNode.childForFieldName('parameters');
      if (params) {
        for (let i = 0; i < params.childCount; i++) {
          const child = params.child(i);
          if (child && child.isNamed && child.type === 'identifier') {
            firstParam = child;
            break;
          }
        }
      }
    }

    if (!firstParam) continue;
    const paramName = firstParam.text;

    if (!tainted.has(paramName)) {
      tainted.set(paramName, {
        varName: paramName,
        sourceExpr: upstreamInfo.sourceExpr,
        sourceLine: upstreamInfo.sourceLine,
        sourceCol: upstreamInfo.sourceCol,
        hops: [
          ...upstreamInfo.hops,
          {
            expression: paramName,
            line: firstParam.startPosition.row + 1,
            column: firstParam.startPosition.column,
          },
        ],
      });
    }
  }
  } // end JS/TS callback taint propagation

  return [...tainted.values()];
}
