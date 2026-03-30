/**
 * Sanitizer detection for taint tracking.
 * Checks whether tainted data has been sanitized before reaching a sink.
 */
import type { SinkCategory } from '../../checks/types.js';
import type { SyntaxNode } from '../ast-helpers.js';
import { findNodes } from '../ast-helpers.js';
import type { TaintInfo } from './types.js';

/** Check if a call expression is to a known sanitizer that neutralizes all taint. */
export function isUniversalSanitizer(callText: string): boolean {
  return /^(parseInt|parseFloat|Number|Boolean|String)\s*\(/.test(callText);
}

/** Check if a call expression is to a known XSS sanitizer. */
export function isXssSanitizer(callText: string): boolean {
  return (
    /DOMPurify\.sanitize\s*\(/.test(callText) ||
    /escapeHtml\s*\(/.test(callText) ||
    /sanitizeHtml\s*\(/.test(callText) ||
    /xss\s*\(/.test(callText) ||
    /encode(URI|URIComponent)\s*\(/.test(callText)
  );
}

/** Check if a call expression is to a known SQL sanitizer. */
export function isSqlSanitizer(callText: string): boolean {
  return (
    /mysql\.escape\s*\(/.test(callText) ||
    /escape(Literal|Identifier|String)\s*\(/.test(callText) ||
    /sqlstring\.escape\s*\(/.test(callText) ||
    /pg\..*\.escapeLiteral\s*\(/.test(callText) ||
    /validator\.escape\s*\(/.test(callText)
  );
}

/** Check if a call expression is to a known shell sanitizer. */
export function isShellSanitizer(callText: string): boolean {
  return (
    /shellescape\s*\(/.test(callText) ||
    /shell-quote/.test(callText) ||
    /quote\s*\(/.test(callText)
  );
}

/** Extract the call_expression from an await_expression. */
function getCallFromAwait(awaitNode: SyntaxNode): SyntaxNode | null {
  const count: number = awaitNode.childCount;
  for (let i = 0; i < count; i++) {
    const child = awaitNode.child(i);
    if (child && child.type === 'call_expression') return child;
  }
  return null;
}

/**
 * Check if a taint path was neutralized by a sanitizer between source and sink.
 * Walk the hops and check if any intermediate assignment wraps a sanitizer call.
 */
export function isSanitized(
  taintInfo: TaintInfo,
  sinkCategory: SinkCategory,
  functionNode: SyntaxNode,
): boolean {
  // Look at each hop's expression name and find its assignment in the function.
  // If the value is a sanitizer call, the taint is neutralized.
  const body = functionNode.childForFieldName('body') ?? functionNode;
  const declarators = findNodes(body, 'variable_declarator');

  for (const hop of taintInfo.hops) {
    // Find the declarator for this variable
    for (const decl of declarators) {
      const nameNode = decl.childForFieldName('name');
      const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
      if (!nameNode || !valueNode || nameNode.type !== 'identifier') continue;
      if (nameNode.text !== hop.expression) continue;

      // Check if value is a sanitizer call
      if (valueNode.type === 'call_expression' || valueNode.type === 'await_expression') {
        const callNode = valueNode.type === 'await_expression'
          ? getCallFromAwait(valueNode)
          : valueNode;
        if (!callNode) continue;
        const callText = callNode.text;

        if (isUniversalSanitizer(callText)) return true;
        if (sinkCategory === 'xss' && isXssSanitizer(callText)) return true;
        if (sinkCategory === 'sql-query' && isSqlSanitizer(callText)) return true;
        if (sinkCategory === 'shell-exec' && isShellSanitizer(callText)) return true;
      }
    }
  }

  return false;
}
