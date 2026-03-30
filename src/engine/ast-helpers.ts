/**
 * Shared tree-sitter AST traversal helpers.
 * Used by taint-tracker.ts, cross-file-taint.ts, ast/index.ts, and ast-pattern.ts.
 */
import type { AstLanguage } from '../checks/types.js';

/** Minimal interface matching the web-tree-sitter / ast-grep SyntaxNode shape. */
export interface SyntaxNode {
  type: string;
  text: string;
  childCount: number;
  child(index: number): SyntaxNode | null;
  childForFieldName(name: string): SyntaxNode | null;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  parent: SyntaxNode | null;
  /** True for named nodes (not punctuation/anonymous). */
  isNamed?: boolean;
}

/** Walk the entire AST subtree rooted at `node`, calling `callback` on every node. */
export function walkTree(node: SyntaxNode, callback: (n: SyntaxNode) => void): void {
  callback(node);
  const count: number = node.childCount;
  for (let i = 0; i < count; i++) {
    const child = node.child(i);
    if (child) walkTree(child, callback);
  }
}

/** Find all descendant nodes whose type matches `type`. */
export function findNodes(node: SyntaxNode, type: string): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  walkTree(node, (n) => {
    if (n.type === type) result.push(n);
  });
  return result;
}

/** Find all descendant nodes whose type is in the given set. */
export function findNodesByTypes(node: SyntaxNode, types: Set<string>): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  walkTree(node, (n) => {
    if (types.has(n.type)) result.push(n);
  });
  return result;
}

/** Node types that represent member/attribute access across languages. */
export const MEMBER_EXPRESSION_TYPES = new Set([
  'member_expression',        // JS/TS
  'selector_expression',      // Go
  'attribute',                // Python
  'member_access_expression', // PHP
]);

/**
 * Get the full dotted text of a member expression (e.g., "req.body.id").
 * Handles JS/TS member_expression, Go selector_expression, Python attribute,
 * and PHP member_access_expression.
 */
export function getMemberExpressionText(node: SyntaxNode): string {
  // JS/TS
  if (node.type === 'member_expression') {
    const obj = node.childForFieldName('object');
    const prop = node.childForFieldName('property');
    if (obj && prop) return getMemberExpressionText(obj) + '.' + prop.text;
  }
  // Go
  if (node.type === 'selector_expression') {
    const operand = node.childForFieldName('operand');
    const field = node.childForFieldName('field');
    if (operand && field) return getMemberExpressionText(operand) + '.' + field.text;
  }
  // Python
  if (node.type === 'attribute') {
    const obj = node.childForFieldName('object');
    const attr = node.childForFieldName('attribute');
    if (obj && attr) return getMemberExpressionText(obj) + '.' + attr.text;
  }
  // PHP
  if (node.type === 'member_access_expression') {
    const obj = node.childForFieldName('object');
    const name = node.childForFieldName('name');
    if (obj && name) return getMemberExpressionText(obj) + '.' + name.text;
  }
  return node.text;
}

/**
 * Check if `node` or any of its descendants references any variable in `taintedVars`.
 * Returns the name of the first tainted variable found, or null.
 *
 * Language-aware: handles JS/TS member_expression, Python attribute,
 * Go selector_expression, Ruby element_reference/params, and PHP superglobals.
 */
export function containsTaintedRef(node: SyntaxNode, taintedVars: Set<string>, language?: AstLanguage): string | null {
  if (node.type === 'identifier' && taintedVars.has(node.text)) {
    return node.text;
  }
  // For shorthand property {x} in object pattern/literal, the identifier is the key
  if (node.type === 'shorthand_property_identifier_pattern' && taintedVars.has(node.text)) {
    return node.text;
  }
  // PHP: variable_name nodes contain the $ prefix in .text
  if (node.type === 'variable_name' && taintedVars.has(node.text)) {
    return node.text;
  }

  // Check if a member-like expression's full dotted text matches a tainted key
  if (MEMBER_EXPRESSION_TYPES.has(node.type)) {
    const fullText = getMemberExpressionText(node);
    if (taintedVars.has(fullText)) {
      return fullText;
    }
    // JS/TS: catch direct user input references (req.body.*, etc.)
    if (!language || language === 'javascript' || language === 'typescript' || language === 'tsx') {
      if (/^req\.(body|params|query|headers|cookies)(\.|$|\[)/.test(fullText) ||
          /^request\.(body|params|query|headers|cookies)(\.|$|\[)/.test(fullText)) {
        return fullText;
      }
    }
    // Python: request.form, request.args, request.data, request.json, request.POST, request.GET
    if (language === 'python') {
      if (/^request\.(form|args|data|json|POST|GET|FILES|values)(\.|$|\[)/.test(fullText) ||
          /^self\.request\.(data|query_params)(\.|$|\[)/.test(fullText)) {
        return fullText;
      }
    }
    // Go: r.FormValue, r.Body, r.URL.Query, c.Param, c.Query, c.FormValue
    if (language === 'go') {
      if (/^r\.(Body|Form|PostForm|MultipartForm)$/.test(fullText) ||
          /^r\.URL\.Query$/.test(fullText) ||
          /^c\.(Param|Query|PostForm|FormValue|DefaultQuery)$/.test(fullText)) {
        return fullText;
      }
    }
    // Ruby: params access via method call
    if (language === 'ruby') {
      if (/^request\.body$/.test(fullText) || /^request\.params$/.test(fullText)) {
        return fullText;
      }
    }
  }

  // Ruby: element_reference for params[:field]
  if (language === 'ruby' && node.type === 'element_reference') {
    const obj = node.child(0);
    if (obj && obj.type === 'identifier' && obj.text === 'params') {
      return node.text;
    }
  }

  // PHP: subscript_expression for $_GET['field'], $_POST['field'], etc.
  if (language === 'php' && node.type === 'subscript_expression') {
    const obj = node.child(0);
    if (obj && obj.type === 'variable_name' &&
        /^\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)$/.test(obj.text)) {
      return node.text;
    }
  }

  const count: number = node.childCount;
  for (let i = 0; i < count; i++) {
    const child = node.child(i);
    if (child) {
      const found = containsTaintedRef(child, taintedVars, language);
      if (found) return found;
    }
  }
  return null;
}
