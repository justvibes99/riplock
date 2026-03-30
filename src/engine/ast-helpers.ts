/**
 * Shared tree-sitter AST traversal helpers.
 * Used by taint-tracker.ts, cross-file-taint.ts, ast/index.ts, and ast-pattern.ts.
 *
 * Note: tree-sitter SyntaxNode is typed as `any` because web-tree-sitter
 * and ast-grep expose different node APIs. A shared typed interface would
 * require runtime abstraction overhead.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type SyntaxNode = any;

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
