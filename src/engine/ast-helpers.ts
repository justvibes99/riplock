/**
 * Shared tree-sitter AST traversal helpers.
 * Used by taint-tracker.ts, cross-file-taint.ts, and ast-pattern.ts.
 *
 * Note: tree-sitter SyntaxNode types are untyped (any) because web-tree-sitter
 * and ast-grep use different node APIs. A shared SyntaxNode interface would
 * require runtime abstraction overhead. The `any` here is intentional —
 * these helpers accept both web-tree-sitter and ast-grep nodes.
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

/**
 * Get the full dotted text of a member expression (e.g., "req.body.id").
 * Handles JS/TS member_expression, Go selector_expression, Python attribute,
 * and PHP member_access_expression.
 */
export function getMemberExpressionText(node: SyntaxNode): string {
  if (
    node.type === 'member_expression' ||
    node.type === 'selector_expression' ||
    node.type === 'attribute' ||
    node.type === 'member_access_expression'
  ) {
    const obj = node.childForFieldName('object');
    const prop =
      node.childForFieldName('property') ??
      node.childForFieldName('field') ??
      node.childForFieldName('attribute');
    if (obj && prop) {
      return getMemberExpressionText(obj) + '.' + prop.text;
    }
  }
  return node.text;
}
