/**
 * Shared types for the taint tracking sub-modules.
 */
import type { TaintNode, SinkCategory, AstLanguage } from '../../checks/types.js';

/** Tracks a single tainted variable: where it came from and hops through the code. */
export interface TaintInfo {
  varName: string;
  sourceExpr: string;
  sourceLine: number;
  sourceCol: number;
  hops: TaintNode[];
}

/** A detected sink hit: a dangerous function/assignment that receives tainted data. */
export interface SinkHit {
  category: SinkCategory;
  node: any;          // the call_expression or assignment
  argNode: any;       // the specific argument that's tainted
  taintRef: string;   // name of the tainted variable found
  line: number;
  col: number;
}

/** An assignment extracted from the AST for taint propagation. */
export interface Assignment {
  name: string;
  value: any;    // SyntaxNode of the value expression
  line: number;  // 1-indexed
  col: number;
}

/** Taint signature for a named function (which params reach which sinks). */
export interface FunctionTaintSignature {
  name: string;
  node: any;
  /** Maps parameter index -> which sink categories that parameter reaches. */
  paramSinks: Map<number, SinkCategory[]>;
}

/** Identifier-like node types across all supported languages. */
export const IDENTIFIER_TYPES = new Set([
  'identifier',                                   // JS/TS/Go/Python/Ruby
  'shorthand_property_identifier_pattern',         // JS/TS destructuring
  'variable_name',                                // PHP ($var)
]);
