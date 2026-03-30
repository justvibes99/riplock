/**
 * Intra-function taint tracking engine.
 *
 * TODO: This file is ~2300 lines. Split into sub-modules:
 * - taint-sources.ts (source detection per language)
 * - taint-sinks.ts (sink detection per language)
 * - taint-propagation.ts (forward propagation + sanitizer checking)
 * - taint-imports.ts (import collection)
 */
import type {
  TaintPath,
  TaintNode,
  TaintQueryOpts,
  SinkCategory,
  AstLanguage,
} from '../checks/types.js';
import { walkTree, findNodes, findNodesByTypes, getMemberExpressionText, MEMBER_EXPRESSION_TYPES } from './ast-helpers.js';

// getMemberExpressionText and MEMBER_EXPRESSION_TYPES imported from ast-helpers.ts

/** Identifier-like node types across all supported languages. */
const IDENTIFIER_TYPES = new Set([
  'identifier',                                   // JS/TS/Go/Python/Ruby
  'shorthand_property_identifier_pattern',         // JS/TS destructuring
  'variable_name',                                // PHP ($var)
]);

/**
 * Check if `node` or any of its descendants references any variable in `taintedVars`.
 * Returns the name of the first tainted variable found, or null.
 */
function containsTaintedRef(node: any, taintedVars: Set<string>, language?: AstLanguage): string | null {
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

/** Check if a call expression is to a known sanitizer that neutralizes all taint. */
function isUniversalSanitizer(callText: string): boolean {
  return /^(parseInt|parseFloat|Number|Boolean|String)\s*\(/.test(callText);
}

/** Check if a call expression is to a known XSS sanitizer. */
function isXssSanitizer(callText: string): boolean {
  return (
    /DOMPurify\.sanitize\s*\(/.test(callText) ||
    /escapeHtml\s*\(/.test(callText) ||
    /sanitizeHtml\s*\(/.test(callText) ||
    /xss\s*\(/.test(callText) ||
    /encode(URI|URIComponent)\s*\(/.test(callText)
  );
}

/** Check if a call expression is to a known SQL sanitizer. */
function isSqlSanitizer(callText: string): boolean {
  return (
    /mysql\.escape\s*\(/.test(callText) ||
    /escape(Literal|Identifier|String)\s*\(/.test(callText) ||
    /sqlstring\.escape\s*\(/.test(callText) ||
    /pg\..*\.escapeLiteral\s*\(/.test(callText) ||
    /validator\.escape\s*\(/.test(callText)
  );
}

/** Check if a call expression is to a known shell sanitizer. */
function isShellSanitizer(callText: string): boolean {
  return (
    /shellescape\s*\(/.test(callText) ||
    /shell-quote/.test(callText) ||
    /quote\s*\(/.test(callText)
  );
}

/**
 * Check if a sink call uses parameterized queries (safe pattern).
 * e.g. query('SELECT ... WHERE id = $1', [userInput])
 */
function isParameterizedQuery(callNode: any): boolean {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;

  // Needs at least two arguments: a query string and a params array
  const argChildren: any[] = [];
  const count: number = args.childCount;
  for (let i = 0; i < count; i++) {
    const child = args.child(i);
    // Skip punctuation: (, ), ,
    if (child && child.isNamed) {
      argChildren.push(child);
    }
  }

  if (argChildren.length < 2) return false;

  const queryArg = argChildren[0];
  const paramsArg = argChildren[1];

  // The query string should contain parameter placeholders ($1, ?, :name, %s)
  const queryText = queryArg.text;
  const hasPlaceholders = /(\$\d+|\?|:\w+|%s)/.test(queryText);

  // The params should be an array/list/tuple expression
  const isArray = paramsArg.type === 'array'       // JS/TS
               || paramsArg.type === 'list'         // Python
               || paramsArg.type === 'tuple'        // Python
               || paramsArg.type === 'argument';    // PHP (wrapping array)

  return hasPlaceholders && isArray;
}

// ── Import collection ────────────────────────────────────────────────

/**
 * Collect all imports/requires at the file level.
 * Returns a map of localName → moduleName.
 * Language-aware: handles import statements for JS/TS, Python, Go, Ruby, PHP.
 */
function collectImports(rootNode: any, language?: AstLanguage): Map<string, string> {
  const imports = new Map<string, string>();

  walkTree(rootNode, (node) => {
    // ES import: import X from 'mod' / import { X } from 'mod'
    if (node.type === 'import_statement') {
      const source = node.childForFieldName('source');
      if (!source) return;
      // strip quotes
      const moduleName = source.text.replace(/['"]/g, '');

      // Check for default import
      // import_clause can contain: identifier (default), named_imports, namespace_import
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
          // import * as X from 'mod'
          const nameNode = child.childForFieldName('name');
          if (nameNode) imports.set(nameNode.text, moduleName);
        }
      });
    }

    // CommonJS require: const X = require('mod') / const { X } = require('mod')
    if (node.type === 'variable_declarator') {
      const init = node.childForFieldName('value') ?? node.childForFieldName('init');
      if (!init) return;

      // Check if init is a require call
      let requireModule: string | null = null;
      if (init.type === 'call_expression') {
        const fn = init.childForFieldName('function');
        if (fn && fn.text === 'require') {
          const args = init.childForFieldName('arguments');
          if (args && args.childCount > 0) {
            // First named child is the argument
            for (let i = 0; i < args.childCount; i++) {
              const arg = args.child(i);
              if (arg && arg.isNamed) {
                requireModule = arg.text.replace(/['"]/g, '');
                break;
              }
            }
          }
        }
      }
      if (!requireModule) return;

      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;

      if (nameNode.type === 'identifier') {
        // const fs = require('fs')
        imports.set(nameNode.text, requireModule);
      } else if (nameNode.type === 'object_pattern') {
        // const { exec } = require('child_process')
        walkTree(nameNode, (child) => {
          if (child.type === 'shorthand_property_identifier_pattern') {
            imports.set(child.text, requireModule!);
          } else if (child.type === 'pair_pattern') {
            const key = child.childForFieldName('key');
            const val = child.childForFieldName('value');
            if (val && val.type === 'identifier') {
              imports.set(val.text, requireModule!);
            } else if (key && key.type === 'identifier') {
              imports.set(key.text, requireModule!);
            }
          }
        });
      }
    }
  });

  // Python: from X import Y, import X
  if (language === 'python') {
    walkTree(rootNode, (node) => {
      if (node.type === 'import_from_statement') {
        const moduleNode = node.childForFieldName('module_name');
        if (!moduleNode) return;
        const moduleName = moduleNode.text;
        // Collect imported names
        walkTree(node, (child) => {
          if (child.type === 'dotted_name' && child !== moduleNode) {
            imports.set(child.text, moduleName);
          }
          if (child.type === 'aliased_import') {
            const alias = child.childForFieldName('alias');
            const name = child.childForFieldName('name');
            if (alias) imports.set(alias.text, moduleName);
            else if (name) imports.set(name.text, moduleName);
          }
        });
      }
      if (node.type === 'import_statement') {
        walkTree(node, (child) => {
          if (child.type === 'dotted_name' && child.parent === node) {
            imports.set(child.text, child.text);
          }
        });
      }
    });
  }

  // Go: import "pkg" or import ( "pkg" )
  if (language === 'go') {
    walkTree(rootNode, (node) => {
      if (node.type === 'import_spec') {
        const path = node.childForFieldName('path');
        if (!path) return;
        const pkgPath = path.text.replace(/"/g, '');
        const alias = node.childForFieldName('name');
        if (alias) {
          imports.set(alias.text, pkgPath);
        } else {
          // Use last segment of import path as the local name
          const segments = pkgPath.split('/');
          imports.set(segments[segments.length - 1], pkgPath);
        }
      }
    });
  }

  // Ruby: require 'gem_name'
  if (language === 'ruby') {
    walkTree(rootNode, (node) => {
      if (node.type === 'call') {
        const method = node.childForFieldName('method');
        if (method && (method.text === 'require' || method.text === 'require_relative')) {
          const args = node.childForFieldName('arguments');
          if (args) {
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.type === 'string') {
                const modName = child.text.replace(/['"]/g, '');
                imports.set(modName, modName);
              }
            }
          }
        }
      }
    });
  }

  // PHP: use statements and require/include
  if (language === 'php') {
    walkTree(rootNode, (node) => {
      if (node.type === 'namespace_use_declaration') {
        walkTree(node, (child) => {
          if (child.type === 'namespace_use_clause') {
            const name = child.childForFieldName('name');
            if (name) {
              const parts = name.text.split('\\');
              imports.set(parts[parts.length - 1], name.text);
            }
          }
        });
      }
    });
  }

  return imports;
}

// ── Taint source detection ───────────────────────────────────────────

interface TaintInfo {
  varName: string;
  sourceExpr: string;
  sourceLine: number;
  sourceCol: number;
  hops: TaintNode[];
}

/**
 * Check if a node is a user-input source expression.
 * Returns a description string if it is, null otherwise.
 * Language-aware: detects framework-specific request input patterns.
 */
function isUserInputSource(node: any, language?: AstLanguage): string | null {
  if (!node) return null;

  const text = node.text;

  // ── JS/TS sources ──────────────────────────────────────────────────
  if (!language || language === 'javascript' || language === 'typescript' || language === 'tsx') {
    // Member expression: req.body.X, req.params.X, req.query.X
    if (node.type === 'member_expression') {
      const fullText = getMemberExpressionText(node);
      if (/^req\.(body|params|query|headers|cookies)(\.|\[)/.test(fullText) ||
          /^req\.(body|params|query|headers|cookies)$/.test(fullText) ||
          /^request\.(body|params|query|headers|cookies)(\.|\[)/.test(fullText) ||
          /^request\.(body|params|query|headers|cookies)$/.test(fullText) ||
          /^ctx\.(request\.body|params|query)(\.|\[)?/.test(fullText)) {
        return fullText;
      }
    }

    // Call expression: formData.get('X'), searchParams.get('X'), req.json(), etc.
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

    // Await expression wrapping a source call: await req.json()
    if (node.type === 'await_expression') {
      const inner = node.childCount > 0 ? node.child(node.childCount - 1) : null;
      if (inner) return isUserInputSource(inner, language);
    }
  }

  // ── Python sources ─────────────────────────────────────────────────
  if (language === 'python') {
    // attribute access: request.form, request.args, request.data, request.json, request.POST, request.GET
    if (node.type === 'attribute') {
      const fullText = getMemberExpressionText(node);
      if (/^request\.(form|args|data|json|POST|GET|FILES|values)$/.test(fullText) ||
          /^self\.request\.(data|query_params)$/.test(fullText)) {
        return fullText;
      }
    }

    // Subscript: request.form['field'], request.args['field'], request.POST['field']
    if (node.type === 'subscript') {
      const value = node.childForFieldName('value');
      if (value && value.type === 'attribute') {
        const fullText = getMemberExpressionText(value);
        if (/^request\.(form|args|POST|GET|FILES|values)$/.test(fullText) ||
            /^self\.request\.(data|query_params)$/.test(fullText)) {
          return text;
        }
      }
    }

    // Call: request.args.get('q'), request.form.get('x'), request.get_json()
    if (node.type === 'call') {
      const fn = node.childForFieldName('function');
      if (fn) {
        const fnText = getMemberExpressionText(fn);
        if (/^request\.(args|form|values)\.get$/.test(fnText) ||
            /^request\.get_json$/.test(fnText) ||
            /^request\.POST\.get$/.test(fnText) ||
            /^request\.GET\.get$/.test(fnText) ||
            /^self\.request\.(data|query_params)\.get$/.test(fnText)) {
          return text;
        }
      }
    }

    // Await expression wrapping a source call
    if (node.type === 'await') {
      const inner = node.childCount > 0 ? node.child(node.childCount - 1) : null;
      if (inner) return isUserInputSource(inner, language);
    }
  }

  // ── Go sources ─────────────────────────────────────────────────────
  if (language === 'go') {
    // Call: r.FormValue("field"), r.URL.Query().Get("field"), c.Param("field"),
    //       c.Query("field"), c.FormValue("field"), c.PostForm("field")
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn) {
        const fnText = getMemberExpressionText(fn);
        if (/^r\.(FormValue|PostFormValue)$/.test(fnText) ||
            /^r\.URL\.Query\(\)\.Get$/.test(fnText) ||
            /^c\.(Param|Query|PostForm|FormValue|DefaultQuery|QueryParam|FormParams)$/.test(fnText)) {
          return text;
        }
        // Also: r.URL.Query().Get — the full text includes the call
        if (/\.Get$/.test(fnText) && /r\.URL\.Query/.test(text)) {
          return text;
        }
      }
    }

    // Selector: r.Body (http.Request body)
    if (node.type === 'selector_expression') {
      const fullText = getMemberExpressionText(node);
      if (/^r\.(Body|Form|PostForm|MultipartForm)$/.test(fullText)) {
        return fullText;
      }
    }
  }

  // ── Ruby sources ───────────────────────────────────────────────────
  if (language === 'ruby') {
    // element_reference: params[:field], params["field"]
    if (node.type === 'element_reference') {
      const obj = node.child(0);
      if (obj && obj.type === 'identifier' && obj.text === 'params') {
        return text;
      }
    }

    // Method call on params: params.fetch(:field), params.require(:field).permit(...)
    if (node.type === 'call') {
      const receiver = node.childForFieldName('receiver');
      const method = node.childForFieldName('method');
      if (receiver && method) {
        if (receiver.type === 'identifier' && receiver.text === 'params' &&
            /^(fetch|require|permit|slice|to_unsafe_h|dig)$/.test(method.text)) {
          return text;
        }
      }
    }

    // attribute: request.body
    if (node.type === 'call') {
      const receiver = node.childForFieldName('receiver');
      const method = node.childForFieldName('method');
      if (receiver && method) {
        if (receiver.type === 'identifier' && receiver.text === 'request' &&
            (method.text === 'body' || method.text === 'params' || method.text === 'raw_post')) {
          return text;
        }
      }
    }
  }

  // ── PHP sources ────────────────────────────────────────────────────
  if (language === 'php') {
    // Subscript: $_GET['field'], $_POST['field'], $_REQUEST['field'], $_FILES['field'], $_COOKIE['field']
    if (node.type === 'subscript_expression') {
      const obj = node.child(0);
      if (obj && obj.type === 'variable_name' &&
          /^\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)$/.test(obj.text)) {
        return text;
      }
    }

    // Direct superglobal variable: $_GET, $_POST as a whole
    if (node.type === 'variable_name') {
      if (/^\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)$/.test(node.text)) {
        return text;
      }
    }
  }

  return null;
}

/**
 * Detect taint sources inside a function body by scanning variable declarations.
 * Also handles destructuring from req.body etc.
 * Language-aware: handles different AST structures per language.
 */
function detectSources(functionNode: any, language?: AstLanguage): TaintInfo[] {
  const sources: TaintInfo[] = [];
  const body = functionNode.childForFieldName('body') ?? functionNode;

  // ── JS/TS: variable_declarator nodes ──
  if (!language || language === 'javascript' || language === 'typescript' || language === 'tsx') {
    const declarators = findNodes(body, 'variable_declarator');

    for (const decl of declarators) {
      const nameNode = decl.childForFieldName('name');
      const valueNode = decl.childForFieldName('value') ?? decl.childForFieldName('init');
      if (!nameNode || !valueNode) continue;

      // Simple binding: const x = req.body.foo
      if (nameNode.type === 'identifier') {
        const sourceExpr = isUserInputSource(valueNode, language);
        if (sourceExpr) {
          sources.push({
            varName: nameNode.text,
            sourceExpr,
            sourceLine: nameNode.startPosition.row + 1,
            sourceCol: nameNode.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: valueNode.startPosition.row + 1,
              column: valueNode.startPosition.column,
            }],
          });
        }
      }

      // Destructuring: const { x, y } = req.body
      if (nameNode.type === 'object_pattern') {
        const sourceExpr = isUserInputSource(valueNode, language);
        if (sourceExpr) {
          walkTree(nameNode, (child) => {
            if (child.type === 'shorthand_property_identifier_pattern' ||
                (child.type === 'identifier' && child.parent?.type === 'pair_pattern')) {
              const varName = child.text;
              sources.push({
                varName,
                sourceExpr: sourceExpr + '.' + varName,
                sourceLine: child.startPosition.row + 1,
                sourceCol: child.startPosition.column,
                hops: [{
                  expression: sourceExpr + '.' + varName,
                  line: child.startPosition.row + 1,
                  column: child.startPosition.column,
                }],
              });
            }
          });
        }
      }
    }

    // Also scan assignment expressions: data.query = req.body.search
    const assignExprs = findNodes(body, 'assignment_expression');
    for (const assign of assignExprs) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (!left || !right) continue;

      if (left.type === 'identifier') {
        const sourceExpr = isUserInputSource(right, language);
        if (sourceExpr) {
          sources.push({
            varName: left.text,
            sourceExpr,
            sourceLine: left.startPosition.row + 1,
            sourceCol: left.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: right.startPosition.row + 1,
              column: right.startPosition.column,
            }],
          });
        }
      }

      if (left.type === 'member_expression') {
        const sourceExpr = isUserInputSource(right, language);
        if (sourceExpr) {
          const fullName = getMemberExpressionText(left);
          sources.push({
            varName: fullName,
            sourceExpr,
            sourceLine: left.startPosition.row + 1,
            sourceCol: left.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: right.startPosition.row + 1,
              column: right.startPosition.column,
            }],
          });
        }
      }
    }
  }

  // ── Python: assignment nodes (q = request.args.get('q')) ──
  if (language === 'python') {
    const assignments = findNodes(body, 'assignment');
    for (const assign of assignments) {
      // Python assignment: left = right
      const leftNode = assign.childForFieldName('left');
      const rightNode = assign.childForFieldName('right');
      if (!leftNode || !rightNode) continue;

      if (leftNode.type === 'identifier') {
        const sourceExpr = isUserInputSource(rightNode, language);
        if (sourceExpr) {
          sources.push({
            varName: leftNode.text,
            sourceExpr,
            sourceLine: leftNode.startPosition.row + 1,
            sourceCol: leftNode.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: rightNode.startPosition.row + 1,
              column: rightNode.startPosition.column,
            }],
          });
        }
      }

      // Tuple destructuring: x, y = request.form['x'], request.form['y']
      if (leftNode.type === 'pattern_list' || leftNode.type === 'tuple_pattern') {
        const sourceExpr = isUserInputSource(rightNode, language);
        if (sourceExpr) {
          walkTree(leftNode, (child) => {
            if (child.type === 'identifier') {
              sources.push({
                varName: child.text,
                sourceExpr: sourceExpr + '.' + child.text,
                sourceLine: child.startPosition.row + 1,
                sourceCol: child.startPosition.column,
                hops: [{
                  expression: sourceExpr + '.' + child.text,
                  line: child.startPosition.row + 1,
                  column: child.startPosition.column,
                }],
              });
            }
          });
        }
      }
    }
  }

  // ── Go: short_var_declaration (id := r.FormValue("id")) ──
  if (language === 'go') {
    const shortVars = findNodes(body, 'short_var_declaration');
    for (const decl of shortVars) {
      // Go short_var_declaration has expression_list children on both sides
      const children: any[] = [];
      for (let i = 0; i < decl.childCount; i++) {
        const child = decl.child(i);
        if (child && child.isNamed) children.push(child);
      }
      // Pattern: expression_list := expression_list
      // children[0] = left expr list, children[1] = right expr list
      if (children.length >= 2) {
        const leftList = children[0];
        const rightList = children[1];
        // For simple single assignment: id := r.FormValue("id")
        const leftNames: any[] = [];
        const rightValues: any[] = [];
        for (let i = 0; i < leftList.childCount; i++) {
          const c = leftList.child(i);
          if (c && c.isNamed) leftNames.push(c);
        }
        for (let i = 0; i < rightList.childCount; i++) {
          const c = rightList.child(i);
          if (c && c.isNamed) rightValues.push(c);
        }
        for (let idx = 0; idx < Math.min(leftNames.length, rightValues.length); idx++) {
          const nameNode = leftNames[idx];
          const valueNode = rightValues[idx];
          if (nameNode.type === 'identifier') {
            const sourceExpr = isUserInputSource(valueNode, language);
            if (sourceExpr) {
              sources.push({
                varName: nameNode.text,
                sourceExpr,
                sourceLine: nameNode.startPosition.row + 1,
                sourceCol: nameNode.startPosition.column,
                hops: [{
                  expression: sourceExpr,
                  line: valueNode.startPosition.row + 1,
                  column: valueNode.startPosition.column,
                }],
              });
            }
          }
        }
      }
    }

    // Go: var declarations with assignment
    const varDecls = findNodes(body, 'var_declaration');
    for (const decl of varDecls) {
      walkTree(decl, (child) => {
        if (child.type === 'var_spec') {
          const nameNode = child.childForFieldName('name');
          const valueNode = child.childForFieldName('value');
          if (nameNode && valueNode && nameNode.type === 'identifier') {
            const sourceExpr = isUserInputSource(valueNode, language);
            if (sourceExpr) {
              sources.push({
                varName: nameNode.text,
                sourceExpr,
                sourceLine: nameNode.startPosition.row + 1,
                sourceCol: nameNode.startPosition.column,
                hops: [{
                  expression: sourceExpr,
                  line: valueNode.startPosition.row + 1,
                  column: valueNode.startPosition.column,
                }],
              });
            }
          }
        }
      });
    }

    // Go: assignment_statement (id = r.FormValue("id"))
    const goAssigns = findNodes(body, 'assignment_statement');
    for (const assign of goAssigns) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (!left || !right) continue;
      // Get first identifier from expression_list
      let nameNode: any = null;
      let valueNode: any = null;
      for (let i = 0; i < left.childCount; i++) {
        const c = left.child(i);
        if (c && c.isNamed) { nameNode = c; break; }
      }
      for (let i = 0; i < right.childCount; i++) {
        const c = right.child(i);
        if (c && c.isNamed) { valueNode = c; break; }
      }
      if (nameNode && valueNode && nameNode.type === 'identifier') {
        const sourceExpr = isUserInputSource(valueNode, language);
        if (sourceExpr) {
          sources.push({
            varName: nameNode.text,
            sourceExpr,
            sourceLine: nameNode.startPosition.row + 1,
            sourceCol: nameNode.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: valueNode.startPosition.row + 1,
              column: valueNode.startPosition.column,
            }],
          });
        }
      }
    }
  }

  // ── Ruby: assignment nodes (id = params[:id]) ──
  if (language === 'ruby') {
    const assignments = findNodes(body, 'assignment');
    for (const assign of assignments) {
      const leftNode = assign.childForFieldName('left');
      const rightNode = assign.childForFieldName('right');
      if (!leftNode || !rightNode) continue;

      if (leftNode.type === 'identifier') {
        const sourceExpr = isUserInputSource(rightNode, language);
        if (sourceExpr) {
          sources.push({
            varName: leftNode.text,
            sourceExpr,
            sourceLine: leftNode.startPosition.row + 1,
            sourceCol: leftNode.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: rightNode.startPosition.row + 1,
              column: rightNode.startPosition.column,
            }],
          });
        }
      }
    }
  }

  // ── PHP: assignment_expression nodes ($id = $_GET['id']) ──
  if (language === 'php') {
    const assignments = findNodes(body, 'assignment_expression');
    for (const assign of assignments) {
      const leftNode = assign.childForFieldName('left');
      const rightNode = assign.childForFieldName('right');
      if (!leftNode || !rightNode) continue;

      if (leftNode.type === 'variable_name') {
        const sourceExpr = isUserInputSource(rightNode, language);
        if (sourceExpr) {
          sources.push({
            varName: leftNode.text,
            sourceExpr,
            sourceLine: leftNode.startPosition.row + 1,
            sourceCol: leftNode.startPosition.column,
            hops: [{
              expression: sourceExpr,
              line: rightNode.startPosition.row + 1,
              column: rightNode.startPosition.column,
            }],
          });
        }
      }
    }
  }

  // ── JS/TS: handle member expression assignments from original code ──
  // (This section was originally part of the assignment_expression handler above for JS/TS.
  //  For other languages, member assignments are handled in their respective blocks.)

  return sources;
}


// ── Taint propagation ────────────────────────────────────────────────

interface Assignment {
  name: string;
  value: any;    // SyntaxNode of the value expression
  line: number;  // 1-indexed
  col: number;
}

/**
 * Find all assignments in a subtree. Language-aware:
 * - JS/TS: variable_declarator, assignment_expression
 * - Python: assignment
 * - Go: short_var_declaration, assignment_statement
 * - Ruby: assignment
 * - PHP: assignment_expression
 */
function findAssignments(node: any, language?: AstLanguage): Assignment[] {
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
      const children: any[] = [];
      for (let i = 0; i < decl.childCount; i++) {
        const child = decl.child(i);
        if (child && child.isNamed) children.push(child);
      }
      if (children.length >= 2) {
        const leftList = children[0];
        const rightList = children[1];
        const leftNames: any[] = [];
        const rightValues: any[] = [];
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
      let nameNode: any = null;
      let valueNode: any = null;
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
function propagateTaint(functionNode: any, sources: TaintInfo[], maxDepth: number, language?: AstLanguage): TaintInfo[] {
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

  // ── Callback taint propagation (JS/TS-specific) ──
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

    // Get the first argument to .then/.map/etc. — should be a function
    const args = call.childForFieldName('arguments');
    if (!args) continue;

    let callbackNode: any = null;
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
    let firstParam: any = null;

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

// ── Sink detection ───────────────────────────────────────────────────

interface SinkHit {
  category: SinkCategory;
  node: any;          // the call_expression or assignment
  argNode: any;       // the specific argument that's tainted
  taintRef: string;   // name of the tainted variable found
  line: number;
  col: number;
}

/** Detect sink patterns and check for tainted arguments. Language-aware. */
function detectSinks(
  functionNode: any,
  taintedVars: Map<string, TaintInfo>,
  imports: Map<string, string>,
  categories: Set<SinkCategory>,
  language?: AstLanguage,
): SinkHit[] {
  const hits: SinkHit[] = [];
  const body = functionNode.childForFieldName('body') ?? functionNode;
  const taintedNames = new Set(taintedVars.keys());

  // Determine call expression node type based on language
  const callNodeTypes = ['call_expression'];
  if (language === 'python') callNodeTypes.push('call');
  if (language === 'ruby') callNodeTypes.push('call');
  if (language === 'php') callNodeTypes.push('function_call_expression');

  // Find all call nodes
  const calls: any[] = [];
  for (const t of callNodeTypes) {
    calls.push(...findNodes(body, t));
  }

  for (const call of calls) {
    // Extract function/method name and arguments based on language-specific node types.
    // Python 'call' has function + arguments; Ruby 'call' has receiver + method + arguments;
    // PHP 'function_call_expression' has function (name node) + arguments; Go uses call_expression.
    let fn: any = null;
    let fnText = '';
    let args: any = null;

    if (call.type === 'call_expression') {
      // JS/TS/Go
      fn = call.childForFieldName('function');
      if (!fn) continue;
      fnText = getMemberExpressionText(fn);
      args = call.childForFieldName('arguments');
    } else if (call.type === 'call' && language === 'python') {
      // Python: call node has 'function' and 'arguments' fields
      fn = call.childForFieldName('function');
      if (!fn) continue;
      fnText = getMemberExpressionText(fn);
      args = call.childForFieldName('arguments');
    } else if (call.type === 'call' && language === 'ruby') {
      // Ruby: call node has 'receiver', 'method', and 'arguments' fields
      const receiver = call.childForFieldName('receiver');
      const method = call.childForFieldName('method');
      if (method) {
        fnText = receiver ? getMemberExpressionText(receiver) + '.' + method.text : method.text;
      } else {
        continue;
      }
      args = call.childForFieldName('arguments');
      fn = method;
    } else if (call.type === 'function_call_expression' && language === 'php') {
      // PHP: function_call_expression has name (function) + arguments
      fn = call.childForFieldName('function');
      if (!fn) fn = call.child(0); // Fallback: first child is the function name
      if (!fn) continue;
      fnText = fn.text;
      args = call.childForFieldName('arguments');
    } else {
      continue;
    }

    // ── SQL sinks ──
    // Match SQL sink methods across languages (case-insensitive for Go's Query/Exec/QueryRow)
    if (categories.has('sql-query') &&
        /\.(query|exec|execute|raw|whereRaw|orderByRaw|havingRaw|joinRaw|literal|\$queryRawUnsafe|\$executeRawUnsafe|prepare|Query|Exec|QueryRow|QueryContext|ExecContext)$/.test(fnText)) {
      // Check for parameterized query (safe)
      if (isParameterizedQuery(call)) continue;

      if (args) {
        const ref = containsTaintedRef(args, taintedNames, language);
        if (ref) {
          hits.push({
            category: 'sql-query',
            node: call,
            argNode: args,
            taintRef: ref,
            line: call.startPosition.row + 1,
            col: call.startPosition.column,
          });
        }
      }
    }

    // ── Shell exec sinks ──
    if (categories.has('shell-exec') &&
        /^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$/.test(fnText)) {
      // Only flag if imported from child_process
      const moduleName = imports.get(fnText);
      if (moduleName === 'child_process' || moduleName === 'node:child_process') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec',
              node: call,
              argNode: args,
              taintRef: ref,
              line: call.startPosition.row + 1,
              col: call.startPosition.column,
            });
          }
        }
      }
    }

    // Shell exec via member expression: child_process.exec(...)
    if (categories.has('shell-exec') &&
        /^(child_process|cp)\.(exec|execSync|execFile|execFileSync|spawn|spawnSync)$/.test(fnText)) {
      const objName = fnText.split('.')[0];
      const moduleName = imports.get(objName);
      if (moduleName === 'child_process' || moduleName === 'node:child_process') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec',
              node: call,
              argNode: args,
              taintRef: ref,
              line: call.startPosition.row + 1,
              col: call.startPosition.column,
            });
          }
        }
      }
    }

    // ── SSRF sinks ──
    if (categories.has('ssrf')) {
      const isSsrf =
        fnText === 'fetch' ||
        /^(axios|got|http|https)\.(get|post|put|patch|delete|request)$/.test(fnText) ||
        fnText === 'got' ||
        fnText === 'axios';

      if (isSsrf && args) {
        // Check first argument specifically (the URL)
        let firstArg: any = null;
        for (let i = 0; i < args.childCount; i++) {
          const child = args.child(i);
          if (child && child.isNamed) {
            firstArg = child;
            break;
          }
        }
        if (firstArg) {
          const ref = containsTaintedRef(firstArg, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'ssrf',
              node: call,
              argNode: firstArg,
              taintRef: ref,
              line: call.startPosition.row + 1,
              col: call.startPosition.column,
            });
          }
        }
      }
    }

    // ── XSS sinks (call-based) ──
    if (categories.has('xss')) {
      if (fnText === 'document.write' || fnText === 'document.writeln') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'xss',
              node: call,
              argNode: args,
              taintRef: ref,
              line: call.startPosition.row + 1,
              col: call.startPosition.column,
            });
          }
        }
      }
    }

    // ── Path traversal sinks ──
    if (categories.has('path-traversal')) {
      const fsOps = new Set([
        'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
        'createReadStream', 'createWriteStream', 'readdir', 'readdirSync',
        'stat', 'statSync', 'access', 'accessSync', 'unlink', 'unlinkSync',
      ]);

      // Direct import: readFile(...)
      if (fsOps.has(fnText)) {
        const moduleName = imports.get(fnText);
        if (moduleName === 'fs' || moduleName === 'node:fs' ||
            moduleName === 'fs/promises' || moduleName === 'node:fs/promises') {
          if (args) {
            // Check first argument (path)
            let firstArg: any = null;
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.isNamed) { firstArg = child; break; }
            }
            if (firstArg) {
              const ref = containsTaintedRef(firstArg, taintedNames, language);
              if (ref) {
                hits.push({
                  category: 'path-traversal',
                  node: call,
                  argNode: firstArg,
                  taintRef: ref,
                  line: call.startPosition.row + 1,
                  col: call.startPosition.column,
                });
              }
            }
          }
        }
      }

      // Member expression: fs.readFile(...)
      const parts = fnText.split('.');
      if (parts.length === 2 && fsOps.has(parts[1])) {
        const moduleName = imports.get(parts[0]);
        if (moduleName === 'fs' || moduleName === 'node:fs' ||
            moduleName === 'fs/promises' || moduleName === 'node:fs/promises') {
          if (args) {
            let firstArg: any = null;
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.isNamed) { firstArg = child; break; }
            }
            if (firstArg) {
              const ref = containsTaintedRef(firstArg, taintedNames, language);
              if (ref) {
                hits.push({
                  category: 'path-traversal',
                  node: call,
                  argNode: firstArg,
                  taintRef: ref,
                  line: call.startPosition.row + 1,
                  col: call.startPosition.column,
                });
              }
            }
          }
        }
      }
    }

    // ── Redirect sinks ──
    if (categories.has('redirect') && /^res\.redirect$/.test(fnText)) {
      if (args) {
        const ref = containsTaintedRef(args, taintedNames, language);
        if (ref) {
          hits.push({
            category: 'redirect',
            node: call,
            argNode: args,
            taintRef: ref,
            line: call.startPosition.row + 1,
            col: call.startPosition.column,
          });
        }
      }
    }

    // ── Eval sinks ──
    if (categories.has('eval')) {
      if (fnText === 'eval') {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'eval',
              node: call,
              argNode: args,
              taintRef: ref,
              line: call.startPosition.row + 1,
              col: call.startPosition.column,
            });
          }
        }
      }

      // new Function(...)
      if (call.type === 'call_expression') {
        const parent = call.parent;
        if (parent?.type === 'new_expression') {
          const constructor = parent.childForFieldName('constructor');
          if (constructor && constructor.text === 'Function') {
            const newArgs = parent.childForFieldName('arguments');
            if (newArgs) {
              const ref = containsTaintedRef(newArgs, taintedNames, language);
              if (ref) {
                hits.push({
                  category: 'eval',
                  node: parent,
                  argNode: newArgs,
                  taintRef: ref,
                  line: parent.startPosition.row + 1,
                  col: parent.startPosition.column,
                });
              }
            }
          }
        }
      }
    }
  }

  // Also detect `new Function(...)` at top level (new_expression, not inside call_expression)
  if (categories.has('eval')) {
    const newExprs = findNodes(body, 'new_expression');
    for (const newExpr of newExprs) {
      const constructor = newExpr.childForFieldName('constructor');
      if (constructor && constructor.text === 'Function') {
        const newArgs = newExpr.childForFieldName('arguments');
        if (newArgs) {
          const ref = containsTaintedRef(newArgs, taintedNames, language);
          if (ref) {
            // Avoid duplicates (already added via call_expression parent check)
            const alreadyAdded = hits.some(
              h => h.category === 'eval' && h.line === newExpr.startPosition.row + 1 && h.col === newExpr.startPosition.column,
            );
            if (!alreadyAdded) {
              hits.push({
                category: 'eval',
                node: newExpr,
                argNode: newArgs,
                taintRef: ref,
                line: newExpr.startPosition.row + 1,
                col: newExpr.startPosition.column,
              });
            }
          }
        }
      }
    }
  }

  // ── XSS sinks (assignment-based): .innerHTML = ... ──
  if (categories.has('xss')) {
    const assignExprs = findNodes(body, 'assignment_expression');
    for (const assign of assignExprs) {
      const left = assign.childForFieldName('left');
      const right = assign.childForFieldName('right');
      if (left && right && left.type === 'member_expression') {
        const prop = left.childForFieldName('property');
        if (prop && prop.text === 'innerHTML') {
          const ref = containsTaintedRef(right, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'xss',
              node: assign,
              argNode: right,
              taintRef: ref,
              line: assign.startPosition.row + 1,
              col: assign.startPosition.column,
            });
          }
        }
      }
    }

    // JSX dangerouslySetInnerHTML prop
    const jsxAttrs = findNodes(body, 'jsx_attribute');
    for (const attr of jsxAttrs) {
      // jsx_attribute has a property_identifier child and a value child
      let propName: string | null = null;
      let value: any = null;
      const count: number = attr.childCount;
      for (let i = 0; i < count; i++) {
        const child = attr.child(i);
        if (!child) continue;
        if (child.type === 'property_identifier' || child.type === 'jsx_attribute_name') {
          propName = child.text;
        }
        if (child.type === 'jsx_expression') {
          value = child;
        }
      }
      if (propName === 'dangerouslySetInnerHTML' && value) {
        const ref = containsTaintedRef(value, taintedNames, language);
        if (ref) {
          hits.push({
            category: 'xss',
            node: attr,
            argNode: value,
            taintRef: ref,
            line: attr.startPosition.row + 1,
            col: attr.startPosition.column,
          });
        }
      }
    }
  }

  // ── Language-specific sinks (outside the main call loop) ──

  // ── Python-specific sinks ──
  if (language === 'python') {
    for (const call of calls) {
      const fn = call.childForFieldName('function');
      if (!fn) continue;
      const fnText = getMemberExpressionText(fn);
      const args = call.childForFieldName('arguments');

      // Python SQL: cursor.execute(...), connection.execute(...)
      if (categories.has('sql-query') &&
          /\.(execute|executemany|executescript)$/.test(fnText)) {
        if (isParameterizedQuery(call)) continue;
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            // Avoid duplicates from the generic sink loop
            const line = call.startPosition.row + 1;
            const col = call.startPosition.column;
            if (!hits.some(h => h.category === 'sql-query' && h.line === line && h.col === col)) {
              hits.push({
                category: 'sql-query', node: call, argNode: args,
                taintRef: ref, line, col,
              });
            }
          }
        }
      }

      // Python shell: os.system(...), subprocess.run(...), subprocess.call(...), subprocess.Popen(...)
      if (categories.has('shell-exec') &&
          /^(os\.system|os\.popen|subprocess\.(run|call|check_call|check_output|Popen|getoutput|getstatusoutput))$/.test(fnText)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }

      // Python SSRF: requests.get(...), urllib.request.urlopen(...), httpx.get(...)
      if (categories.has('ssrf') &&
          /^(requests\.(get|post|put|patch|delete|head|options|request)|urllib\.request\.(urlopen|urlretrieve)|httpx\.(get|post|put|patch|delete|request))$/.test(fnText)) {
        if (args) {
          // First argument is URL
          let firstArg: any = null;
          for (let i = 0; i < args.childCount; i++) {
            const child = args.child(i);
            if (child && child.isNamed) { firstArg = child; break; }
          }
          if (firstArg) {
            const ref = containsTaintedRef(firstArg, taintedNames, language);
            if (ref) {
              hits.push({
                category: 'ssrf', node: call, argNode: firstArg,
                taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
              });
            }
          }
        }
      }
    }
  }

  // ── Go-specific sinks ──
  if (language === 'go') {
    for (const call of calls) {
      const fn = call.childForFieldName('function');
      if (!fn) continue;
      const fnText = getMemberExpressionText(fn);
      const args = call.childForFieldName('arguments');

      // Go shell: exec.Command(...)
      if (categories.has('shell-exec') &&
          /^exec\.(Command|CommandContext)$/.test(fnText)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }

      // Go SSRF: http.Get(...), http.Post(...), http.NewRequest(...)
      if (categories.has('ssrf') &&
          /^http\.(Get|Post|Head|NewRequest|NewRequestWithContext)$/.test(fnText)) {
        if (args) {
          let firstArg: any = null;
          for (let i = 0; i < args.childCount; i++) {
            const child = args.child(i);
            if (child && child.isNamed) { firstArg = child; break; }
          }
          if (firstArg) {
            const ref = containsTaintedRef(firstArg, taintedNames, language);
            if (ref) {
              hits.push({
                category: 'ssrf', node: call, argNode: firstArg,
                taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
              });
            }
          }
        }
      }
    }
  }

  // ── Ruby-specific sinks ──
  if (language === 'ruby') {
    for (const call of calls) {
      const receiver = call.childForFieldName('receiver');
      const method = call.childForFieldName('method');
      const args = call.childForFieldName('arguments');
      if (!method) continue;
      const methodName = method.text;
      const fullName = receiver ? getMemberExpressionText(receiver) + '.' + methodName : methodName;

      // Ruby SQL: .where(...), .find_by_sql(...), .execute(...)
      if (categories.has('sql-query') &&
          /^(where|find_by_sql|execute|select_all|select_one|select_value)$/.test(methodName)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'sql-query', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }

      // Ruby shell: system(...), exec(...), `backtick`, %x{...}, Open3.capture2(...)
      if (categories.has('shell-exec') &&
          /^(system|exec|spawn|popen|IO\.popen|Open3\.(capture2|capture3|popen3|popen2))$/.test(fullName)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }
    }
  }

  // ── PHP-specific sinks ──
  if (language === 'php') {
    for (const call of calls) {
      let fn: any = call.childForFieldName('function');
      if (!fn) fn = call.child(0);
      if (!fn) continue;
      const fnText = fn.text;
      const args = call.childForFieldName('arguments');

      // PHP SQL: mysql_query(...), mysqli_query(...), ->query(...)
      if (categories.has('sql-query') &&
          /^(mysql_query|mysqli_query|pg_query|pg_query_params)$/.test(fnText)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'sql-query', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }

      // PHP shell: exec(...), system(...), passthru(...), shell_exec(...), popen(...)
      if (categories.has('shell-exec') &&
          /^(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)$/.test(fnText)) {
        if (args) {
          const ref = containsTaintedRef(args, taintedNames, language);
          if (ref) {
            hits.push({
              category: 'shell-exec', node: call, argNode: args,
              taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
            });
          }
        }
      }

      // PHP SSRF: file_get_contents(...), curl_exec(...)
      if (categories.has('ssrf') &&
          /^(file_get_contents|curl_exec|curl_setopt|fopen)$/.test(fnText)) {
        if (args) {
          let firstArg: any = null;
          for (let i = 0; i < args.childCount; i++) {
            const child = args.child(i);
            if (child && child.isNamed) { firstArg = child; break; }
          }
          if (firstArg) {
            const ref = containsTaintedRef(firstArg, taintedNames, language);
            if (ref) {
              hits.push({
                category: 'ssrf', node: call, argNode: firstArg,
                taintRef: ref, line: call.startPosition.row + 1, col: call.startPosition.column,
              });
            }
          }
        }
      }
    }
  }

  return hits;
}

// ── Sanitizer check ──────────────────────────────────────────────────

/**
 * Check if a taint path was neutralized by a sanitizer between source and sink.
 * Walk the hops and check if any intermediate assignment wraps a sanitizer call.
 */
function isSanitized(
  taintInfo: TaintInfo,
  sinkCategory: SinkCategory,
  functionNode: any,
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

/** Extract the call_expression from an await_expression. */
function getCallFromAwait(awaitNode: any): any | null {
  const count: number = awaitNode.childCount;
  for (let i = 0; i < count; i++) {
    const child = awaitNode.child(i);
    if (child && child.type === 'call_expression') return child;
  }
  return null;
}

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
function findFunctionScopes(rootNode: any): any[] {
  const scopes: any[] = [];
  walkTree(rootNode, (node) => {
    if (FUNCTION_TYPES.has(node.type)) {
      scopes.push(node);
    }
  });
  return scopes;
}

// ── Inter-function taint signatures ─────────────────────────────────

interface FunctionTaintSignature {
  name: string;
  node: any;
  /** Maps parameter index → which sink categories that parameter reaches. */
  paramSinks: Map<number, SinkCategory[]>;
}

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
function buildFunctionSignatures(
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

  // ── Phase 2: Inter-function taint (same file) ──
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
