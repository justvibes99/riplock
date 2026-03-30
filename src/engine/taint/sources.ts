/**
 * Taint source detection.
 * Identifies user-input sources in function bodies across supported languages.
 */
import type { AstLanguage } from '../../checks/types.js';
import { walkTree, findNodes, getMemberExpressionText } from '../ast-helpers.js';
import type { TaintInfo } from './types.js';

/**
 * Check if a node is a user-input source expression.
 * Returns a description string if it is, null otherwise.
 * Language-aware: detects framework-specific request input patterns.
 */
export function isUserInputSource(node: any, language?: AstLanguage): string | null {
  if (!node) return null;

  const text = node.text;

  // -- JS/TS sources --
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

  // -- Python sources --
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

  // -- Go sources --
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
        // Also: r.URL.Query().Get -- the full text includes the call
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

  // -- Ruby sources --
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

  // -- PHP sources --
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
export function detectSources(functionNode: any, language?: AstLanguage): TaintInfo[] {
  const sources: TaintInfo[] = [];
  const body = functionNode.childForFieldName('body') ?? functionNode;

  // -- JS/TS: variable_declarator nodes --
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

  // -- Python: assignment nodes (q = request.args.get('q')) --
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

  // -- Go: short_var_declaration (id := r.FormValue("id")) --
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

  // -- Ruby: assignment nodes (id = params[:id]) --
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

  // -- PHP: assignment_expression nodes ($id = $_GET['id']) --
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

  return sources;
}
