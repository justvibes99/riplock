/**
 * Sink detection for taint tracking.
 * Identifies dangerous function calls and assignments that receive tainted data.
 */
import type { SinkCategory, AstLanguage } from '../../checks/types.js';
import type { SyntaxNode } from '../ast-helpers.js';
import { findNodes, getMemberExpressionText } from '../ast-helpers.js';
import { containsTaintedRef } from '../ast-helpers.js';
import type { TaintInfo, SinkHit } from './types.js';

/**
 * Check if a sink call uses parameterized queries (safe pattern).
 * e.g. query('SELECT ... WHERE id = $1', [userInput])
 */
export function isParameterizedQuery(callNode: SyntaxNode): boolean {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;

  // Needs at least two arguments: a query string and a params array
  const argChildren: SyntaxNode[] = [];
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

/** Detect sink patterns and check for tainted arguments. Language-aware. */
export function detectSinks(
  functionNode: SyntaxNode,
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
  const calls: SyntaxNode[] = [];
  for (const t of callNodeTypes) {
    calls.push(...findNodes(body, t));
  }

  for (const call of calls) {
    // Extract function/method name and arguments based on language-specific node types.
    let fn: SyntaxNode | null = null;
    let fnText = '';
    let args: SyntaxNode | null = null;

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

    // -- SQL sinks --
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

    // -- Shell exec sinks --
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

    // -- SSRF sinks --
    if (categories.has('ssrf')) {
      const isSsrf =
        fnText === 'fetch' ||
        /^(axios|got|http|https)\.(get|post|put|patch|delete|request)$/.test(fnText) ||
        fnText === 'got' ||
        fnText === 'axios';

      if (isSsrf && args) {
        // Check first argument specifically (the URL)
        let firstArg: SyntaxNode | null = null;
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

    // -- XSS sinks (call-based) --
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

    // -- Path traversal sinks --
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
            let firstArg: SyntaxNode | null = null;
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
            let firstArg: SyntaxNode | null = null;
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

    // -- Redirect sinks --
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

    // -- Eval sinks --
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

  // -- XSS sinks (assignment-based): .innerHTML = ... --
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
      let value: SyntaxNode | null = null;
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

  // -- Language-specific sinks (outside the main call loop) --

  // -- Python-specific sinks --
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
          let firstArg: SyntaxNode | null = null;
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

  // -- Go-specific sinks --
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
          let firstArg: SyntaxNode | null = null;
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

  // -- Ruby-specific sinks --
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

  // -- PHP-specific sinks --
  if (language === 'php') {
    for (const call of calls) {
      let fn: SyntaxNode | null = call.childForFieldName('function');
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
          let firstArg: SyntaxNode | null = null;
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
