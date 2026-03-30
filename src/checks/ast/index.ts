import type { AstCheck, AstCheckContext, CheckDefinition, FileEntry, Finding, SinkCategory, TaintPath } from '../types.js';

// ── Helpers ────────────────────────────────────────────────────────────

function taintFinding(
  path: TaintPath,
  opts: {
    checkId: string;
    title: string;
    message: string;
    severity: 'critical' | 'high';
    category: string;
    fix: string;
    fixCode?: string;
    file: FileEntry;
  },
): Finding {
  return {
    checkId: opts.checkId,
    title: opts.title,
    message: opts.message,
    severity: opts.severity,
    category: opts.category as Finding['category'],
    location: {
      filePath: opts.file.relativePath,
      startLine: path.sink.line,  // already 1-indexed from taint tracker
      startColumn: path.sink.column,
    },
    fix: opts.fix,
    fixCode: opts.fixCode,
    taintFlow: [
      `${path.source.expression} (line ${path.source.line})`,
      ...path.intermediates.map(n => `${n.expression} (line ${n.line})`),
      `${path.sink.expression} (line ${path.sink.line})`,
    ],
    confidence: 'high',
  };
}

import { walkTree, type SyntaxNode } from '../../engine/ast-helpers.js';

// ── AST-INJ001: SQL Injection (Taint-Tracked) ─────────────────────────

const astInj001: AstCheck = {
  level: 'ast',
  id: 'AST-INJ001',
  name: 'SQL Injection (Taint-Tracked)',
  description: 'Detects user input flowing into SQL queries through variables.',
  category: 'injection',
  defaultSeverity: 'critical',
  languages: ['javascript', 'typescript', 'tsx', 'python', 'go', 'ruby', 'php'],
  sinkCategories: ['sql-query'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const paths = astCtx.findTaintPaths({ sinkCategories: ['sql-query'] });
    return paths.map(p =>
      taintFinding(p, {
        checkId: 'AST-INJ001',
        title: 'SQL Injection (Taint-Tracked)',
        message:
          'User input flows into a SQL query through variable assignment. An attacker can modify the query to read, change, or delete data.',
        severity: 'critical',
        category: 'injection',
        fix: 'Use parameterized queries. Pass user values as parameters, never interpolate them into query strings.',
        fixCode: "// Safe:\ndb.query('SELECT * FROM users WHERE id = $1', [userId]);",
        file: astCtx.file,
      }),
    );
  },
};

// ── AST-INJ002: Command Injection (Taint-Tracked) ─────────────────────

const astInj002: AstCheck = {
  level: 'ast',
  id: 'AST-INJ002',
  name: 'Command Injection (Taint-Tracked)',
  description: 'Detects user input flowing into shell execution through variables, with import awareness.',
  category: 'injection',
  defaultSeverity: 'critical',
  languages: ['javascript', 'typescript', 'tsx', 'python', 'go', 'ruby', 'php'],
  sinkCategories: ['shell-exec'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const paths = astCtx.findTaintPaths({ sinkCategories: ['shell-exec'] });
    return paths.map(p =>
      taintFinding(p, {
        checkId: 'AST-INJ002',
        title: 'Command Injection (Taint-Tracked)',
        message:
          'User input flows into a shell command through variable assignment. An attacker can execute arbitrary system commands.',
        severity: 'critical',
        category: 'injection',
        fix: 'Avoid passing user input to shell commands. Use execFile with an argument array instead of exec with string interpolation.',
        fixCode: "// Safe:\nexecFile('/usr/bin/ls', [userDir], callback);",
        file: astCtx.file,
      }),
    );
  },
};

// ── AST-INJ003: SSRF (Taint-Tracked) ──────────────────────────────────

const astInj003: AstCheck = {
  level: 'ast',
  id: 'AST-INJ003',
  name: 'Server-Side Request Forgery (Taint-Tracked)',
  description: 'Detects user input flowing into outbound HTTP requests.',
  category: 'injection',
  defaultSeverity: 'critical',
  languages: ['javascript', 'typescript', 'tsx', 'python', 'go', 'php'],
  sinkCategories: ['ssrf'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const paths = astCtx.findTaintPaths({ sinkCategories: ['ssrf'] });
    return paths.map(p =>
      taintFinding(p, {
        checkId: 'AST-INJ003',
        title: 'Server-Side Request Forgery (Taint-Tracked)',
        message:
          'User input flows into an outbound HTTP request URL. An attacker can make the server send requests to internal services or arbitrary hosts.',
        severity: 'critical',
        category: 'injection',
        fix: 'Validate and allowlist target URLs. Never let user input directly control the request destination.',
        fixCode:
          "// Safe:\nconst allowedHosts = new Set(['api.example.com']);\nconst url = new URL(userUrl);\nif (!allowedHosts.has(url.hostname)) throw new Error('Blocked');",
        file: astCtx.file,
      }),
    );
  },
};

// ── AST-INJ004: XSS (Taint-Tracked) ───────────────────────────────────

const astInj004: AstCheck = {
  level: 'ast',
  id: 'AST-INJ004',
  name: 'Cross-Site Scripting (Taint-Tracked)',
  description: 'Detects user input flowing into DOM sinks like innerHTML or document.write.',
  category: 'injection',
  defaultSeverity: 'high',
  languages: ['javascript', 'typescript', 'tsx', 'php'],
  sinkCategories: ['xss'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const paths = astCtx.findTaintPaths({ sinkCategories: ['xss'] });
    return paths.map(p =>
      taintFinding(p, {
        checkId: 'AST-INJ004',
        title: 'Cross-Site Scripting (Taint-Tracked)',
        message:
          'User input flows into a DOM sink. An attacker can inject malicious scripts that execute in other users\' browsers.',
        severity: 'high',
        category: 'injection',
        fix: 'Sanitize output with DOMPurify or use safe APIs like textContent instead of innerHTML.',
        fixCode: "// Safe:\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);",
        file: astCtx.file,
      }),
    );
  },
};

// ── AST-INJ005: Path Traversal (Taint-Tracked) ────────────────────────

const astInj005: AstCheck = {
  level: 'ast',
  id: 'AST-INJ005',
  name: 'Path Traversal (Taint-Tracked)',
  description: 'Detects user input flowing into filesystem operations.',
  category: 'injection',
  defaultSeverity: 'high',
  languages: ['javascript', 'typescript', 'tsx', 'python', 'go', 'ruby', 'php'],
  sinkCategories: ['path-traversal'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const paths = astCtx.findTaintPaths({ sinkCategories: ['path-traversal'] });
    return paths.map(p =>
      taintFinding(p, {
        checkId: 'AST-INJ005',
        title: 'Path Traversal (Taint-Tracked)',
        message:
          'User input flows into a filesystem operation. An attacker can read or write arbitrary files using ../ sequences.',
        severity: 'high',
        category: 'injection',
        fix: 'Resolve the path and verify it stays within an allowed base directory. Use path.resolve() and check the prefix.',
        fixCode:
          "// Safe:\nconst resolved = path.resolve(baseDir, userPath);\nif (!resolved.startsWith(baseDir)) throw new Error('Traversal blocked');",
        file: astCtx.file,
      }),
    );
  },
};

// ── AST-AUTH001: Server Component Prop Leak ────────────────────────────

/** Environment variable names that suggest secrets. */
const SECRET_ENV_PATTERN = /^(SECRET|KEY|TOKEN|PASSWORD|PRIVATE|API_KEY|AUTH|CREDENTIAL)/i;

const astAuth001: AstCheck = {
  level: 'ast',
  id: 'AST-AUTH001',
  name: 'Server Component Prop Leak',
  description: 'Detects process.env secrets passed as JSX props, which may leak to the client.',
  category: 'data-exposure',
  defaultSeverity: 'high',
  languages: ['tsx'],
  analyze(astCtx: AstCheckContext): Finding[] {
    const findings: Finding[] = [];

    walkTree(astCtx.rootNode as SyntaxNode, (node) => {
      // Look for jsx_attribute nodes
      if (node.type !== 'jsx_attribute') return;

      // Find the value child — typically a jsx_expression containing the env access
      let valueNode: any = null;
      const count: number = node.childCount;
      for (let i = 0; i < count; i++) {
        const child = node.child(i);
        if (child && (child.type === 'jsx_expression' || child.type === 'string')) {
          valueNode = child;
          break;
        }
      }
      if (!valueNode) return;

      const valueText: string = valueNode.text;

      // Check for process.env.SECRET_NAME patterns
      const envMatch = valueText.match(/process\.env\.([A-Z_][A-Z0-9_]*)/);
      if (!envMatch) return;

      const envName = envMatch[1];
      if (!SECRET_ENV_PATTERN.test(envName)) return;

      findings.push({
        checkId: 'AST-AUTH001',
        title: 'Server Component Prop Leak',
        message: `process.env.${envName} is passed as a JSX prop. In frameworks like Next.js, props passed to client components are serialized and sent to the browser, exposing the secret.`,
        severity: 'high',
        category: 'data-exposure',
        location: {
          filePath: astCtx.file.relativePath,
          startLine: node.startPosition.row + 1,
          startColumn: node.startPosition.column,
        },
        fix: 'Keep secrets server-side. Access them only in server actions, API routes, or getServerSideProps — never pass them as component props.',
        confidence: 'high',
      });
    });

    return findings;
  },
};

// ── Export ──────────────────────────────────────────────────────────────

export const astChecks: CheckDefinition[] = [
  astInj001,
  astInj002,
  astInj003,
  astInj004,
  astInj005,
  astAuth001,
];
