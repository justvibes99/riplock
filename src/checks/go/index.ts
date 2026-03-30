import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---- Go Security Checks ----

export const goChecks: CheckDefinition[] = [
  // GO001 - SQL Injection (fmt.Sprintf)
  createLineCheck({
    id: 'GO001',
    category: 'go',
    name: 'SQL Injection (fmt.Sprintf)',
    severity: 'critical',
    pattern: /fmt\.Sprintf\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s/gi,
    appliesTo: ['go'],
    message:
      'SQL query built with fmt.Sprintf. Use parameterized queries with database/sql.',
    fix: 'Use parameterized queries with placeholder arguments instead of fmt.Sprintf.',
    fixCode: `db.Query("SELECT * FROM users WHERE id = $1", id)`,
  }),

  // GO002 - SQL Injection (string concat)
  createLineCheck({
    id: 'GO002',
    category: 'go',
    name: 'SQL Injection (string concat)',
    severity: 'critical',
    pattern: /(?:Query|Exec|QueryRow)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+/gi,
    appliesTo: ['go'],
    message: 'SQL query built with string concatenation.',
    fix: 'Use parameterized queries with placeholder arguments instead of string concatenation.',
  }),

  // GO003 - Command Injection
  createLineCheck({
    id: 'GO003',
    category: 'go',
    name: 'Command Injection',
    severity: 'critical',
    pattern: /exec\.Command\s*\(\s*['"](?:sh|bash|cmd)['"]\s*,\s*['"](?:-c|-Command)['"]\s*,/g,
    appliesTo: ['go'],
    message:
      'Shell command execution via exec.Command with sh -c. Use exec.Command with direct binary + args instead.',
    fix: 'Call the binary directly with exec.Command and pass arguments as separate strings instead of using a shell.',
  }),

  // GO004 - Hardcoded Credentials
  createLineCheck({
    id: 'GO004',
    category: 'go',
    name: 'Hardcoded Credentials',
    severity: 'high',
    pattern: /(?:password|secret|apiKey|token)\s*(?::=|=)\s*['"][^'"]{8,}['"]/gi,
    appliesTo: ['go'],
    validate(_match, line) {
      if (/os\.Getenv/.test(line)) return false;
      if (/viper/.test(line)) return false;
      if (/config\./.test(line)) return false;
      return true;
    },
    message:
      'Credentials are hardcoded in source code. Anyone with repository access can see them.',
    fix: 'Load secrets from environment variables or a configuration manager like Viper.',
  }),

  // GO005 - Insecure TLS Config
  createLineCheck({
    id: 'GO005',
    category: 'go',
    name: 'Insecure TLS Config',
    severity: 'high',
    pattern: /InsecureSkipVerify\s*:\s*true/g,
    appliesTo: ['go'],
    message:
      'TLS certificate verification is disabled. This allows man-in-the-middle attacks.',
    fix: 'Remove InsecureSkipVerify or set it to false. Configure proper CA certificates if needed.',
  }),

  // GO006 - Unhandled Error
  createLineCheck({
    id: 'GO006',
    category: 'go',
    name: 'Unhandled Error',
    severity: 'medium',
    pattern: /,\s*_\s*(?::=|=)\s*\w+\.\w+\(/g,
    appliesTo: ['go'],
    validate(_match, _line, file) {
      // Skip test files
      if (/_test\.go$/.test(file.relativePath)) return false;
      return true;
    },
    message:
      'Error return value is discarded. Unhandled errors can hide security issues.',
    fix: 'Handle the error explicitly. At minimum, log it. In security-sensitive code, return or abort on error.',
  }),

  // GO007 - Unsafe Pointer
  createLineCheck({
    id: 'GO007',
    category: 'go',
    name: 'Unsafe Pointer',
    severity: 'medium',
    pattern: /unsafe\.Pointer/g,
    appliesTo: ['go'],
    message:
      'unsafe.Pointer bypasses Go\'s type safety. This can cause memory corruption.',
    fix: 'Avoid unsafe.Pointer unless absolutely necessary. Use type-safe alternatives.',
  }),

  // GO008 - net/http No Timeout
  createLineCheck({
    id: 'GO008',
    category: 'go',
    name: 'HTTP Server No Timeout',
    severity: 'medium',
    pattern: /&http\.Server\s*\{/g,
    appliesTo: ['go'],
    validate(_match, line) {
      if (/ReadTimeout/.test(line)) return false;
      if (/WriteTimeout/.test(line)) return false;
      if (/IdleTimeout/.test(line)) return false;
      return true;
    },
    message:
      'HTTP server has no timeout configuration. Slow clients can exhaust connections.',
    fix: 'Set ReadTimeout, WriteTimeout, and IdleTimeout on your http.Server.',
  }),

  // GO009 - Exported Sensitive Field
  createLineCheck({
    id: 'GO009',
    category: 'go',
    name: 'Exported Sensitive Field',
    severity: 'medium',
    pattern: /(?:Password|Secret|Token|ApiKey|PrivateKey)\s+string\s+`json:"/g,
    appliesTo: ['go'],
    message:
      'Sensitive field is JSON-exported. It will be included in API responses.',
    fix: 'Use `json:"-"` to exclude the field from JSON output, or use a separate response struct.',
  }),
];
