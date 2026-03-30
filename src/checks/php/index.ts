import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---- PHP Security Checks ----

export const phpChecks: CheckDefinition[] = [
  // PHP001 - SQL Injection
  createLineCheck({
    id: 'PHP001',
    category: 'php',
    name: 'SQL Injection',
    severity: 'critical',
    pattern: /(?:mysql_query|mysqli_query|->query)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE).*\$_(?:GET|POST|REQUEST)/gi,
    appliesTo: ['php'],
    message:
      'User input in SQL query. Use prepared statements with PDO or mysqli.',
    fix: 'Use prepared statements with bound parameters instead of concatenating user input into queries.',
  }),

  // PHP002 - Command Injection
  createLineCheck({
    id: 'PHP002',
    category: 'php',
    name: 'Command Injection',
    severity: 'critical',
    pattern: /(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST)/g,
    appliesTo: ['php'],
    message: 'User input in shell command.',
    fix: 'Use escapeshellarg() or escapeshellcmd() to sanitize input, or avoid shell commands entirely.',
  }),

  // PHP003 - eval Usage
  createLineCheck({
    id: 'PHP003',
    category: 'php',
    name: 'eval with User Input',
    severity: 'critical',
    pattern: /\beval\s*\(\s*\$_(?:GET|POST|REQUEST)/g,
    appliesTo: ['php'],
    message: 'eval with user input executes arbitrary PHP code.',
    fix: 'Never pass user input to eval. Use a safe alternative or a whitelist approach.',
  }),

  // PHP004 - File Inclusion
  createLineCheck({
    id: 'PHP004',
    category: 'php',
    name: 'File Inclusion',
    severity: 'critical',
    pattern: /(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)/g,
    appliesTo: ['php'],
    message:
      'User input in file include. An attacker can include arbitrary files, including remote code.',
    fix: 'Validate file paths against an allowlist. Never pass raw user input to include/require.',
  }),

  // PHP005 - XSS (echo without escape)
  createLineCheck({
    id: 'PHP005',
    category: 'php',
    name: 'XSS (echo without escape)',
    severity: 'high',
    pattern: /echo\s+\$_(?:GET|POST|REQUEST)/g,
    appliesTo: ['php'],
    message:
      'User input echoed without escaping. Use htmlspecialchars() to prevent XSS.',
    fix: 'Wrap user input with htmlspecialchars() before outputting it.',
    fixCode: `echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');`,
  }),

  // PHP006 - Insecure Password Hash
  createLineCheck({
    id: 'PHP006',
    category: 'php',
    name: 'Insecure Password Hash',
    severity: 'high',
    pattern: /(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd)/gi,
    appliesTo: ['php'],
    message:
      'MD5/SHA1 for passwords is broken. Use password_hash() with PASSWORD_BCRYPT.',
    fix: 'Use password_hash($password, PASSWORD_BCRYPT) for hashing and password_verify() for checking.',
  }),

  // PHP007 - Register Globals
  createLineCheck({
    id: 'PHP007',
    category: 'php',
    name: 'Register Globals',
    severity: 'critical',
    pattern: /register_globals\s*=\s*(?:On|on|1)/g,
    appliesTo: ['php'],
    message:
      'register_globals allows attackers to set any variable via query parameters.',
    fix: 'Set register_globals = Off. This directive was removed in PHP 5.4.',
  }),

  // PHP008 - Error Display
  createLineCheck({
    id: 'PHP008',
    category: 'php',
    name: 'Error Display Enabled',
    severity: 'high',
    pattern: /display_errors\s*=\s*(?:On|on|1)/g,
    appliesTo: ['php'],
    validate(_match, line) {
      // Skip if line is a comment (;-prefixed in php.ini)
      if (/^\s*;/.test(line)) return false;
      return true;
    },
    message:
      'PHP error display is enabled. Error messages reveal file paths and SQL queries to attackers.',
    fix: 'Set display_errors = Off in production. Log errors to a file instead with log_errors = On.',
  }),

  // PHP009 - File Upload No Validation
  createLineCheck({
    id: 'PHP009',
    category: 'php',
    name: 'File Upload No Validation',
    severity: 'high',
    pattern: /move_uploaded_file\s*\(\s*\$_FILES/g,
    appliesTo: ['php'],
    message:
      'File upload without type validation. An attacker can upload executable PHP files.',
    fix: 'Validate file type with finfo_file() or getimagesize(). Restrict allowed extensions and store uploads outside the web root.',
  }),
];
