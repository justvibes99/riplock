import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---- Ruby Security Checks ----

export const rubyChecks: CheckDefinition[] = [
  // RB001 - SQL Injection
  createLineCheck({
    id: 'RB001',
    category: 'ruby',
    name: 'SQL Injection',
    severity: 'critical',
    pattern: /\.where\s*\(\s*['"].*#\{/g,
    appliesTo: ['rb'],
    message:
      'String interpolation in ActiveRecord where clause. Use parameterized queries.',
    fix: 'Use parameterized queries with placeholder arguments instead of string interpolation.',
    fixCode: `User.where("name = ?", params[:name])`,
  }),

  // RB002 - Command Injection
  createLineCheck({
    id: 'RB002',
    category: 'ruby',
    name: 'Command Injection',
    severity: 'critical',
    pattern: /(?:\bsystem\b|\bexec\b|%x\[|`).*#\{/g,
    appliesTo: ['rb'],
    message: 'User input in shell command.',
    fix: 'Use array form of system() or Open3 to avoid shell interpretation of user input.',
  }),

  // RB003 - Mass Assignment (permit!)
  createLineCheck({
    id: 'RB003',
    category: 'ruby',
    name: 'Mass Assignment (permit!)',
    severity: 'high',
    pattern: /\.permit!\s*\(/g,
    appliesTo: ['rb'],
    message:
      'permit! allows ALL parameters. Use permit(:field1, :field2) to whitelist specific fields.',
    fix: 'Replace permit! with permit(:field1, :field2) listing only the fields you expect.',
  }),

  // RB004 - eval Usage
  createLineCheck({
    id: 'RB004',
    category: 'ruby',
    name: 'eval with User Input',
    severity: 'critical',
    pattern: /\beval\s*\(\s*(?:params|request|cookies)/g,
    appliesTo: ['rb'],
    message: 'eval with user input executes arbitrary Ruby code.',
    fix: 'Never pass user input to eval. Use a safe parser or a whitelist approach.',
  }),

  // RB005 - Rails Debug Mode
  createLineCheck({
    id: 'RB005',
    category: 'ruby',
    name: 'Rails Debug Mode',
    severity: 'high',
    pattern: /config\.consider_all_requests_local\s*=\s*true/g,
    appliesTo: ['rb'],
    message:
      'Rails shows detailed error pages to all users. Set to false in production.',
    fix: 'Set config.consider_all_requests_local = false in production.rb.',
  }),

  // RB006 - Open Redirect
  createLineCheck({
    id: 'RB006',
    category: 'ruby',
    name: 'Open Redirect',
    severity: 'medium',
    pattern: /redirect_to\s+params\[/g,
    appliesTo: ['rb'],
    message: 'Redirect URL comes from user input. Validate against an allowlist.',
    fix: 'Validate redirect targets against an allowlist of permitted URLs or paths.',
  }),

  // RB007 - Hardcoded Secret
  createLineCheck({
    id: 'RB007',
    category: 'ruby',
    name: 'Hardcoded Secret Key Base',
    severity: 'high',
    pattern: /secret_key_base\s*=\s*['"][^'"]{8,}['"]/g,
    appliesTo: ['rb'],
    validate(_match, line) {
      if (/ENV/.test(line)) return false;
      if (/Rails\.application\.credentials/.test(line)) return false;
      return true;
    },
    message: 'Rails secret_key_base is hardcoded.',
    fix: 'Load secret_key_base from Rails credentials or an environment variable.',
  }),

  // RB008 - Unsafe Deserialization
  createLineCheck({
    id: 'RB008',
    category: 'ruby',
    name: 'Unsafe Deserialization',
    severity: 'critical',
    pattern: /(?:Marshal\.load|YAML\.(?:load|unsafe_load))\s*\(/g,
    appliesTo: ['rb'],
    validate(_match, line) {
      if (/YAML\.safe_load/.test(line)) return false;
      return true;
    },
    message:
      'Deserializing untrusted data can execute arbitrary code. Use YAML.safe_load or JSON.',
    fix: 'Use YAML.safe_load or JSON.parse for untrusted data. Never use Marshal.load or YAML.load on user input.',
  }),
];
