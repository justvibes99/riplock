/**
 * Supply chain attack detection checks.
 *
 * These patterns are suspicious INSIDE a dependency package but may be normal
 * in application code. They are only run during `--scan-deps` mode against
 * files inside node_modules/, site-packages/, vendor/, etc.
 *
 * Tuned against real-world deps to minimize false positives:
 * - debug, express, vite, playwright, acorn, eslint, hono, typescript-eslint
 *   should all produce ZERO findings.
 */
import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

/**
 * Detect minified/bundled files by checking for extremely long lines.
 * Minified code bundles many modules together, making co-occurrence checks
 * meaningless (bulk env from `debug` + fetch from `node-fetch` in one blob).
 * The original source files are also in the package and get scanned individually.
 */
function isMinified(lines: readonly string[]): boolean {
  return lines.some(l => l.length > 2000);
}

export const supplyChainChecks: CheckDefinition[] = [
  // SC001 - Bulk Environment Variable Access
  // Only flag if the package ALSO has network calls (exfiltration indicator)
  // Standalone env reading (like debug checking DEBUG_*) is normal
  {
    level: 'file',
    id: 'SC001',
    name: 'Bulk Environment Variable Access with Network Call',
    description: 'Dependency reads all environment variables AND makes network calls in the same file.',
    category: 'supply-chain',
    defaultSeverity: 'critical',
    appliesTo: ['js', 'ts', 'py', 'rb'],
    fastFilter: 'process.env',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      const content = file.content ?? await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Must have bulk env access
      const hasBulkEnv = /Object\.(?:keys|values|entries)\s*\(\s*process\.env\)|os\.environ\.(?:items|keys|values)\(\)|ENV\.(?:to_h|each)/.test(content);
      if (!hasBulkEnv) return [];

      // Must ALSO have a network call in the same file (exfiltration)
      const hasNetworkCall = /(?:https?\.request|fetch\s*\(|axios\.|got\(|requests?\.|urllib|http\.request|net\.connect|WebSocket)/.test(content);
      if (!hasNetworkCall) return [];

      const lines = file.lines ?? await ctx.readLines(file.absolutePath);

      // Skip minified bundles — co-occurrence is meaningless when many
      // modules are concatenated into a single file
      if (isMinified(lines)) return [];
      let envLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/Object\.(?:keys|values|entries)\s*\(\s*process\.env/.test(lines[i])) {
          envLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(lines, envLine, ctx.config.contextLines);

      return [{
        checkId: 'SC001',
        title: 'Bulk Environment Variable Access with Network Call',
        message: 'Dependency reads ALL environment variables AND makes network requests in the same file. This is a credential harvesting + exfiltration pattern.',
        severity: 'critical',
        category: 'supply-chain',
        location: { filePath: file.relativePath, startLine: envLine },
        snippet, contextBefore, contextAfter,
        fix: 'Inspect this file carefully. If the bulk env read and network call are unrelated, the package may be safe. Otherwise, remove it immediately.',
      }];
    },
  } satisfies FileCheck,

  // SC002 - HTTP POST with encoded/collected secrets
  // Tighter: must have POST (not just fetch) AND secret-like data in the body
  createLineCheck({
    id: 'SC002',
    name: 'HTTP POST with Secrets',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:\.post|http\.request)\s*\([^)]*(?:process\.env|os\.environ|ENV\[|secret|credential|password|token)/gi,
    appliesTo: ['js', 'ts', 'py', 'rb'],
    validate(_match, line, file) {
      // Must be a POST, not just a fetch/get
      if (/\.get\s*\(/.test(line) && !/\.post/.test(line)) return false;
      // Skip test files within deps
      if (/test|spec|__test__|fixture/i.test(file.relativePath)) return false;
      // Skip minified lines — keywords may co-occur by coincidence in bundled code
      if (line.length > 500) return false;
      return true;
    },
    message: 'Dependency sends secrets or environment data via HTTP POST. This is a credential exfiltration pattern.',
    fix: 'Remove this dependency immediately and rotate any exposed secrets.',
  }),

  // SC003 - eval/exec of Fetched Content (unchanged — very specific, low FP)
  createLineCheck({
    id: 'SC003',
    name: 'Remote Code Execution via Fetch',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:eval|exec|Function)\s*\(\s*(?:await\s+)?(?:fetch|axios|got|requests?\.get|urllib)/g,
    appliesTo: ['js', 'ts', 'py'],
    message: 'Dependency downloads and executes code at runtime. This is a remote code execution backdoor.',
    fix: 'Remove this dependency immediately.',
  }),

  // SC004 - Base64 Decoded Execution (unchanged — very specific)
  createLineCheck({
    id: 'SC004',
    name: 'Base64 Decoded Execution',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:eval|exec|Function|subprocess)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)/g,
    appliesTo: ['js', 'ts', 'py'],
    message: 'Dependency decodes and executes base64 content. This is an obfuscation technique used in supply chain attacks.',
    fix: 'Remove this dependency immediately.',
  }),

  // SC005 - Obfuscated Code
  // Tighter: skip known parser/unicode packages, require LONGER sequences
  createLineCheck({
    id: 'SC005',
    name: 'Obfuscated Code',
    category: 'supply-chain',
    severity: 'high',
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}/g,  // 20+ hex pairs (was 10)
    appliesTo: ['js', 'ts', 'py'],
    validate(_match, line, file) {
      // Skip .d.ts type definition files
      if (file.basename.endsWith('.d.ts')) return false;
      // Skip data-heavy lines (>80% hex content) — these are unicode lookup tables
      // not obfuscated code. Real obfuscated code has control flow mixed in.
      const hexBytes = (line.match(/\\x[0-9a-f]{2}/gi) || []).length * 4;
      if (hexBytes > line.length * 0.8) return false;
      // Skip minified lines — hex in minified bundles is usually inlined data
      if (line.length > 1000) return false;
      return true;
    },
    message: 'Dependency contains heavily obfuscated hex sequences (20+ bytes). This may indicate hidden malicious code.',
    fix: 'Inspect the obfuscated content. Compare with the package source on GitHub/npm to check for tampering.',
  }),

  // SC006 - Reverse Shell Pattern (unchanged — very specific)
  createLineCheck({
    id: 'SC006',
    name: 'Reverse Shell Pattern',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:\/bin\/(?:sh|bash|zsh)|cmd\.exe).*(?:socket|net\.connect|TCPSocket|subprocess\.Popen)/g,
    appliesTo: ['js', 'ts', 'py', 'rb'],
    validate(_match, _line, file) {
      // Skip test fixtures
      if (/test|spec|fixture|example/i.test(file.relativePath)) return false;
      return true;
    },
    message: 'Dependency opens a shell connected to a network socket. This is a reverse shell.',
    fix: 'Remove this dependency immediately and audit your system for unauthorized access.',
  }),

  // SC007 - Cryptocurrency Mining (unchanged — very specific keywords)
  createLineCheck({
    id: 'SC007',
    name: 'Cryptocurrency Mining',
    category: 'supply-chain',
    severity: 'high',
    pattern: /(?:coinhive|cryptonight|stratum\+tcp|xmrig|minergate)/gi,
    appliesTo: ['js', 'ts', 'py'],
    message: 'Dependency contains cryptocurrency mining references.',
    fix: 'Remove this dependency. Cryptomining in a dependency is unauthorized resource usage.',
  }),

  // SC008 - Postinstall Network Fetch (unchanged — checks package.json scripts)
  {
    level: 'file',
    id: 'SC008',
    name: 'Install Script Network Fetch',
    description: 'Detects package.json install scripts that download external content.',
    category: 'supply-chain',
    defaultSeverity: 'critical',
    appliesTo: ['json'],
    fastFilter: 'install',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      if (file.basename !== 'package.json') return [];

      const content = file.content ?? await ctx.readFile(file.absolutePath);
      if (!content) return [];

      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(content);
      } catch {
        return [];
      }

      const scripts = parsed.scripts as Record<string, string> | undefined;
      if (!scripts) return [];

      const findings: Finding[] = [];
      const dangerousScriptRe = /(?:curl|wget|node\s+-e|python\s+-c).*(?:https?:\/\/|\|)/;
      const hookNames = ['preinstall', 'install', 'postinstall'];

      const lines = file.lines ?? await ctx.readLines(file.absolutePath);

      for (const hook of hookNames) {
        const scriptValue = scripts[hook];
        if (!scriptValue || !dangerousScriptRe.test(scriptValue)) continue;

        let lineNum = 1;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(`"${hook}"`) || lines[i].includes(`'${hook}'`)) {
            lineNum = i + 1;
            break;
          }
        }

        const { snippet, contextBefore, contextAfter } = extractSnippet(lines, lineNum, ctx.config.contextLines);

        findings.push({
          checkId: 'SC008',
          title: 'Install Script Network Fetch',
          message: `Package "${hook}" script downloads and executes external content: "${scriptValue}". This is a common supply chain attack vector.`,
          severity: 'critical',
          category: 'supply-chain',
          location: { filePath: file.relativePath, startLine: lineNum },
          snippet, contextBefore, contextAfter,
          fix: 'Investigate the install script. Legitimate packages rarely need to download content during installation.',
        });
      }

      return findings;
    },
  } satisfies FileCheck,

  // SC009 - DNS Exfiltration (unchanged — very specific)
  createLineCheck({
    id: 'SC009',
    name: 'DNS Exfiltration',
    category: 'supply-chain',
    severity: 'high',
    pattern: /(?:dns\.resolve|dns\.lookup)\s*\(.*(?:process\.env|secret|token|password)/gi,
    appliesTo: ['js', 'ts', 'py'],
    message: 'Dependency performs DNS lookups using secret values. This is a DNS exfiltration technique.',
    fix: 'Remove this dependency. DNS exfiltration encodes stolen data in DNS queries.',
  }),

  // SC010 - Systemd/Cron Persistence
  // Much tighter: require actual systemd unit file writes or crontab commands
  // NOT just the word ".service" (which matches JS service workers, etc.)
  createLineCheck({
    id: 'SC010',
    name: 'System Persistence Mechanism',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:writeFile|writeFileSync|open\s*\().*(?:\/etc\/systemd|\/etc\/cron|\.service\b.*ExecStart|crontab\s+-)/g,
    appliesTo: ['js', 'ts', 'py', 'rb', 'sh'],
    message: 'Dependency writes to systemd or crontab. This is a persistence mechanism used in supply chain attacks.',
    fix: 'Remove this dependency immediately. No legitimate package should install system services.',
  }),

  // SC011 - .pth File with Code Execution (Python-specific, from LiteLLM attack)
  createLineCheck({
    id: 'SC011',
    name: '.pth File with Code Execution',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:import\s+|subprocess|exec\s*\(|eval\s*\(|os\.system)/g,
    appliesTo: ['pth'],
    message: 'A .pth file contains executable code. This is the exact technique used in the LiteLLM supply chain attack (March 2026).',
    fix: 'Remove this .pth file immediately. Legitimate .pth files contain only directory paths, not code.',
  }),

  // SC012 - Steganographic/Hidden File Extensions
  createLineCheck({
    id: 'SC012',
    name: 'Suspicious File with Hidden Extension',
    category: 'supply-chain',
    severity: 'high',
    pattern: /(?:\.jpg\.js|\.png\.py|\.gif\.sh|\.pdf\.js|\.ico\.py)/g,
    appliesTo: ['js', 'ts', 'py', 'sh'],
    validate(_match, _line, file) {
      // Check the actual filename for double extensions
      return /\.\w+\.\w+$/.test(file.basename) && /\.(js|py|sh|rb|ts)$/.test(file.basename);
    },
    message: 'File has a suspicious double extension (e.g., image.jpg.js). This hides executable code behind an innocent-looking name.',
    fix: 'Inspect this file. Double extensions are a social engineering technique in supply chain attacks.',
  }),
];
