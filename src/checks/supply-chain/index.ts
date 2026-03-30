/**
 * Supply chain attack detection checks.
 *
 * These patterns are suspicious INSIDE a dependency package but may be normal
 * in application code. They are only run during `--scan-deps` mode against
 * files inside node_modules/, site-packages/, vendor/, etc.
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

export const supplyChainChecks: CheckDefinition[] = [
  // SC001 - Bulk Environment Variable Access
  createLineCheck({
    id: 'SC001',
    name: 'Bulk Environment Variable Access',
    category: 'supply-chain',
    severity: 'high',
    pattern: /Object\.(?:keys|values|entries)\s*\(\s*process\.env\)|os\.environ\.(?:items|keys|values)\(\)|ENV\.(?:to_h|each)/g,
    appliesTo: ['js', 'ts', 'py', 'rb'],
    message:
      'Dependency reads all environment variables. This is a common credential harvesting pattern in supply chain attacks.',
    fix: 'Investigate why this dependency needs access to all environment variables.\nIf you trust this package, add "SC001" to your .riplock.json "disable" list.',
  }),

  // SC002 - HTTP Exfiltration of Secrets
  createLineCheck({
    id: 'SC002',
    name: 'HTTP Exfiltration of Secrets',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:fetch|axios|got|requests?\.post|urllib|http\.request|Net::HTTP)\s*\(.*(?:env|secret|token|key|password|credential)/gi,
    appliesTo: ['js', 'ts', 'py', 'rb'],
    message:
      'Dependency sends environment variables or secrets over HTTP. This is a credential exfiltration pattern.',
    fix: 'This is a strong indicator of a supply chain attack. Remove this dependency immediately and audit your environment for exposed secrets.',
  }),

  // SC003 - eval/exec of Fetched Content
  createLineCheck({
    id: 'SC003',
    name: 'Remote Code Execution via Fetch',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:eval|exec|Function)\s*\(\s*(?:await\s+)?(?:fetch|axios|got|requests?\.get|urllib)/g,
    appliesTo: ['js', 'ts', 'py'],
    message:
      'Dependency downloads and executes code at runtime. This is a remote code execution backdoor pattern.',
    fix: 'Remove this dependency immediately. No legitimate package should download and eval arbitrary code at runtime.',
  }),

  // SC004 - Base64 Decoded Execution
  createLineCheck({
    id: 'SC004',
    name: 'Base64 Decoded Execution',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:eval|exec|Function|subprocess)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)/g,
    appliesTo: ['js', 'ts', 'py'],
    message:
      'Dependency decodes and executes base64 content. This is an obfuscation technique used in supply chain attacks.',
    fix: 'Remove this dependency immediately. Decoding and executing base64 content is a strong indicator of malicious code.',
  }),

  // SC005 - Obfuscated Code (long hex/unicode sequences)
  createLineCheck({
    id: 'SC005',
    name: 'Obfuscated Code',
    category: 'supply-chain',
    severity: 'high',
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}|\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}/g,
    appliesTo: ['js', 'ts', 'py'],
    message:
      'Dependency contains heavily obfuscated hex/unicode sequences. Legitimate packages use readable code.',
    fix: 'Inspect the obfuscated content carefully. Consider replacing this dependency with a transparent alternative.',
  }),

  // SC006 - Reverse Shell Pattern
  createLineCheck({
    id: 'SC006',
    name: 'Reverse Shell Pattern',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:\/bin\/(?:sh|bash|zsh)|cmd\.exe).*(?:socket|net\.connect|TCPSocket|subprocess)|new\s+(?:net\.Socket|WebSocket)\s*\(\s*[^)]*(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|['"]\w+\.\w+)/g,
    appliesTo: ['js', 'ts', 'py', 'rb'],
    message:
      'Dependency opens a network socket to an external host with shell access. This is a reverse shell pattern.',
    fix: 'Remove this dependency immediately. Reverse shells are a critical indicator of a backdoor.',
  }),

  // SC007 - Cryptocurrency Mining
  createLineCheck({
    id: 'SC007',
    name: 'Cryptocurrency Mining',
    category: 'supply-chain',
    severity: 'high',
    pattern: /(?:coinhive|cryptonight|monero|stratum\+tcp|xmrig|minergate)/gi,
    appliesTo: ['js', 'ts', 'py'],
    message:
      'Dependency contains cryptocurrency mining references.',
    fix: 'Remove this dependency. Cryptomining code in a dependency is unauthorized resource usage.',
  }),

  // SC008 - Postinstall Network Fetch (FileCheck for package.json)
  {
    level: 'file',
    id: 'SC008',
    name: 'Install Script Network Fetch',
    description:
      'Detects package.json install scripts that download external content.',
    category: 'supply-chain',
    defaultSeverity: 'critical',
    appliesTo: ['json'],
    fastFilter: 'install',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Only check package.json files
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
      const dangerousScriptRe = /(?:curl|wget|node\s+-e|python\s+-c|https?:\/\/)/;
      const hookNames = ['preinstall', 'install', 'postinstall'];

      const lines = file.lines ?? await ctx.readLines(file.absolutePath);

      for (const hook of hookNames) {
        const scriptValue = scripts[hook];
        if (!scriptValue || !dangerousScriptRe.test(scriptValue)) continue;

        // Find the line number of this script in the file
        let lineNum = 1;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(`"${hook}"`) || lines[i].includes(`'${hook}'`)) {
            lineNum = i + 1;
            break;
          }
        }

        const { snippet, contextBefore, contextAfter } = extractSnippet(
          lines,
          lineNum,
          ctx.config.contextLines,
        );

        findings.push({
          checkId: 'SC008',
          title: 'Install Script Network Fetch',
          message: `Package "${hook}" script downloads external content: "${scriptValue}". This is a common supply chain attack vector.`,
          severity: 'critical',
          category: 'supply-chain',
          location: {
            filePath: file.relativePath,
            startLine: lineNum,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Investigate the install script. If the package is not trusted, remove it immediately.\nLegitimate packages rarely need to download content during installation.',
        });
      }

      return findings;
    },
  } satisfies FileCheck,

  // SC009 - DNS Exfiltration
  createLineCheck({
    id: 'SC009',
    name: 'DNS Exfiltration',
    category: 'supply-chain',
    severity: 'high',
    pattern: /(?:dns\.resolve|dns\.lookup|resolv|getaddrinfo)\s*\(.*(?:env|secret|token|key)/gi,
    appliesTo: ['js', 'ts', 'py'],
    message:
      'Dependency performs DNS lookups using secret values. This is a DNS exfiltration technique.',
    fix: 'Remove this dependency. DNS exfiltration encodes stolen data in DNS queries to bypass network firewalls.',
  }),

  // SC010 - Systemd/Cron Persistence
  createLineCheck({
    id: 'SC010',
    name: 'System Persistence Mechanism',
    category: 'supply-chain',
    severity: 'critical',
    pattern: /(?:\/etc\/systemd|\/etc\/cron|crontab|\.service|ExecStart|WantedBy)/g,
    appliesTo: ['js', 'ts', 'py', 'rb', 'sh'],
    message:
      'Dependency installs system services or cron jobs. This is a persistence mechanism used in supply chain attacks.',
    fix: 'Remove this dependency. Legitimate npm/pip packages should never install system services or cron jobs.',
  }),
];
