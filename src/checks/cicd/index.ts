import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isGitHubWorkflow(file: FileEntry): boolean {
  return file.relativePath.includes('.github/workflows/');
}

// ---------------------------------------------------------------------------
// CICD001 - GitHub Actions Script Injection
// ---------------------------------------------------------------------------

const CICD001: CheckDefinition = createLineCheck({
  id: 'CICD001',
  name: 'GitHub Actions Script Injection',
  category: 'cicd',
  severity: 'critical',
  appliesTo: ['yml', 'yaml'],
  pattern:
    /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref)/g,
  message:
    'GitHub Actions expression uses untrusted input from a PR/issue. An attacker can inject commands via a crafted title or body.',
  fix: 'Use an intermediate environment variable instead of inline expressions.',
  fixCode: `# Dangerous:
run: echo "$\{{ github.event.issue.title }}"

# Safe:
env:
  TITLE: $\{{ github.event.issue.title }}
run: echo "$TITLE"`,
  validate(_match, _line, file) {
    return isGitHubWorkflow(file);
  },
});

// ---------------------------------------------------------------------------
// CICD002 - Unpinned GitHub Actions
// ---------------------------------------------------------------------------

const CICD002: CheckDefinition = createLineCheck({
  id: 'CICD002',
  name: 'Unpinned GitHub Actions',
  category: 'cicd',
  severity: 'medium',
  appliesTo: ['yml', 'yaml'],
  pattern: /uses:\s*[\w-]+\/[\w-]+@(?:main|master|v\d+)\s*$/gm,
  message:
    'GitHub Actions pinned to a branch or major version tag. A compromised action can inject malicious code. Pin to a full commit SHA.',
  fix: 'Pin the action to a full commit SHA and add a version comment.',
  fixCode: `# Dangerous:
uses: actions/checkout@v4
uses: actions/checkout@main

# Safe:
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1`,
  validate(_match, _line, file) {
    return isGitHubWorkflow(file);
  },
});

// ---------------------------------------------------------------------------
// CICD003 - pull_request_target with Checkout
// ---------------------------------------------------------------------------

const CICD003: FileCheck = {
  level: 'file',
  id: 'CICD003',
  name: 'pull_request_target with Checkout',
  description:
    'Detects workflows that use pull_request_target and check out PR code, giving untrusted code access to secrets.',
  category: 'cicd',
  defaultSeverity: 'critical',
  appliesTo: ['yml', 'yaml'],
  fastFilter: 'pull_request_target',

  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    if (!isGitHubWorkflow(file)) return [];

    const lines = file.lines ?? (await ctx.readLines(file.absolutePath));
    const content = lines.join('\n');

    // Must have pull_request_target trigger
    if (!content.includes('pull_request_target')) return [];

    // Must check out PR head code
    const checkoutPrHead =
      /actions\/checkout[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/;
    if (!checkoutPrHead.test(content)) return [];

    // Find the line number of the checkout ref for better location reporting
    let refLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (/ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/.test(lines[i])) {
        refLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      refLine,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'CICD003',
        title: 'pull_request_target with PR Checkout',
        message:
          'Workflow uses pull_request_target and checks out PR code. This gives the PR code access to secrets, allowing any forker to steal them.',
        severity: ctx.config.severityOverrides.get('CICD003') ?? 'critical',
        category: 'cicd',
        location: {
          filePath: file.relativePath,
          startLine: refLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: 'Do not check out PR code in pull_request_target workflows. If you must, run it in an isolated job without secrets.',
      },
    ];
  },
} satisfies FileCheck;

// ---------------------------------------------------------------------------
// CICD004 - Overly Permissive Workflow Permissions
// ---------------------------------------------------------------------------

const CICD004: CheckDefinition = createLineCheck({
  id: 'CICD004',
  name: 'Overly Permissive Workflow Permissions',
  category: 'cicd',
  severity: 'medium',
  appliesTo: ['yml', 'yaml'],
  pattern: /permissions:\s*write-all|permissions:\s*\n\s+contents:\s*write/gm,
  message:
    'Workflow has broad write permissions. Follow the principle of least privilege.',
  fix: 'Restrict permissions to only what the workflow needs.',
  fixCode: `# Dangerous:
permissions: write-all

# Safe - only what you need:
permissions:
  contents: read
  pull-requests: write`,
  validate(_match, _line, file) {
    return isGitHubWorkflow(file);
  },
});

// ---------------------------------------------------------------------------
// CICD005 - Secrets Logged
// ---------------------------------------------------------------------------

const CICD005: CheckDefinition = createLineCheck({
  id: 'CICD005',
  name: 'Secret Echoed to Log',
  category: 'cicd',
  severity: 'high',
  appliesTo: ['yml', 'yaml'],
  pattern: /echo.*\$\{\{\s*secrets\./g,
  message:
    'A secret is echoed to the workflow log. GitHub masks known secrets but this can be bypassed with encoding.',
  fix: 'Never echo secrets. If you need to verify a secret exists, check its length or hash instead.',
  fixCode: `# Dangerous:
run: echo "$\{{ secrets.MY_TOKEN }}"

# Safe - check existence without exposing:
run: |
  if [ -z "$MY_TOKEN" ]; then
    echo "Token is not set"
    exit 1
  fi
  echo "Token is set (length: $\{#MY_TOKEN})"
env:
  MY_TOKEN: $\{{ secrets.MY_TOKEN }}`,
  validate(_match, _line, file) {
    return isGitHubWorkflow(file);
  },
});

// ---------------------------------------------------------------------------
// CICD006 - GitHub Actions Without Permissions Block
// ---------------------------------------------------------------------------

const CICD006: FileCheck = {
  level: 'file',
  id: 'CICD006',
  name: 'GitHub Actions Without Permissions Block',
  description:
    'Detects GitHub Actions workflow files that lack a top-level permissions block, defaulting to broad write access.',
  category: 'cicd',
  defaultSeverity: 'medium',
  appliesTo: ['yml', 'yaml'],
  fastFilter: 'runs-on',

  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    if (!isGitHubWorkflow(file)) return [];

    const lines = file.lines ?? (await ctx.readLines(file.absolutePath));
    const content = lines.join('\n');

    // Must have runs-on (confirms it is a workflow, not just any yaml)
    if (!content.includes('runs-on')) return [];

    // Check for a top-level permissions block.
    // In GitHub Actions, permissions: can appear at root or per-job.
    // We flag only if there is NO permissions: anywhere in the file.
    if (/^\s*permissions\s*:/m.test(content)) return [];

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      1,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'CICD006',
        title: 'Workflow Missing Permissions Block',
        message:
          'Workflow has no permissions block. GitHub Actions defaults to broad write access for all scopes, violating least privilege.',
        severity: ctx.config.severityOverrides.get('CICD006') ?? 'medium',
        category: 'cicd',
        location: {
          filePath: file.relativePath,
          startLine: 1,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: 'Add an explicit `permissions:` block at the workflow level. Start with `contents: read` and add only what the workflow needs.',
        fixCode: `# Add near the top of the workflow:
permissions:
  contents: read

# Or restrict per-job:
jobs:
  build:
    permissions:
      contents: read
    runs-on: ubuntu-latest`,
      },
    ];
  },
} satisfies FileCheck;

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const cicdChecks: CheckDefinition[] = [
  CICD001,
  CICD002,
  CICD003,
  CICD004,
  CICD005,
  CICD006,
];
