import pc from 'picocolors';
import type { Finding, ScanResult, Severity } from '../checks/types.js';

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: pc.bgRed(pc.white(pc.bold(' CRITICAL '))),
  high: pc.bgYellow(pc.black(pc.bold(' HIGH '))),
  medium: pc.bgCyan(pc.black(pc.bold(' MEDIUM '))),
  low: pc.bgWhite(pc.black(pc.bold(' LOW '))),
};

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: pc.red,
  high: pc.yellow,
  medium: pc.cyan,
  low: pc.white,
};

const BAR_CHAR = '\u2588';

// Max individual findings to show before grouping
const GROUP_THRESHOLD = 3;

export function renderTerminal(result: ScanResult, version = '2.0.0'): string {
  const lines: string[] = [];

  lines.push('');
  if (result.scanDeps) {
    lines.push(pc.bold(`  riplock v${version}`) + pc.dim(` \u2014 scanning dependencies in ${result.projectRoot}`));
  } else {
    lines.push(pc.bold(`  riplock v${version}`) + pc.dim(` \u2014 scanning ${result.projectRoot}`));
  }
  lines.push('');
  lines.push(pc.dim(`  Scanned ${result.filesScanned} files with ${result.checksRun} checks in ${(result.totalDurationMs / 1000).toFixed(1)}s`));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(pc.green(pc.bold('  \u2713 No security issues found! Grade: A+')));
    lines.push('');
    lines.push(pc.dim('  Your project looks clean. Keep it up!'));
    lines.push('');
    return lines.join('\n');
  }

  // Group findings by checkId
  const groups = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const list = groups.get(f.checkId) ?? [];
    list.push(f);
    groups.set(f.checkId, list);
  }

  // Sort groups: critical first, then by count descending within severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedGroups = [...groups.entries()].sort((a, b) => {
    const sevA = severityOrder[a[1][0].severity] ?? 4;
    const sevB = severityOrder[b[1][0].severity] ?? 4;
    if (sevA !== sevB) return sevA - sevB;
    return b[1].length - a[1].length;
  });

  for (const [_checkId, findings] of sortedGroups) {
    if (findings.length <= GROUP_THRESHOLD) {
      // Show each finding individually
      for (const f of findings) {
        lines.push(renderFinding(f));
      }
    } else {
      // Show grouped summary + top examples
      lines.push(renderGroupedFinding(findings));
    }
  }

  // Summary
  lines.push(renderSummary(result, groups));

  return lines.join('\n');
}

function renderFinding(f: Finding): string {
  const lines: string[] = [];

  lines.push(`  ${SEVERITY_BADGE[f.severity]}  ${pc.bold(f.title)}  ${pc.dim(f.checkId)}`);
  lines.push(pc.dim('  ' + '\u2500'.repeat(55)));

  if (f.location) {
    lines.push(`  ${pc.dim(f.location.filePath + ':' + f.location.startLine)}`);
  }

  // Code snippet
  if (f.contextBefore?.length || f.snippet || f.contextAfter?.length) {
    const startLine = f.location?.startLine ?? 0;
    const contextBefore = f.contextBefore ?? [];
    const contextAfter = f.contextAfter ?? [];

    for (let i = 0; i < contextBefore.length; i++) {
      const ln = startLine - contextBefore.length + i;
      lines.push(pc.dim(`  \u2502 ${padNum(ln)} \u2502 ${contextBefore[i]}`));
    }

    if (f.snippet) {
      lines.push(
        SEVERITY_COLOR[f.severity](`  \u2502 ${padNum(startLine)} \u2502 ${f.snippet}`) +
        pc.dim('      \u2190 HERE'),
      );
    }

    for (let i = 0; i < contextAfter.length; i++) {
      const ln = startLine + 1 + i;
      lines.push(pc.dim(`  \u2502 ${padNum(ln)} \u2502 ${contextAfter[i]}`));
    }

    lines.push(pc.dim('  \u2502'));
  }

  // Taint flow (AST-tracked findings)
  if (f.taintFlow && f.taintFlow.length > 0) {
    lines.push(pc.dim('  \u2502 ') + pc.magenta(pc.bold('Data flow:')));
    for (let i = 0; i < f.taintFlow.length; i++) {
      const prefix = i === 0 ? '\u2514' : i === f.taintFlow.length - 1 ? '\u2514' : '\u251c';
      lines.push(pc.dim('  \u2502  ') + pc.magenta(`${prefix} ${f.taintFlow[i]}`));
    }
    lines.push(pc.dim('  \u2502'));
  }

  // Message
  lines.push(pc.dim('  \u2502 ') + f.message);
  lines.push(pc.dim('  \u2502'));

  // Fix
  lines.push(pc.dim('  \u2502 ') + pc.green(pc.bold('Fix:')));
  for (const fixLine of f.fix.split('\n')) {
    lines.push(pc.dim('  \u2502  ') + pc.green(fixLine));
  }

  if (f.fixCode) {
    lines.push(pc.dim('  \u2502'));
    for (const codeLine of f.fixCode.split('\n')) {
      lines.push(pc.dim('  \u2502  ') + pc.dim(codeLine));
    }
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Render a group of 4+ findings from the same check as a summary
 * with the top 3 most important examples shown in detail.
 */
function renderGroupedFinding(findings: Finding[]): string {
  const lines: string[] = [];
  const f = findings[0];
  const count = findings.length;

  // Collect unique files
  const files = new Set<string>();
  for (const ff of findings) {
    if (ff.location) files.add(ff.location.filePath);
  }

  lines.push(`  ${SEVERITY_BADGE[f.severity]}  ${pc.bold(f.title)}  ${pc.dim(f.checkId)}`);
  lines.push(pc.dim('  ' + '\u2500'.repeat(55)));
  lines.push(`  ${SEVERITY_COLOR[f.severity](pc.bold(`${count} occurrences`))} across ${files.size} file${files.size !== 1 ? 's' : ''}`);
  lines.push(pc.dim('  \u2502'));

  // Show top 3 examples (file paths only for brevity)
  const examples = findings.slice(0, 3);
  for (const ex of examples) {
    if (ex.location) {
      const snippet = ex.snippet ? `: ${ex.snippet.trim().slice(0, 50)}` : '';
      lines.push(pc.dim('  \u2502 ') + `${ex.location.filePath}:${ex.location.startLine}` + pc.dim(snippet));
    }
  }
  if (count > 3) {
    lines.push(pc.dim(`  \u2502 ... and ${count - 3} more`));
  }

  lines.push(pc.dim('  \u2502'));

  // Message (once, not per-finding)
  lines.push(pc.dim('  \u2502 ') + f.message);
  lines.push(pc.dim('  \u2502'));

  // Fix (once)
  lines.push(pc.dim('  \u2502 ') + pc.green(pc.bold('Fix:')));
  for (const fixLine of f.fix.split('\n')) {
    lines.push(pc.dim('  \u2502  ') + pc.green(fixLine));
  }

  // Suppress action
  lines.push(pc.dim('  \u2502'));
  lines.push(pc.dim(`  \u2502 To suppress: add "${f.checkId}" to .riplock.json "disable" list`));

  lines.push('');
  return lines.join('\n');
}

function renderSummary(result: ScanResult, groups: Map<string, Finding[]>): string {
  const { stats } = result;
  const lines: string[] = [];

  const grade = computeGrade(result);
  const uniqueChecks = groups.size;

  lines.push(pc.dim('  ' + '\u2500'.repeat(20) + ' Security Report ' + '\u2500'.repeat(20)));
  lines.push(`  Grade: ${pc.bold(grade.letter)} (${grade.score}/100)`);
  lines.push(`  ${stats.total} findings from ${uniqueChecks} unique checks`);
  lines.push('');

  if (stats.critical > 0) {
    lines.push(`  ${pc.red(`${stats.critical} critical`)}  ${pc.red(BAR_CHAR.repeat(Math.min(stats.critical * 4, 40)))}`);
  }
  if (stats.high > 0) {
    lines.push(`  ${pc.yellow(`${stats.high} high`)}      ${pc.yellow(BAR_CHAR.repeat(Math.min(stats.high * 4, 40)))}`);
  }
  if (stats.medium > 0) {
    lines.push(`  ${pc.cyan(`${stats.medium} medium`)}    ${pc.cyan(BAR_CHAR.repeat(Math.min(stats.medium * 4, 40)))}`);
  }
  if (stats.low > 0) {
    lines.push(`  ${pc.white(`${stats.low} low`)}       ${pc.white(BAR_CHAR.repeat(Math.min(stats.low * 4, 40)))}`);
  }

  lines.push('');

  // Show top priorities
  const priorities = [...groups.entries()]
    .filter(([, fs]) => fs[0].severity === 'critical' || fs[0].severity === 'high')
    .sort((a, b) => {
      const sevA = a[1][0].severity === 'critical' ? 0 : 1;
      const sevB = b[1][0].severity === 'critical' ? 0 : 1;
      if (sevA !== sevB) return sevA - sevB;
      return b[1].length - a[1].length;
    })
    .slice(0, 5);

  if (priorities.length > 0) {
    lines.push(pc.bold('  Top priorities:'));
    for (const [checkId, fs] of priorities) {
      const sev = SEVERITY_COLOR[fs[0].severity];
      lines.push(`  ${sev(`\u2022 ${checkId}`)} ${fs[0].title} (${fs.length}x)`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

function computeGrade(result: ScanResult): { letter: string; score: number } {
  const { stats } = result;
  let score = 100;

  score -= stats.critical * 25;
  score -= stats.high * 15;
  score -= stats.medium * 5;
  score -= stats.low * 2;

  score = Math.max(0, score);

  // Hard constraints
  if (stats.critical >= 3) score = Math.min(score, 0);
  if (stats.critical > 0) score = Math.min(score, 60);

  let letter: string;
  if (score === 100) letter = 'A+';
  else if (score >= 90) letter = 'A';
  else if (score >= 75) letter = 'B';
  else if (score >= 60) letter = 'C';
  else if (score >= 40) letter = 'D';
  else letter = 'F';

  return { letter, score };
}

function padNum(n: number): string {
  return String(n).padStart(4, ' ');
}
