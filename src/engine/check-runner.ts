import type {
  AstCheck,
  AstCheckContext,
  CheckDefinition,
  DependencyCheck,
  FileCheck,
  FileEntry,
  Finding,
  LineCheck,
  LineMatch,
  ProjectCheck,
  ScanContext,
} from '../checks/types.js';
import { loadFileContent, loadFileLines } from './file-discovery.js';

export async function runChecks(
  checks: CheckDefinition[],
  ctx: ScanContext,
): Promise<Finding[]> {
  const lineChecks: LineCheck[] = [];
  const fileChecks: FileCheck[] = [];
  const projectChecks: ProjectCheck[] = [];
  const depChecks: DependencyCheck[] = [];
  const astChecks: AstCheck[] = [];

  for (const check of checks) {
    const severity = ctx.config.severityOverrides.get(check.id) ?? check.defaultSeverity;
    if (ctx.config.disabledChecks.has(check.id)) continue;
    if (severityRank(severity) < severityRank(ctx.config.minSeverity)) continue;

    switch (check.level) {
      case 'line': lineChecks.push(check); break;
      case 'file': fileChecks.push(check); break;
      case 'project': projectChecks.push(check); break;
      case 'dependency': depChecks.push(check); break;
      case 'ast': astChecks.push(check); break;
    }
  }

  const findings: Finding[] = [];
  const errors: string[] = [];

  // Run line + file checks in parallel across files
  const fileEntries = [...ctx.files.values()];
  const fileResults = await Promise.allSettled(
    fileEntries.map((file) => runChecksOnFile(file, lineChecks, fileChecks, ctx)),
  );
  for (const result of fileResults) {
    if (result.status === 'fulfilled') {
      findings.push(...result.value);
    } else {
      errors.push(`File check error: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
    }
  }

  // Run project-level checks
  const projectResults = await Promise.allSettled(
    projectChecks.map((check) => check.analyze(ctx)),
  );
  for (let i = 0; i < projectResults.length; i++) {
    const result = projectResults[i];
    if (result.status === 'fulfilled') {
      findings.push(...result.value);
    } else {
      errors.push(`Check ${projectChecks[i].id} error: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
    }
  }

  // Run dependency checks
  if (!ctx.config.skipDeps && ctx.packageJson) {
    const depResults = await Promise.allSettled(
      depChecks.map((check) => check.analyze(ctx.packageJson!, ctx.lockFile, ctx)),
    );
    for (let i = 0; i < depResults.length; i++) {
      const result = depResults[i];
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      } else {
        errors.push(`Check ${depChecks[i].id} error: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
      }
    }
  }

  // Run AST checks (taint-tracked)
  if (astChecks.length > 0) {
    const astResults = await runAstChecks(fileEntries, astChecks, ctx);
    findings.push(...astResults);
  }

  // Report errors to stderr if verbose
  if (ctx.config.verbose && errors.length > 0) {
    for (const err of errors) {
      process.stderr.write(`[riplock] ${err}\n`);
    }
  }

  return findings;
}

async function runChecksOnFile(
  file: FileEntry,
  lineChecks: LineCheck[],
  fileChecks: FileCheck[],
  ctx: ScanContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Filter checks by file extension
  const applicableLineChecks = lineChecks.filter(
    (c) => !c.appliesTo || c.appliesTo.includes(file.extension),
  );
  const applicableFileChecks = fileChecks.filter(
    (c) => !c.appliesTo || c.appliesTo.includes(file.extension),
  );

  if (applicableLineChecks.length === 0 && applicableFileChecks.length === 0) {
    return findings;
  }

  // Load content lazily
  const content = await loadFileContent(file);
  const lines = await loadFileLines(file);

  // Run line checks
  if (applicableLineChecks.length > 0) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const check of applicableLineChecks) {
        check.pattern.lastIndex = 0;
        const match = check.pattern.exec(line);
        if (!match) continue;

        const lineMatch: LineMatch = {
          line,
          lineNumber: i + 1,
          regexMatch: match,
          file,
        };

        const finding = check.analyze(lineMatch, ctx);
        if (finding) findings.push(finding);
      }
    }
  }

  // Run file checks
  for (const check of applicableFileChecks) {
    if (check.fastFilter) {
      if (typeof check.fastFilter === 'string') {
        if (!content.includes(check.fastFilter)) continue;
      } else {
        check.fastFilter.lastIndex = 0;
        if (!check.fastFilter.test(content)) continue;
      }
    }
    const fileFindings = await check.analyze(file, ctx);
    findings.push(...fileFindings);
  }

  return findings;
}

async function runAstChecks(
  files: FileEntry[],
  checks: AstCheck[],
  ctx: ScanContext,
): Promise<Finding[]> {
  // Lazy import to avoid loading tree-sitter when no AST checks are enabled
  const { parseFile, isAstParseable } = await import('./ast-parser.js');
  const { findTaintPaths: findTaint } = await import('./taint-tracker.js');

  const findings: Finding[] = [];
  const parseableFiles = files.filter(f => isAstParseable(f.extension));

  const results = await Promise.allSettled(
    parseableFiles.map(async (file) => {
      const parsed = await parseFile(file);
      if (!parsed) return [];

      const applicable = checks.filter(c => c.languages.includes(parsed.language));
      if (applicable.length === 0) return [];

      const astCtx: AstCheckContext = {
        rootNode: parsed.rootNode,
        file,
        language: parsed.language,
        ctx,
        findTaintPaths(opts) {
          return findTaint(parsed.rootNode, parsed.language, opts);
        },
      };

      const fileFindings: Finding[] = [];
      for (const check of applicable) {
        try {
          fileFindings.push(...check.analyze(astCtx));
        } catch (err) {
          if (ctx.config.verbose) {
            process.stderr.write(`[riplock] AST check ${check.id} failed on ${file.relativePath}: ${err instanceof Error ? err.message : err}\n`);
          }
        }
      }
      return fileFindings;
    }),
  );

  for (const r of results) {
    if (r.status === 'fulfilled') findings.push(...r.value);
  }

  // Cross-file taint analysis: look for tainted data flowing across import boundaries
  try {
    const { findCrossFileTaintPaths } = await import('./cross-file-taint.js');

    // Collect all sink categories from AST checks
    const allSinkCategories = new Set<import('../checks/types.js').SinkCategory>();
    for (const check of checks) {
      // Infer sink categories from check IDs
      if (check.id.includes('INJ001')) allSinkCategories.add('sql-query');
      if (check.id.includes('INJ002')) allSinkCategories.add('shell-exec');
      if (check.id.includes('INJ003')) allSinkCategories.add('ssrf');
      if (check.id.includes('INJ004')) allSinkCategories.add('xss');
      if (check.id.includes('INJ005')) allSinkCategories.add('path-traversal');
    }
    // If no specific categories matched, use all
    if (allSinkCategories.size === 0) {
      for (const cat of ['sql-query', 'shell-exec', 'ssrf', 'xss', 'path-traversal', 'redirect', 'eval'] as const) {
        allSinkCategories.add(cat);
      }
    }

    const crossFileTaintDepth = 3; // N-level transitive taint propagation (default 3)
    const crossFileResults = await findCrossFileTaintPaths(ctx.files, allSinkCategories, parseFile, crossFileTaintDepth);

    // Convert cross-file TaintPaths to Findings
    for (const path of crossFileResults.paths) {
      const sinkCatToCheckId: Record<string, { checkId: string; title: string; severity: 'critical' | 'high' }> = {
        'sql-query': { checkId: 'AST-INJ001', title: 'SQL Injection (Cross-File Taint)', severity: 'critical' },
        'shell-exec': { checkId: 'AST-INJ002', title: 'Command Injection (Cross-File Taint)', severity: 'critical' },
        'ssrf': { checkId: 'AST-INJ003', title: 'SSRF (Cross-File Taint)', severity: 'critical' },
        'xss': { checkId: 'AST-INJ004', title: 'XSS (Cross-File Taint)', severity: 'high' },
        'path-traversal': { checkId: 'AST-INJ005', title: 'Path Traversal (Cross-File Taint)', severity: 'high' },
        'redirect': { checkId: 'AST-INJ006', title: 'Open Redirect (Cross-File Taint)', severity: 'high' },
        'eval': { checkId: 'AST-INJ007', title: 'Code Injection (Cross-File Taint)', severity: 'critical' },
      };

      const info = sinkCatToCheckId[path.sinkCategory] ?? {
        checkId: 'AST-XFILE',
        title: `Cross-File Taint (${path.sinkCategory})`,
        severity: 'high' as const,
      };

      findings.push({
        checkId: info.checkId,
        title: info.title,
        message: `User input flows across file boundaries into a ${path.sinkCategory} sink. ${path.intermediates.map(n => n.expression).find(e => e.startsWith('cross-file:')) ?? ''}`.trim(),
        severity: info.severity,
        category: 'injection',
        location: {
          // Extract file path from cross-file intermediate (format: "cross-file: fn() in path/to/file.ts")
          filePath: (() => {
            const crossFileNode = path.intermediates.find(n => n.expression.startsWith('cross-file:'));
            if (crossFileNode) {
              const match = crossFileNode.expression.match(/in\s+(\S+)/);
              if (match) return match[1];
            }
            return 'unknown';
          })(),
          startLine: path.sink.line,
          startColumn: path.sink.column,
        },
        fix: 'Validate and sanitize user input before passing it across module boundaries to dangerous sinks.',
        taintFlow: [
          `${path.source.expression} (line ${path.source.line})`,
          ...path.intermediates.map(n => `${n.expression} (line ${n.line})`),
          `${path.sink.expression} (line ${path.sink.line})`,
        ],
        confidence: 'high',
      });
    }
  } catch (err) {
    if (ctx.config.verbose) {
      process.stderr.write(`[riplock] Cross-file taint analysis failed: ${err instanceof Error ? err.message : err}\n`);
    }
  }

  return findings;
}

function severityRank(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}
