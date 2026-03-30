/**
 * Shared infrastructure for all check implementations.
 * Every check category imports from here instead of duplicating helpers.
 */
import type {
  CheckCategory,
  FileEntry,
  Finding,
  LineCheck,
  LineMatch,
  ScanContext,
  Severity,
} from './types.js';
import { extractSnippet } from '../utils/snippet.js';

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

const COMMENT_RE = /^\s*(?:\/\/|#|\*|\/\*|<!--|%|;)/;

export function isCommentLine(line: string): boolean {
  return COMMENT_RE.test(line);
}

// ---------------------------------------------------------------------------
// User input detection (used for severity escalation)
// ---------------------------------------------------------------------------

const USER_INPUT_RE = /(?:req\.|params\.|query\.|body\.|input\.|args\.|user\.)/;

export function hasUserInput(line: string): boolean {
  return USER_INPUT_RE.test(line);
}

// ---------------------------------------------------------------------------
// Line check factory
// ---------------------------------------------------------------------------

export interface LineCheckOpts {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  pattern: RegExp;
  appliesTo?: string[];
  description?: string;
  message: string;
  fix: string;
  fixCode?: string;
  /** Return false to suppress the finding (false-positive reduction). */
  validate?: (match: RegExpExecArray, line: string, file: FileEntry) => boolean;
  /** Override severity based on the matched line. Return null to use default. */
  severityOverride?: (line: string) => Severity | null;
}

/**
 * Factory that creates a LineCheck from a simple options object.
 * Handles comment skipping, optional validation, snippet extraction,
 * severity overrides, and Finding construction automatically.
 */
export function createLineCheck(opts: LineCheckOpts): LineCheck {
  return {
    level: 'line',
    id: opts.id,
    name: opts.name,
    description: opts.description ?? opts.message,
    category: opts.category,
    defaultSeverity: opts.severity,
    appliesTo: opts.appliesTo,
    pattern: opts.pattern,
    analyze(match: LineMatch, ctx: ScanContext): Finding | null {
      if (isCommentLine(match.line)) return null;

      if (opts.validate && !opts.validate(match.regexMatch, match.line, match.file)) {
        return null;
      }

      const lines = match.file.lines ?? [];
      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        match.lineNumber,
        ctx.config.contextLines,
      );

      // Determine severity: config override > per-match override > default
      let severity = ctx.config.severityOverrides.get(opts.id) ?? opts.severity;
      if (!ctx.config.severityOverrides.has(opts.id) && opts.severityOverride) {
        const override = opts.severityOverride(match.line);
        if (override) severity = override;
      }

      return {
        checkId: opts.id,
        title: opts.name,
        message: opts.message,
        severity,
        category: opts.category,
        location: {
          filePath: match.file.relativePath,
          startLine: match.lineNumber,
          startColumn: match.regexMatch.index,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: opts.fix,
        fixCode: opts.fixCode,
      };
    },
  };
}
