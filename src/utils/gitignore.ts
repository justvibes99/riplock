import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function loadGitignore(projectRoot: string): Promise<string | null> {
  try {
    return await readFile(join(projectRoot, '.gitignore'), 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Compile gitignore content into a matcher function.
 * Handles negation (!), directory patterns (/), wildcards (* and **),
 * and .env* style patterns properly.
 */
export function compileGitignore(content: string | null): (relativePath: string) => boolean {
  if (!content) return () => false;

  const rules: { pattern: RegExp; negated: boolean }[] = [];

  const lines = content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  for (const line of lines) {
    let negated = false;
    let pattern = line;

    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
    }

    const regex = gitignorePatternToRegex(pattern);
    if (regex) {
      rules.push({ pattern: regex, negated });
    }
  }

  return (relativePath: string): boolean => {
    let ignored = false;
    for (const rule of rules) {
      if (rule.pattern.test(relativePath)) {
        ignored = !rule.negated;
      }
    }
    return ignored;
  };
}

/**
 * Simple backward-compatible wrapper for existing code.
 */
export function isPathGitignored(
  relativePath: string,
  gitignoreContent: string | null,
): boolean {
  return compileGitignore(gitignoreContent)(relativePath);
}

function gitignorePatternToRegex(pattern: string): RegExp | null {
  let p = pattern;

  // Remove trailing spaces
  p = p.trimEnd();
  if (!p) return null;

  // Remove trailing slash (means "directory only" but we treat files too)
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);

  // Determine if pattern is anchored (contains / other than trailing)
  const anchored = p.includes('/');

  // Strip leading / (it means "anchored to root", not a literal /)
  if (p.startsWith('/')) p = p.slice(1);

  // Convert gitignore glob to regex
  let regex = '';
  let i = 0;
  while (i < p.length) {
    const ch = p[i];
    if (ch === '*') {
      if (p[i + 1] === '*') {
        if (p[i + 2] === '/') {
          // **/ matches zero or more directories
          regex += '(?:.*/)?';
          i += 3;
          continue;
        }
        // ** at end matches everything
        regex += '.*';
        i += 2;
        continue;
      }
      // * matches anything except /
      regex += '[^/]*';
      i++;
    } else if (ch === '?') {
      regex += '[^/]';
      i++;
    } else if (ch === '[') {
      // Character class — pass through
      const close = p.indexOf(']', i + 1);
      if (close === -1) {
        regex += '\\[';
        i++;
      } else {
        regex += p.slice(i, close + 1);
        i = close + 1;
      }
    } else if ('.+^${}()|\\'.includes(ch)) {
      regex += '\\' + ch;
      i++;
    } else {
      regex += ch;
      i++;
    }
  }

  if (anchored) {
    // Pattern with / is matched from root
    return new RegExp('^' + regex + '(?:$|/)');
  }

  // Unanchored pattern matches any path component
  // e.g., ".env*" should match ".env", ".env.local", "subdir/.env.local"
  return new RegExp('(?:^|/)' + regex + '(?:$|/)');
}
