import { describe, it, expect } from 'vitest';
import { isAstGrepPattern, matchAstPattern, extractFastFilter } from '../../src/engine/ast-pattern.js';
import type { CompoundRuleOpts } from '../../src/engine/ast-pattern.js';

// ---------------------------------------------------------------------------
// isAstGrepPattern
// ---------------------------------------------------------------------------

describe('isAstGrepPattern', () => {
  it('returns true for code patterns with $METAVAR tokens', () => {
    expect(isAstGrepPattern('$DB.query($SQL)')).toBe(true);
    expect(isAstGrepPattern('eval($CODE)')).toBe(true);
    expect(isAstGrepPattern('$EL.innerHTML = $VALUE')).toBe(true);
  });

  it('returns false for regex patterns with backslash metacharacters', () => {
    expect(isAstGrepPattern('\\s+eval\\(')).toBe(false);
    expect(isAstGrepPattern('new\\s+RegExp')).toBe(false);
    expect(isAstGrepPattern('(?:req\\.|body\\.)')).toBe(false);
  });

  it('returns false for regex patterns with character classes', () => {
    expect(isAstGrepPattern('[^/]*\\.js')).toBe(false);
  });

  it('returns false for patterns without metavariables', () => {
    expect(isAstGrepPattern('eval(foo)')).toBe(false);
    expect(isAstGrepPattern('console.log("hello")')).toBe(false);
  });

  it('respects explicit mode override', () => {
    expect(isAstGrepPattern('eval(foo)', 'ast')).toBe(true);
    expect(isAstGrepPattern('$DB.query($SQL)', 'regex')).toBe(false);
  });

  it('returns true for patterns with explicit ast mode even without metavars', () => {
    expect(isAstGrepPattern('cors()', 'ast')).toBe(true);
    expect(isAstGrepPattern('Math.random()', 'ast')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// matchAstPattern — basic matching
// ---------------------------------------------------------------------------

describe('matchAstPattern', () => {
  it('finds $DB.query($SQL) in JavaScript code', async () => {
    const code = `
const db = require('pg');
const result = db.query('SELECT * FROM users WHERE id = ' + userId);
`;
    const matches = await matchAstPattern(code, 'javascript', '$DB.query($SQL)');
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('db.query');
    expect(matches[0].startLine).toBe(3);
  });

  it('extracts metavariables correctly', async () => {
    const code = `pool.query(userInput);\n`;
    const matches = await matchAstPattern(code, 'javascript', '$DB.query($SQL)');
    expect(matches).toHaveLength(1);
    expect(matches[0].metaVariables.get('DB')).toBe('pool');
    expect(matches[0].metaVariables.get('SQL')).toBe('userInput');
  });

  it('returns empty array for unsupported languages', async () => {
    const code = `db.query(user_input)\n`;
    const matches = await matchAstPattern(code, 'python', '$DB.query($SQL)');
    expect(matches).toHaveLength(0);
  });

  it('returns empty array for go', async () => {
    const matches = await matchAstPattern('db.Query(input)', 'go', '$DB.Query($SQL)');
    expect(matches).toHaveLength(0);
  });

  it('returns empty array for ruby', async () => {
    const matches = await matchAstPattern('db.exec(sql)', 'ruby', '$DB.exec($SQL)');
    expect(matches).toHaveLength(0);
  });

  it('finds eval($CODE) matching eval(userInput)', async () => {
    const code = `const result = eval(userInput);\n`;
    const matches = await matchAstPattern(code, 'javascript', 'eval($CODE)');
    expect(matches).toHaveLength(1);
    expect(matches[0].metaVariables.get('CODE')).toBe('userInput');
  });

  it('does find eval in comment lines (comment filtering is done by caller)', async () => {
    // ast-grep matches structurally — comment lines are not valid JS expressions,
    // so eval inside a comment typically won't parse as a call expression.
    const code = `// eval(x)\neval(y);\n`;
    const matches = await matchAstPattern(code, 'javascript', 'eval($CODE)');
    // The comment line won't parse as a call expression in AST, so only the real call matches
    expect(matches.length).toBeGreaterThanOrEqual(1);
    // The real call should be found
    const realMatch = matches.find(m => m.text === 'eval(y)');
    expect(realMatch).toBeTruthy();
  });

  it('finds multiple matches in one file', async () => {
    const code = `
db.query('SELECT 1');
pool.query('SELECT 2');
conn.query('SELECT 3');
`;
    const matches = await matchAstPattern(code, 'javascript', '$DB.query($SQL)');
    expect(matches).toHaveLength(3);
    expect(matches[0].startLine).toBe(2);
    expect(matches[1].startLine).toBe(3);
    expect(matches[2].startLine).toBe(4);
  });

  it('works with TypeScript code', async () => {
    const code = `const r: QueryResult = db.query(sql);\n`;
    const matches = await matchAstPattern(code, 'typescript', '$DB.query($SQL)');
    expect(matches).toHaveLength(1);
  });

  it('works with TSX code', async () => {
    const code = `const x = eval(dangerous);\n`;
    const matches = await matchAstPattern(code, 'tsx', 'eval($CODE)');
    expect(matches).toHaveLength(1);
  });

  it('returns correct 1-indexed line numbers', async () => {
    const code = `line1();\nline2();\neval(x);\nline4();\n`;
    const matches = await matchAstPattern(code, 'javascript', 'eval($CODE)');
    expect(matches).toHaveLength(1);
    expect(matches[0].startLine).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// extractFastFilter
// ---------------------------------------------------------------------------

describe('extractFastFilter', () => {
  it('extracts longest literal from pattern with metavars', () => {
    expect(extractFastFilter('$DB.query($SQL)')).toBe('.query');
  });

  it('extracts keyword from eval pattern', () => {
    expect(extractFastFilter('eval($CODE)')).toBe('eval');
  });

  it('extracts from innerHTML pattern', () => {
    const filter = extractFastFilter('$EL.innerHTML = $VALUE');
    expect(filter).toBe('.innerHTML');
  });

  it('returns undefined for pattern with only metavars', () => {
    expect(extractFastFilter('$X')).toBeUndefined();
  });

  it('extracts from multi-word pattern', () => {
    const filter = extractFastFilter('document.write($CONTENT)');
    expect(filter).toBe('document.write');
  });
});

// ---------------------------------------------------------------------------
// matchAstPattern — compound operators
// ---------------------------------------------------------------------------

describe('matchAstPattern compound operators', () => {
  it('inside: matches pattern inside an arrow_function', async () => {
    const code = `
const handler = () => {
  db.query(sql);
};
`;
    const opts: CompoundRuleOpts = { inside: { kind: 'arrow_function' } };
    const matches = await matchAstPattern(code, 'javascript', '$DB.query($SQL)', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('db.query');
  });

  it('inside: does NOT match when pattern is outside an arrow_function', async () => {
    const code = `db.query(sql);\n`;
    const opts: CompoundRuleOpts = { inside: { kind: 'arrow_function' } };
    const matches = await matchAstPattern(code, 'javascript', '$DB.query($SQL)', opts);
    expect(matches).toHaveLength(0);
  });

  it('has: matches only when child contains the specified regex', async () => {
    const codeWith = `db.query('SELECT ' + userId);\n`;
    const codeWithout = `db.query('SELECT 1');\n`;
    const opts: CompoundRuleOpts = { has: { regex: '\\+' } };

    const matchesWith = await matchAstPattern(codeWith, 'javascript', '$DB.query($SQL)', opts);
    expect(matchesWith.length).toBeGreaterThanOrEqual(1);

    const matchesWithout = await matchAstPattern(codeWithout, 'javascript', '$DB.query($SQL)', opts);
    expect(matchesWithout).toHaveLength(0);
  });

  it('not: excludes matches that also match the not pattern', async () => {
    // eval outside try — should match with not: { inside: try_statement }
    const codeOutside = `eval(userInput);\n`;
    const opts: CompoundRuleOpts = { not: { inside: { kind: 'try_statement' } } };

    const matchesOutside = await matchAstPattern(codeOutside, 'javascript', 'eval($CODE)', opts);
    expect(matchesOutside).toHaveLength(1);

    // eval inside try — should NOT match
    const codeInside = `
try {
  eval(userInput);
} catch(e) {}
`;
    const matchesInside = await matchAstPattern(codeInside, 'javascript', 'eval($CODE)', opts);
    expect(matchesInside).toHaveLength(0);
  });

  it('has-not: matches only when child does NOT contain the text', async () => {
    const codeWithHttpOnly = `res.cookie('sid', token, { httpOnly: true });\n`;
    const codeWithout = `res.cookie('sid', token, { secure: true });\n`;
    const opts: CompoundRuleOpts = { hasNot: { regex: 'httpOnly' } };

    const matchesWith = await matchAstPattern(
      codeWithHttpOnly, 'javascript',
      'res.cookie($NAME, $VALUE, $OPTS)', opts,
    );
    expect(matchesWith).toHaveLength(0);

    const matchesWithout = await matchAstPattern(
      codeWithout, 'javascript',
      'res.cookie($NAME, $VALUE, $OPTS)', opts,
    );
    expect(matchesWithout).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// matchAstPattern — Python/Go/Ruby kind-based matching
// ---------------------------------------------------------------------------

describe('matchAstPattern kind-based matching (Python/Go/Ruby)', () => {
  it('Python: kind-based match for cursor.execute(...)', async () => {
    const code = `cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n`;
    const opts: CompoundRuleOpts = { kind: 'call', regex: '\\.execute\\(' };
    const matches = await matchAstPattern(code, 'python', '', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('cursor.execute');
  });

  it('Python: kind-based match for eval()', async () => {
    const code = `result = eval(user_input)\n`;
    const opts: CompoundRuleOpts = { kind: 'call', regex: '^eval\\(' };
    const matches = await matchAstPattern(code, 'python', '', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('eval');
  });

  it('Python: returns empty for $METAVAR pattern without kind/regex', async () => {
    const code = `cursor.execute(sql)\n`;
    const matches = await matchAstPattern(code, 'python', '$DB.execute($SQL)');
    expect(matches).toHaveLength(0);
  });

  it('Go: kind-based match for db.Query(...)', async () => {
    const code = `package main\nfunc main() { db.Query("SELECT * FROM users WHERE id = " + id) }\n`;
    const opts: CompoundRuleOpts = {
      kind: 'call_expression',
      regex: '\\.(?:Query|Exec|QueryRow)\\([\\s\\S]*\\+',
    };
    const matches = await matchAstPattern(code, 'go', '', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('db.Query');
  });

  it('Ruby: kind-based match for system(...)', async () => {
    const code = `system(user_input)\n`;
    const opts: CompoundRuleOpts = { kind: 'call', regex: '^system\\(' };
    const matches = await matchAstPattern(code, 'ruby', '', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('system');
  });

  it('Ruby: kind-based match for Marshal.load', async () => {
    const code = `obj = Marshal.load(data)\n`;
    const opts: CompoundRuleOpts = { kind: 'call', regex: 'Marshal\\.load' };
    const matches = await matchAstPattern(code, 'ruby', '', opts);
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toContain('Marshal.load');
  });

  it('dynamic language registration is idempotent', async () => {
    // Running two Python matches in sequence should not throw
    const code1 = `eval(x)\n`;
    const code2 = `eval(y)\n`;
    const opts: CompoundRuleOpts = { kind: 'call', regex: '^eval\\(' };
    const m1 = await matchAstPattern(code1, 'python', '', opts);
    const m2 = await matchAstPattern(code2, 'python', '', opts);
    expect(m1).toHaveLength(1);
    expect(m2).toHaveLength(1);
  });

  it('returns empty for unsupported language (php)', async () => {
    const matches = await matchAstPattern('eval($x)', 'php', '', { kind: 'call', regex: 'eval' });
    expect(matches).toHaveLength(0);
  });
});
