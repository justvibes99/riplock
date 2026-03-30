import { describe, it, expect } from 'vitest';
import { injectionChecks } from '../../src/checks/injection/index.js';
import { testLine, testFileCheck } from '../helpers.js';

// ---------------------------------------------------------------------------
// INJ001 - SQL Injection (Template Literal)
// ---------------------------------------------------------------------------

describe('INJ001 - SQL Injection (Template Literal)', () => {
  it('detects SQL in template literal with interpolation', () => {
    const finding = testLine(
      injectionChecks,
      'INJ001',
      'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ001');
    expect(finding!.severity).toBe('critical');
  });

  it('does not flag parameterized queries', () => {
    const finding = testLine(
      injectionChecks,
      'INJ001',
      "db.query('SELECT * FROM users WHERE id = $1', [userId])",
    );
    expect(finding).toBeNull();
  });

  it('does not flag commented-out code', () => {
    const finding = testLine(
      injectionChecks,
      'INJ001',
      '// db.query(`SELECT * FROM users WHERE id = ${userId}`)',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ002 - SQL Injection (String Concatenation)
// ---------------------------------------------------------------------------

describe('INJ002 - SQL Injection (String Concatenation)', () => {
  it('detects SQL string concatenation', () => {
    const finding = testLine(
      injectionChecks,
      'INJ002',
      'db.query("SELECT * FROM users WHERE id=" + id)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ002');
    expect(finding!.severity).toBe('critical');
  });

  it('does not flag static queries without concat', () => {
    const finding = testLine(
      injectionChecks,
      'INJ002',
      'db.query("SELECT * FROM users")',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ003 - NoSQL Injection (MongoDB)
// ---------------------------------------------------------------------------

describe('INJ003 - NoSQL Injection (MongoDB)', () => {
  it('detects direct req.body in findOne', () => {
    const finding = testLine(
      injectionChecks,
      'INJ003',
      'User.findOne(req.body)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('detects req.query in find', () => {
    const finding = testLine(
      injectionChecks,
      'INJ003',
      'db.collection.find(req.query)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag safe object construction', () => {
    const finding = testLine(
      injectionChecks,
      'INJ003',
      'User.findOne({ email: sanitized })',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ004 - Command Injection (exec)
// ---------------------------------------------------------------------------

describe('INJ004 - Command Injection (exec)', () => {
  it('detects exec with template literal interpolation', () => {
    const finding = testLine(
      injectionChecks,
      'INJ004',
      'exec(`ls ${req.query.path}`)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ004');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('skips execFile (safer alternative)', () => {
    const finding = testLine(
      injectionChecks,
      'INJ004',
      'execFile(`ls ${input}`)',
    );
    expect(finding).toBeNull();
  });

  it('detects exec with string concatenation', () => {
    const finding = testLine(
      injectionChecks,
      'INJ004',
      'exec("ls " + input)',
    );
    expect(finding).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ007 - XSS via innerHTML
// ---------------------------------------------------------------------------

describe('INJ007 - XSS via innerHTML', () => {
  it('detects dynamic innerHTML assignment', () => {
    const finding = testLine(
      injectionChecks,
      'INJ007',
      'el.innerHTML = data;',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ007');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('skips static string innerHTML assignment', () => {
    const finding = testLine(
      injectionChecks,
      'INJ007',
      "el.innerHTML = '<div>';",
    );
    expect(finding).toBeNull();
  });

  it('does not flag empty string innerHTML', () => {
    const finding = testLine(
      injectionChecks,
      'INJ007',
      "el.innerHTML = '';",
    );
    expect(finding).toBeNull();
  });

  it('detects innerHTML with function call', () => {
    const finding = testLine(
      injectionChecks,
      'INJ007',
      'el.innerHTML = buildHtml(data);',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ007');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });
});

// ---------------------------------------------------------------------------
// INJ009 - eval()
// ---------------------------------------------------------------------------

describe('INJ009 - eval() Usage', () => {
  it('detects eval call', () => {
    const finding = testLine(
      injectionChecks,
      'INJ009',
      'eval(userInput)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ009');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('skips eval in a line comment', () => {
    const finding = testLine(
      injectionChecks,
      'INJ009',
      '// eval(x)',
    );
    expect(finding).toBeNull();
  });

  it('skips eval in a block comment', () => {
    const finding = testLine(
      injectionChecks,
      'INJ009',
      '/* eval(x) */',
    );
    expect(finding).toBeNull();
  });

  it('detects eval in an expression', () => {
    const finding = testLine(
      injectionChecks,
      'INJ009',
      'const result = eval(code);',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ009');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });
});

// ---------------------------------------------------------------------------
// INJ013 - Open Redirect
// ---------------------------------------------------------------------------

describe('INJ013 - Open Redirect', () => {
  it('detects res.redirect with req.query', () => {
    const finding = testLine(
      injectionChecks,
      'INJ013',
      'res.redirect(req.query.url)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ013');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag redirect with a static path', () => {
    const finding = testLine(
      injectionChecks,
      'INJ013',
      "res.redirect('/home')",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ014 - SSRF
// ---------------------------------------------------------------------------

describe('INJ014 - SSRF', () => {
  it('detects fetch with req.query.url', () => {
    const finding = testLine(
      injectionChecks,
      'INJ014',
      'fetch(req.query.url)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ014');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag fetch with a static URL', () => {
    const finding = testLine(
      injectionChecks,
      'INJ014',
      "fetch('https://api.internal.co/data')",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ017 - Prisma $queryRawUnsafe
// ---------------------------------------------------------------------------

describe('INJ017 - Prisma $queryRawUnsafe', () => {
  it('detects $queryRawUnsafe usage', () => {
    const finding = testLine(
      injectionChecks,
      'INJ017',
      'const result = await prisma.$queryRawUnsafe(sql)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ017');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('detects $executeRawUnsafe usage', () => {
    const finding = testLine(
      injectionChecks,
      'INJ017',
      'await prisma.$executeRawUnsafe(query)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ017');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag safe $queryRaw tagged template', () => {
    const finding = testLine(
      injectionChecks,
      'INJ017',
      'const result = await prisma.$queryRaw`SELECT * FROM users`',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ018 - Mass Assignment via req.body Spread
// ---------------------------------------------------------------------------

describe('INJ018 - Mass Assignment', () => {
  it('detects create with data: req.body', () => {
    const finding = testLine(
      injectionChecks,
      'INJ018',
      'await prisma.user.create({ data: req.body })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ018');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('detects create with spread req.body', () => {
    const finding = testLine(
      injectionChecks,
      'INJ018',
      'await prisma.user.create({ data: { ...req.body } })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ018');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag create with explicit fields', () => {
    const finding = testLine(
      injectionChecks,
      'INJ018',
      'await prisma.user.create({ data: { name, email } })',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ005 - Command Injection (Python)
// ---------------------------------------------------------------------------

describe('INJ005 - Command Injection (Python)', () => {
  it('detects os.system with f-string', () => {
    const finding = testLine(
      injectionChecks,
      'INJ005',
      'os.system(f"ls {user_input}")',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ005');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag subprocess.run with list args', () => {
    const finding = testLine(
      injectionChecks,
      'INJ005',
      'subprocess.run(["ls", arg])',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ006 - Path Traversal
// ---------------------------------------------------------------------------

describe('INJ006 - Path Traversal', () => {
  it('detects readFileSync with req.query input', () => {
    const finding = testLine(
      injectionChecks,
      'INJ006',
      'fs.readFileSync(req.query.path)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ006');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag readFileSync with static path', () => {
    const finding = testLine(
      injectionChecks,
      'INJ006',
      "fs.readFileSync('./config.json')",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ008 - XSS via dangerouslySetInnerHTML
// ---------------------------------------------------------------------------

describe('INJ008 - XSS via dangerouslySetInnerHTML', () => {
  it('detects dangerouslySetInnerHTML with dynamic data', () => {
    const finding = testLine(
      injectionChecks,
      'INJ008',
      'dangerouslySetInnerHTML={{__html: data}}',
      'tsx',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ008');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag dangerouslySetInnerHTML with DOMPurify.sanitize', () => {
    const finding = testLine(
      injectionChecks,
      'INJ008',
      'dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(data)}}',
      'tsx',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ010 - new Function()
// ---------------------------------------------------------------------------

describe('INJ010 - new Function() Usage', () => {
  it('detects new Function call', () => {
    const finding = testLine(
      injectionChecks,
      'INJ010',
      'new Function(code)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ010');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag new Function in a comment', () => {
    const finding = testLine(
      injectionChecks,
      'INJ010',
      '// new Function()',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ011 - document.write
// ---------------------------------------------------------------------------

describe('INJ011 - document.write Usage', () => {
  it('detects document.write call', () => {
    const finding = testLine(
      injectionChecks,
      'INJ011',
      'document.write(html)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ011');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag commented-out document.write', () => {
    const finding = testLine(
      injectionChecks,
      'INJ011',
      '// document.write(html)',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ012 - Prototype Pollution
// ---------------------------------------------------------------------------

describe('INJ012 - Prototype Pollution', () => {
  it('detects Object.assign with req.body', () => {
    const finding = testLine(
      injectionChecks,
      'INJ012',
      'Object.assign({}, req.body)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ012');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag spread of a safe local variable', () => {
    const finding = testLine(
      injectionChecks,
      'INJ012',
      'const settings = { ...defaults, theme };',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ015 - Regex Injection (ReDoS)
// ---------------------------------------------------------------------------

describe('INJ015 - Regex Injection (ReDoS)', () => {
  it('detects new RegExp with req.query input', () => {
    const finding = testLine(
      injectionChecks,
      'INJ015',
      'new RegExp(req.query.pattern)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ015');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag new RegExp with static string', () => {
    const finding = testLine(
      injectionChecks,
      'INJ015',
      "new RegExp('fixed')",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ016 - Server-Side Template Injection (SSTI)
// ---------------------------------------------------------------------------

describe('INJ016 - Server-Side Template Injection (SSTI)', () => {
  it('detects ejs.render with req.body.template', () => {
    const finding = testLine(
      injectionChecks,
      'INJ016',
      'ejs.render(req.body.template)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ016');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag ejs.render with local template variable', () => {
    const finding = testLine(
      injectionChecks,
      'INJ016',
      'ejs.render(template, data)',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ019 - AI Prompt Injection
// ---------------------------------------------------------------------------

describe('INJ019 - AI Prompt Injection', () => {
  it('detects user input interpolated into prompt content', () => {
    const finding = testLine(
      injectionChecks,
      'INJ019',
      'content: `Summarize this: ${req.body.message}`',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ019');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag static prompt content', () => {
    const finding = testLine(
      injectionChecks,
      'INJ019',
      "content: 'You are a helpful assistant'",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ020 - Email Header Injection
// ---------------------------------------------------------------------------

describe('INJ020 - Email Header Injection', () => {
  it('detects sendMail with req.body.email in to field', () => {
    const finding = testLine(
      injectionChecks,
      'INJ020',
      'sendMail({ to: req.body.email })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ020');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag sendMail with static email', () => {
    const finding = testLine(
      injectionChecks,
      'INJ020',
      "sendMail({ to: 'fixed@email.com' })",
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INJ021 - Insecure Deserialization
// ---------------------------------------------------------------------------

describe('INJ021 - Insecure Deserialization', () => {
  it('detects JSON.parse with req.body', () => {
    const finding = testLine(
      injectionChecks,
      'INJ021',
      'JSON.parse(req.body)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INJ021');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('injection');
  });

  it('does not flag JSON.parse with static string', () => {
    const finding = testLine(
      injectionChecks,
      'INJ021',
      'JSON.parse(\'{"a":1}\')',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Regression: real-world false positives
// ---------------------------------------------------------------------------

describe('Regression: real-world false positives', () => {
  it('INJ001: does not flag "Delete" in JSX aria-label', () => {
    const finding = testLine(injectionChecks, 'INJ001', 'aria-label={`Delete "${goal.text}"`}');
    expect(finding).toBeNull();
  });

  it('INJ001: returns high (not critical) for SQL with internal variables', () => {
    const finding = testLine(injectionChecks, 'INJ001', 'db.prepare(`UPDATE contacts SET ${sets.join(", ")} WHERE id = ?`).run(...vals)');
    // Internal variable (no req./body./params.) should be high, not critical
    if (finding) expect(finding.severity).not.toBe('critical');
  });

  it('INJ004: does not flag db.exec (SQLite exec, not shell)', () => {
    const finding = testLine(injectionChecks, 'INJ004', 'db.exec(`ALTER TABLE schedules ADD COLUMN ${col} ${type}`)');
    expect(finding).toBeNull();
  });

  it('INJ004: returns medium (not critical) for exec with internal variables', () => {
    const finding = testLine(injectionChecks, 'INJ004', 'execSync(`open "${authUrl}"`, { stdio: "ignore" })');
    if (finding) expect(finding.severity).toBe('medium');
  });

  it('INJ007: does not flag innerHTML with long static string containing double quotes', () => {
    const finding = testLine(injectionChecks, 'INJ007', `panel.innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No data</p></div>';`);
    expect(finding).toBeNull();
  });

  it('INJ014: does not flag fetch with config var in template literal and body in options', () => {
    const finding = testLine(injectionChecks, 'INJ014', 'await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`, { method: "POST", body: form })');
    expect(finding).toBeNull();
  });
});

describe('INJ021 continued', () => {
  // INJ022 - Zip Slip (FileCheck)
  describe('INJ022 - Zip Slip / Archive Path Traversal', () => {
    it('flags archive extraction without path validation', async () => {
      const content = `const tar = require('tar');
tar.extract({ file: uploadedFile, cwd: destDir });`;
      const findings = await testFileCheck(injectionChecks, 'INJ022', content, { relativePath: 'extract.ts' });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('INJ022');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('injection');
    });

    it('skips when path validation is present', async () => {
      const content = `const tar = require('tar');
const resolved = path.resolve(destDir, entry.path);
if (!resolved.startsWith(destDir)) throw new Error('Zip slip');
tar.extract({ file: uploadedFile, cwd: destDir });`;
      const findings = await testFileCheck(injectionChecks, 'INJ022', content, { relativePath: 'extract.ts' });
      expect(findings).toHaveLength(0);
    });
  });
});
