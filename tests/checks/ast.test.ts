import { describe, it, expect } from 'vitest';
import type { AstCheck, AstCheckContext, Finding, FileEntry, ScanContext } from '../../src/checks/types.js';
import { astChecks } from '../../src/checks/ast/index.js';
import { parseFile, clearAstCache } from '../../src/engine/ast-parser.js';
import { findTaintPaths } from '../../src/engine/taint-tracker.js';
import { defaultConfig } from '../../src/config/defaults.js';

async function testAst(
  checkId: string,
  code: string,
  extension = 'js',
): Promise<Finding[]> {
  clearAstCache();
  const check = astChecks.find((c) => c.id === checkId) as AstCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const file: FileEntry = {
    absolutePath: `/test/file.${extension}`,
    relativePath: `file.${extension}`,
    sizeBytes: code.length,
    extension,
    basename: `file.${extension}`,
    content: code,
    lines: code.split('\n'),
  };

  const parsed = await parseFile(file);
  if (!parsed) throw new Error(`Failed to parse ${extension} file`);

  const ctx = { config: defaultConfig() } as ScanContext;
  const astCtx: AstCheckContext = {
    rootNode: parsed.rootNode,
    file,
    language: parsed.language,
    ctx,
    findTaintPaths(opts) {
      return findTaintPaths(parsed.rootNode, parsed.language, opts);
    },
  };

  return check.analyze(astCtx);
}

describe('AST-INJ001 - SQL Injection (Taint-Tracked)', () => {
  it('detects SQL injection through variable indirection', async () => {
    const code = `
app.get('/users', async (req, res) => {
  const id = req.params.id;
  const result = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(result);
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].taintFlow).toBeDefined();
    expect(findings[0].taintFlow!.length).toBeGreaterThan(1);
  });

  it('detects SQL injection through multi-hop variables', async () => {
    const code = `
app.post('/search', async (req, res) => {
  const { q } = req.body;
  const term = q.trim();
  const sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
  const results = await db.query(sql);
  res.json(results);
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does NOT flag parameterized queries', async () => {
    const code = `
app.get('/users', async (req, res) => {
  const id = req.params.id;
  const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  res.json(result);
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag when no user input is involved', async () => {
    const code = `
async function getAdmins() {
  const role = 'admin';
  return await db.query(\`SELECT * FROM users WHERE role = '\${role}'\`);
}`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings).toHaveLength(0);
  });
});

describe('AST-INJ002 - Command Injection (Taint-Tracked)', () => {
  it('detects command injection through variable', async () => {
    const code = `
const { exec } = require('child_process');
app.post('/run', (req, res) => {
  const cmd = req.body.command;
  exec(cmd, (err, stdout) => {
    res.json({ output: stdout });
  });
});`;
    const findings = await testAst('AST-INJ002', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ002');
    expect(findings[0].severity).toBe('critical');
  });

  it('does NOT flag exec with safe internal variables', async () => {
    const code = `
const { exec } = require('child_process');
function restartServer() {
  const script = './restart.sh';
  exec(script);
}`;
    const findings = await testAst('AST-INJ002', code);
    expect(findings).toHaveLength(0);
  });
});

describe('AST-INJ003 - SSRF (Taint-Tracked)', () => {
  it('detects SSRF through variable URL', async () => {
    const code = `
app.get('/proxy', async (req, res) => {
  const url = req.query.target;
  const response = await fetch(url);
  res.json(await response.json());
});`;
    const findings = await testAst('AST-INJ003', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ003');
    expect(findings[0].severity).toBe('critical');
  });

  it('does NOT flag fetch with hardcoded URL', async () => {
    const code = `
async function getData() {
  const response = await fetch('https://api.example.com/data');
  return response.json();
}`;
    const findings = await testAst('AST-INJ003', code);
    expect(findings).toHaveLength(0);
  });
});

describe('AST-INJ004 - XSS (Taint-Tracked)', () => {
  it('detects XSS through variable innerHTML', async () => {
    const code = `
app.get('/page', (req, res) => {
  const content = req.query.html;
  document.getElementById('output').innerHTML = content;
});`;
    const findings = await testAst('AST-INJ004', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ004');
    expect(findings[0].severity).toBe('high');
  });
});

describe('AST-INJ005 - Path Traversal (Taint-Tracked)', () => {
  it('detects path traversal through variable', async () => {
    const code = `
const fs = require('fs');
app.get('/file', (req, res) => {
  const filePath = req.query.path;
  const data = fs.readFileSync(filePath);
  res.send(data);
});`;
    const findings = await testAst('AST-INJ005', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ005');
    expect(findings[0].severity).toBe('high');
  });

  it('does NOT flag file read with hardcoded path', async () => {
    const code = `
const fs = require('fs');
function readConfig() {
  return fs.readFileSync('./config.json', 'utf-8');
}`;
    const findings = await testAst('AST-INJ005', code);
    expect(findings).toHaveLength(0);
  });
});

describe('Object property taint tracking', () => {
  it('detects taint through object property assignment', async () => {
    const code = `
app.post('/api', (req, res) => {
  const data = {};
  data.query = req.body.search;
  db.query(\`SELECT * WHERE name = '\${data.query}'\`);
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].taintFlow).toBeDefined();
  });
});

describe('Promise .then() callback taint', () => {
  it('detects taint flowing through .then() callback parameter', async () => {
    const code = `
app.post('/api', (req, res) => {
  const input = req.body.data;
  processAsync(input).then(result => {
    db.query(\`SELECT * WHERE x = '\${result}'\`);
  });
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
  });
});

describe('Inter-function taint (same file)', () => {
  it('detects taint flowing through a helper function call', async () => {
    const code = `
function runQuery(q) {
  db.query(q);
}

app.get('/api', (req, res) => {
  const search = req.body.q;
  runQuery(search);
});`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
  });

  it('does NOT flag cross-function call with safe data', async () => {
    const code = `
function runQuery(q) {
  db.query(q);
}

function doStuff() {
  const safe = 'SELECT 1';
  runQuery(safe);
}`;
    const findings = await testAst('AST-INJ001', code);
    expect(findings).toHaveLength(0);
  });
});

// ── Python taint tracking ─────────────────────────────────────────────

describe('Python AST-INJ001 - SQL Injection (Taint-Tracked)', () => {
  it('detects SQL injection through Flask request.args', async () => {
    const code = `from flask import request

@app.route('/search')
def search():
    q = request.args.get('q')
    cursor.execute(f"SELECT * FROM items WHERE name = '{q}'")
`;
    const findings = await testAst('AST-INJ001', code, 'py');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].taintFlow).toBeDefined();
  });

  it('does NOT flag parameterized queries in Python', async () => {
    const code = `from flask import request

@app.route('/search')
def search():
    q = request.args.get('q')
    cursor.execute("SELECT * FROM items WHERE name = %s", [q])
`;
    const findings = await testAst('AST-INJ001', code, 'py');
    expect(findings).toHaveLength(0);
  });
});

describe('Python AST-INJ002 - Command Injection (Taint-Tracked)', () => {
  it('detects os.system with user input', async () => {
    const code = `from flask import request
import os

@app.route('/run')
def run_cmd():
    cmd = request.form.get('cmd')
    os.system(cmd)
`;
    const findings = await testAst('AST-INJ002', code, 'py');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ002');
  });
});

// ── Go taint tracking ────────────────────────────────────────────────

describe('Go AST-INJ001 - SQL Injection (Taint-Tracked)', () => {
  it('detects SQL injection through r.FormValue', async () => {
    const code = `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    db.Query("SELECT * FROM users WHERE id = " + id)
}
`;
    const findings = await testAst('AST-INJ001', code, 'go');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].taintFlow).toBeDefined();
  });

  it('does NOT flag when no user input is involved in Go', async () => {
    const code = `package main

func getAdmins() {
    role := "admin"
    db.Query("SELECT * FROM users WHERE role = '" + role + "'")
}
`;
    const findings = await testAst('AST-INJ001', code, 'go');
    expect(findings).toHaveLength(0);
  });
});

describe('Go AST-INJ002 - Command Injection (Taint-Tracked)', () => {
  it('detects exec.Command with user input', async () => {
    const code = `package main

import (
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command(cmd)
}
`;
    const findings = await testAst('AST-INJ002', code, 'go');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ002');
  });
});

// ── Ruby taint tracking ──────────────────────────────────────────────

describe('Ruby AST-INJ001 - SQL Injection (Taint-Tracked)', () => {
  it('detects SQL injection through params', async () => {
    const code = `class UsersController < ApplicationController
  def show
    id = params[:id]
    User.where("name = '#{id}'")
  end
end
`;
    const findings = await testAst('AST-INJ001', code, 'rb');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].severity).toBe('critical');
  });
});

// ── PHP taint tracking ──────────────────────────────────────────────

describe('PHP AST-INJ001 - SQL Injection (Taint-Tracked)', () => {
  it('detects SQL injection through $_GET', async () => {
    const code = `<?php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
`;
    const findings = await testAst('AST-INJ001', code, 'php');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ001');
    expect(findings[0].severity).toBe('critical');
  });
});

describe('PHP AST-INJ002 - Command Injection (Taint-Tracked)', () => {
  it('detects exec with $_POST input', async () => {
    const code = `<?php
$cmd = $_POST['cmd'];
exec($cmd);
`;
    const findings = await testAst('AST-INJ002', code, 'php');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-INJ002');
  });
});

// ── AST-AUTH001: Server Component Prop Leak ─────────────────────────────

describe('AST-AUTH001 - Server Component Prop Leak', () => {
  it('detects process.env.SECRET_KEY passed as JSX prop', async () => {
    const code = `export default function Page() {
  return <ClientComponent apiKey={process.env.SECRET_KEY} />;
}`;
    const findings = await testAst('AST-AUTH001', code, 'tsx');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('AST-AUTH001');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('data-exposure');
    expect(findings[0].message).toContain('SECRET_KEY');
    expect(findings[0].message).toContain('prop');
    expect(findings[0].fix).toBeTruthy();
  });

  it('does NOT flag NEXT_PUBLIC_ env vars passed as JSX props', async () => {
    const code = `export default function Page() {
  return <ClientComponent name={process.env.NEXT_PUBLIC_NAME} />;
}`;
    const findings = await testAst('AST-AUTH001', code, 'tsx');
    expect(findings).toHaveLength(0);
  });
});
