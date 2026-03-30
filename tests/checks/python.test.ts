import { describe, it, expect } from 'vitest';
import { pythonChecks } from '../../src/checks/python/index.js';
import { testLine } from '../helpers.js';

// ---------------------------------------------------------------------------
// PY001 - SQL Injection (f-string)
// ---------------------------------------------------------------------------

describe('PY001 - SQL Injection (f-string)', () => {
  it('detects f-string in SQL execute', () => {
    const finding = testLine(
      pythonChecks,
      'PY001',
      'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('does not flag parameterized query', () => {
    const finding = testLine(
      pythonChecks,
      'PY001',
      'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY002 - SQL Injection (.format)
// ---------------------------------------------------------------------------

describe('PY002 - SQL Injection (.format)', () => {
  it('detects .format() in SQL execute', () => {
    const finding = testLine(
      pythonChecks,
      'PY002',
      'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('does not flag parameterized query', () => {
    const finding = testLine(
      pythonChecks,
      'PY002',
      'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY003 - Command Injection
// ---------------------------------------------------------------------------

describe('PY003 - Command Injection', () => {
  it('detects os.system with f-string', () => {
    const finding = testLine(
      pythonChecks,
      'PY003',
      'os.system(f"rm {filename}")',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY003');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('does not flag subprocess.run with list args', () => {
    const finding = testLine(
      pythonChecks,
      'PY003',
      'subprocess.run(["ls", arg])',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY004 - Pickle Deserialization
// ---------------------------------------------------------------------------

describe('PY004 - Pickle Deserialization', () => {
  it('detects pickle.loads', () => {
    const finding = testLine(
      pythonChecks,
      'PY004',
      'pickle.loads(data)',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY004');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('does not flag json.loads', () => {
    const finding = testLine(
      pythonChecks,
      'PY004',
      'json.loads(data)',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY005 - Django DEBUG True
// ---------------------------------------------------------------------------

describe('PY005 - Django DEBUG True', () => {
  it('detects DEBUG = True', () => {
    const finding = testLine(
      pythonChecks,
      'PY005',
      'DEBUG = True',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
  });

  it('skips when value comes from os.environ', () => {
    const finding = testLine(
      pythonChecks,
      'PY005',
      "DEBUG = os.environ.get('DEBUG')",
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY006 - Django SECRET_KEY Hardcoded
// ---------------------------------------------------------------------------

describe('PY006 - Django SECRET_KEY Hardcoded', () => {
  it('detects hardcoded SECRET_KEY', () => {
    const finding = testLine(
      pythonChecks,
      'PY006',
      "SECRET_KEY = 'django-insecure-abc123def456'",
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY006');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('skips when value comes from env()', () => {
    const finding = testLine(
      pythonChecks,
      'PY006',
      "SECRET_KEY = env('SECRET_KEY')",
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY007 - Flask Debug Mode
// ---------------------------------------------------------------------------

describe('PY007 - Flask Debug Mode', () => {
  it('detects app.run(debug=True)', () => {
    const finding = testLine(
      pythonChecks,
      'PY007',
      'app.run(debug=True)',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY007');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
  });

  it('does not flag app.run() without debug', () => {
    const finding = testLine(
      pythonChecks,
      'PY007',
      'app.run()',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY008 - eval() with User Input
// ---------------------------------------------------------------------------

describe('PY008 - eval() with User Input', () => {
  it('detects eval with request.form input', () => {
    const finding = testLine(
      pythonChecks,
      'PY008',
      "eval(request.form['code'])",
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY008');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('python');
  });

  it('does not flag eval with static string (no user input)', () => {
    const finding = testLine(
      pythonChecks,
      'PY008',
      "eval('1+1')",
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY009 - Hardcoded Password (Python)
// ---------------------------------------------------------------------------

describe('PY009 - Hardcoded Password (Python)', () => {
  it('detects hardcoded password string', () => {
    const finding = testLine(
      pythonChecks,
      'PY009',
      'password = "hardcoded123"',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY009');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
  });

  it('skips when password comes from os.environ', () => {
    const finding = testLine(
      pythonChecks,
      'PY009',
      "password = os.environ['DB_PASS']",
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY011 - Insecure Password Hash
// ---------------------------------------------------------------------------

describe('PY011 - Insecure Password Hash', () => {
  it('detects hashlib.md5 for password hashing', () => {
    const finding = testLine(
      pythonChecks,
      'PY011',
      'hashlib.md5(password.encode())',
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY011');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
  });

  it('does not flag hashlib.md5 without password', () => {
    const finding = testLine(
      pythonChecks,
      'PY011',
      'hashlib.md5(data.encode())',
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY012 - Path Traversal
// ---------------------------------------------------------------------------

describe('PY012 - Path Traversal', () => {
  it('detects open with request.args input', () => {
    const finding = testLine(
      pythonChecks,
      'PY012',
      "open(request.args['file'])",
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY012');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
  });

  it('does not flag open with static filename', () => {
    const finding = testLine(
      pythonChecks,
      'PY012',
      "open('config.json')",
      'py',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// PY010 - No CSRF Middleware (Django)
// ---------------------------------------------------------------------------

describe('PY010 - No CSRF Middleware (Django)', () => {
  it('detects MIDDLEWARE list without CSRF on same line', () => {
    const finding = testLine(
      pythonChecks,
      'PY010',
      "MIDDLEWARE = [",
      'py',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PY010');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('python');
    expect(finding!.message).toContain('CSRF');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag MIDDLEWARE list that includes CsrfViewMiddleware on same line', () => {
    const finding = testLine(
      pythonChecks,
      'PY010',
      "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']",
      'py',
    );
    expect(finding).toBeNull();
  });
});
