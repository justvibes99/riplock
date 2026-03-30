import { describe, it, expect } from 'vitest';
import { goChecks } from '../../src/checks/go/index.js';
import { testLine } from '../helpers.js';

// ---------------------------------------------------------------------------
// GO001 - SQL Injection (fmt.Sprintf)
// ---------------------------------------------------------------------------

describe('GO001 - SQL Injection (fmt.Sprintf)', () => {
  it('detects fmt.Sprintf building a SQL query', () => {
    const finding = testLine(
      goChecks,
      'GO001',
      'fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('go');
  });

  it('does not flag parameterized query', () => {
    const finding = testLine(
      goChecks,
      'GO001',
      'db.Query("SELECT * FROM users WHERE id = $1", id)',
      'go',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// GO002 - SQL Injection (string concat)
// ---------------------------------------------------------------------------

describe('GO002 - SQL Injection (string concat)', () => {
  it('detects string concatenation in SQL query', () => {
    const finding = testLine(
      goChecks,
      'GO002',
      'db.Query("SELECT * FROM users WHERE id=" + id)',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO003 - Command Injection
// ---------------------------------------------------------------------------

describe('GO003 - Command Injection', () => {
  it('detects exec.Command with sh -c', () => {
    const finding = testLine(
      goChecks,
      'GO003',
      'exec.Command("sh", "-c", cmd)',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO003');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO004 - Hardcoded Credentials
// ---------------------------------------------------------------------------

describe('GO004 - Hardcoded Credentials', () => {
  it('detects hardcoded password', () => {
    const finding = testLine(
      goChecks,
      'GO004',
      'password := "hardcoded123"',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO004');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('go');
  });

  it('skips when password comes from os.Getenv', () => {
    const finding = testLine(
      goChecks,
      'GO004',
      'password := os.Getenv("DB_PASS")',
      'go',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// GO005 - Insecure TLS Config
// ---------------------------------------------------------------------------

describe('GO005 - Insecure TLS Config', () => {
  it('detects InsecureSkipVerify: true', () => {
    const finding = testLine(
      goChecks,
      'GO005',
      'InsecureSkipVerify: true',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO006 - Unhandled Error
// ---------------------------------------------------------------------------

describe('GO006 - Unhandled Error', () => {
  it('detects discarded error return value', () => {
    const finding = testLine(
      goChecks,
      'GO006',
      'result, _ := db.Query(sql)',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO006');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO007 - Unsafe Pointer
// ---------------------------------------------------------------------------

describe('GO007 - Unsafe Pointer', () => {
  it('detects unsafe.Pointer usage', () => {
    const finding = testLine(
      goChecks,
      'GO007',
      'unsafe.Pointer',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO007');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO009 - Exported Sensitive Field
// ---------------------------------------------------------------------------

describe('GO009 - Exported Sensitive Field', () => {
  it('detects JSON-exported Password field', () => {
    const finding = testLine(
      goChecks,
      'GO009',
      'Password string `json:"password"`',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO009');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('go');
  });
});

// ---------------------------------------------------------------------------
// GO008 - HTTP Server No Timeout
// ---------------------------------------------------------------------------

describe('GO008 - HTTP Server No Timeout', () => {
  it('detects &http.Server{} without timeout', () => {
    const finding = testLine(
      goChecks,
      'GO008',
      'srv := &http.Server{Addr: ":8080"}',
      'go',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('GO008');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('go');
    expect(finding!.message).toContain('timeout');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag &http.Server with ReadTimeout on same line', () => {
    const finding = testLine(
      goChecks,
      'GO008',
      'srv := &http.Server{Addr: ":8080", ReadTimeout: 10 * time.Second}',
      'go',
    );
    expect(finding).toBeNull();
  });
});
