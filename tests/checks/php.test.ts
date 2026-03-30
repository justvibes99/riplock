import { describe, it, expect } from 'vitest';
import { phpChecks } from '../../src/checks/php/index.js';
import { testLine } from '../helpers.js';

// ---------------------------------------------------------------------------
// PHP001 - SQL Injection
// ---------------------------------------------------------------------------

describe('PHP001 - SQL Injection', () => {
  it('detects user input concatenated into SQL query', () => {
    const finding = testLine(
      phpChecks,
      'PHP001',
      `mysqli_query("SELECT * FROM users WHERE id=" . $_GET['id'])`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP002 - Command Injection
// ---------------------------------------------------------------------------

describe('PHP002 - Command Injection', () => {
  it('detects exec with user input', () => {
    const finding = testLine(
      phpChecks,
      'PHP002',
      `exec($_GET['cmd'])`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP003 - eval with User Input
// ---------------------------------------------------------------------------

describe('PHP003 - eval with User Input', () => {
  it('detects eval with POST input', () => {
    const finding = testLine(
      phpChecks,
      'PHP003',
      `eval($_POST['code'])`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP003');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP004 - File Inclusion
// ---------------------------------------------------------------------------

describe('PHP004 - File Inclusion', () => {
  it('detects include with user input', () => {
    const finding = testLine(
      phpChecks,
      'PHP004',
      `include($_GET['page'])`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP004');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP005 - XSS (echo without escape)
// ---------------------------------------------------------------------------

describe('PHP005 - XSS (echo without escape)', () => {
  it('detects echo with unescaped user input', () => {
    const finding = testLine(
      phpChecks,
      'PHP005',
      `echo $_GET['name']`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP006 - Insecure Password Hash
// ---------------------------------------------------------------------------

describe('PHP006 - Insecure Password Hash', () => {
  it('detects md5 for password hashing', () => {
    const finding = testLine(
      phpChecks,
      'PHP006',
      'md5($password)',
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP006');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP008 - Error Display Enabled
// ---------------------------------------------------------------------------

describe('PHP008 - Error Display Enabled', () => {
  it('detects display_errors = On', () => {
    const finding = testLine(
      phpChecks,
      'PHP008',
      'display_errors = On',
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP008');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP009 - File Upload No Validation
// ---------------------------------------------------------------------------

describe('PHP009 - File Upload No Validation', () => {
  it('detects move_uploaded_file with $_FILES', () => {
    const finding = testLine(
      phpChecks,
      'PHP009',
      `move_uploaded_file($_FILES['file']['tmp_name'], $target)`,
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP009');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('php');
  });
});

// ---------------------------------------------------------------------------
// PHP007 - Register Globals
// ---------------------------------------------------------------------------

describe('PHP007 - Register Globals', () => {
  it('detects register_globals = On', () => {
    const finding = testLine(
      phpChecks,
      'PHP007',
      'register_globals = On',
      'php',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('PHP007');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('php');
    expect(finding!.message).toContain('register_globals');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag register_globals = Off', () => {
    const finding = testLine(
      phpChecks,
      'PHP007',
      'register_globals = Off',
      'php',
    );
    expect(finding).toBeNull();
  });
});
