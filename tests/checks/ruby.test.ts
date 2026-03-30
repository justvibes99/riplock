import { describe, it, expect } from 'vitest';
import { rubyChecks } from '../../src/checks/ruby/index.js';
import { testLine } from '../helpers.js';

// ---------------------------------------------------------------------------
// RB001 - SQL Injection
// ---------------------------------------------------------------------------

describe('RB001 - SQL Injection', () => {
  it('detects string interpolation in where clause', () => {
    const finding = testLine(
      rubyChecks,
      'RB001',
      `.where("name = '#{params[:name]}'")`,
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('ruby');
  });

  it('does not flag parameterized query', () => {
    const finding = testLine(
      rubyChecks,
      'RB001',
      '.where("name = ?", params[:name])',
      'rb',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RB003 - Mass Assignment (permit!)
// ---------------------------------------------------------------------------

describe('RB003 - Mass Assignment (permit!)', () => {
  it('detects permit! call', () => {
    const finding = testLine(
      rubyChecks,
      'RB003',
      '.permit!()',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('ruby');
  });
});

// ---------------------------------------------------------------------------
// RB004 - eval with User Input
// ---------------------------------------------------------------------------

describe('RB004 - eval with User Input', () => {
  it('detects eval with params input', () => {
    const finding = testLine(
      rubyChecks,
      'RB004',
      'eval(params[:code])',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB004');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('ruby');
  });
});

// ---------------------------------------------------------------------------
// RB005 - Rails Debug Mode
// ---------------------------------------------------------------------------

describe('RB005 - Rails Debug Mode', () => {
  it('detects consider_all_requests_local = true', () => {
    const finding = testLine(
      rubyChecks,
      'RB005',
      'config.consider_all_requests_local = true',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('ruby');
  });
});

// ---------------------------------------------------------------------------
// RB006 - Open Redirect
// ---------------------------------------------------------------------------

describe('RB006 - Open Redirect', () => {
  it('detects redirect_to with params input', () => {
    const finding = testLine(
      rubyChecks,
      'RB006',
      'redirect_to params[:url]',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB006');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('ruby');
  });
});

// ---------------------------------------------------------------------------
// RB007 - Hardcoded Secret Key Base
// ---------------------------------------------------------------------------

describe('RB007 - Hardcoded Secret Key Base', () => {
  it('detects hardcoded secret_key_base', () => {
    const finding = testLine(
      rubyChecks,
      'RB007',
      'secret_key_base = "abc123longkey456"',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB007');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('ruby');
  });

  it('skips when value comes from ENV', () => {
    const finding = testLine(
      rubyChecks,
      'RB007',
      'secret_key_base = ENV["SECRET_KEY_BASE"]',
      'rb',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RB008 - Unsafe Deserialization
// ---------------------------------------------------------------------------

describe('RB008 - Unsafe Deserialization', () => {
  it('detects Marshal.load', () => {
    const finding = testLine(
      rubyChecks,
      'RB008',
      'Marshal.load(data)',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB008');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('ruby');
  });

  it('does not flag YAML.safe_load', () => {
    const finding = testLine(
      rubyChecks,
      'RB008',
      'YAML.safe_load(data)',
      'rb',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RB002 - Command Injection
// ---------------------------------------------------------------------------

describe('RB002 - Command Injection', () => {
  it('detects system() with string interpolation', () => {
    const finding = testLine(
      rubyChecks,
      'RB002',
      'system("cmd #{input}")',
      'rb',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('RB002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('ruby');
    expect(finding!.message).toContain('shell command');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag system() with a static string', () => {
    const finding = testLine(
      rubyChecks,
      'RB002',
      'system("ls -la")',
      'rb',
    );
    expect(finding).toBeNull();
  });
});
