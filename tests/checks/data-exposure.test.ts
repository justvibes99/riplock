import { describe, it, expect } from 'vitest';
import { dataExposureChecks } from '../../src/checks/data-exposure/index.js';
import { testLine } from '../helpers.js';

describe('data-exposure checks', () => {
  describe('DATA001 - Secret Exposed via NEXT_PUBLIC_', () => {
    it('flags NEXT_PUBLIC_ with a secret-looking name', () => {
      const result = testLine(dataExposureChecks, 'DATA001', `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc`, 'env');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA001');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('data-exposure');
      expect(result!.message).toContain('NEXT_PUBLIC');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag NEXT_PUBLIC_ with a non-secret name', () => {
      const result = testLine(dataExposureChecks, 'DATA001', `NEXT_PUBLIC_API_URL=https://api.com`, 'env');
      expect(result).toBeNull();
    });
  });

  describe('DATA003 - Debug Endpoint Exposed', () => {
    it('flags a debug endpoint', () => {
      const result = testLine(dataExposureChecks, 'DATA003', `app.get('/debug/info', handler)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA003');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('data-exposure');
      expect(result!.message).toContain('Debug');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('DATA004 - All Environment Variables Sent in Response', () => {
    it('flags res.json(process.env)', () => {
      const result = testLine(dataExposureChecks, 'DATA004', `res.json(process.env)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA004');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('data-exposure');
    });
  });

  describe('DATA005 - Sensitive Data in Console Log', () => {
    it('flags console.log with token', () => {
      const result = testLine(dataExposureChecks, 'DATA005', `console.log('token:', token)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA005');
      expect(result!.severity).toBe('low');
      expect(result!.category).toBe('data-exposure');
    });
  });

  describe('DATA007 - Full DB Object in Response', () => {
    it('flags res.json(user)', () => {
      const result = testLine(dataExposureChecks, 'DATA007', `res.json(user)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA007');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('data-exposure');
    });
  });

  describe('DATA002 - Stack Trace in Response', () => {
    it('flags err.stack sent in res.json', () => {
      const result = testLine(dataExposureChecks, 'DATA002', `res.json({ error: err.stack })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA002');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('data-exposure');
    });

    it('does not flag err.stack in console.error (no response context)', () => {
      const result = testLine(dataExposureChecks, 'DATA002', `console.error(err.stack)`);
      expect(result).toBeNull();
    });
  });

  describe('DATA006 - Source Maps Enabled in Production', () => {
    it('flags productionBrowserSourceMaps: true', () => {
      const result = testLine(dataExposureChecks, 'DATA006', `productionBrowserSourceMaps: true`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA006');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('data-exposure');
    });

    it('does not flag productionBrowserSourceMaps: false', () => {
      const result = testLine(dataExposureChecks, 'DATA006', `productionBrowserSourceMaps: false`);
      expect(result).toBeNull();
    });
  });

  describe('DATA008 - Secrets in URL Query Parameters', () => {
    it('flags token in URL query string', () => {
      const result = testLine(dataExposureChecks, 'DATA008', 'fetch(`/api?token=${token}`)');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA008');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('data-exposure');
    });

    it('does not flag token in headers', () => {
      const result = testLine(dataExposureChecks, 'DATA008', `fetch('/api', { headers: { auth: token } })`);
      expect(result).toBeNull();
    });
  });

  describe('DATA009 - Error Component Leaks Error Details', () => {
    it('flags {error.message} in tsx file', () => {
      const result = testLine(dataExposureChecks, 'DATA009', `<p>{error.message}</p>`, 'tsx');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA009');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('data-exposure');
    });

    it('still matches in ts file (appliesTo filtering is done by the scanner, not the check)', () => {
      // DATA009 has appliesTo: ['tsx', 'jsx']. The scanner skips .ts files,
      // but the check itself does not enforce extension — so testLine still returns a finding.
      const result = testLine(dataExposureChecks, 'DATA009', `<p>{error.message}</p>`, 'ts');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DATA009');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('data-exposure');
    });
  });

  describe('Regression: real-world false positives', () => {
    it('DATA005: does not flag console.log with sensitive word only in string message', () => {
      const finding = testLine(dataExposureChecks, 'DATA005', "console.log('Authenticated as:', email)");
      expect(finding).toBeNull();
    });

    it('DATA005: does not flag console.log with auth in URL string', () => {
      const finding = testLine(dataExposureChecks, 'DATA005', "console.log('NOT logged in (redirected to auth page)')");
      expect(finding).toBeNull();
    });

    it('DATA005: still flags console.log with sensitive variable outside strings', () => {
      const finding = testLine(dataExposureChecks, 'DATA005', "console.log('user data:', token)");
      expect(finding).not.toBeNull();
      expect(finding!.checkId).toBe('DATA005');
      expect(finding!.severity).toBe('low');
      expect(finding!.category).toBe('data-exposure');
    });
  });
});
