import { describe, it, expect } from 'vitest';
import { networkChecks } from '../../src/checks/network/index.js';
import { testLine, testProjectCheck } from '../helpers.js';

describe('network checks', () => {
  describe('NET001 - Open CORS Policy', () => {
    it('flags origin: \'*\'', () => {
      const result = testLine(networkChecks, 'NET001', `origin: '*'`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET001');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('network');
      expect(result!.message).toContain('any website');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag a specific origin', () => {
      const result = testLine(networkChecks, 'NET001', `origin: 'https://myapp.com'`);
      expect(result).toBeNull();
    });
  });

  describe('NET004 - Insecure HTTP URL', () => {
    it('flags a non-localhost HTTP URL', () => {
      const result = testLine(networkChecks, 'NET004', `'http://api.example.com'`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET004');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('network');
      expect(result!.message).toContain('HTTP');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag localhost HTTP URL', () => {
      const result = testLine(networkChecks, 'NET004', `'http://localhost:3000'`);
      expect(result).toBeNull();
    });
  });

  describe('NET006 - cors() with No Arguments', () => {
    it('flags cors() called with no arguments', () => {
      const result = testLine(networkChecks, 'NET006', `cors()`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET006');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('network');
    });
  });

  describe('NET008 - CORS Origin Reflection', () => {
    it('flags origin set to req.headers.origin', () => {
      const result = testLine(networkChecks, 'NET008', `origin: req.headers.origin`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET008');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('network');
    });
  });

  // NET003 removed — duplicated by INJ014

  describe('NET005 - Internal URL in Client-Side Config', () => {
    it('flags NEXT_PUBLIC env var with internal IP', () => {
      const result = testLine(networkChecks, 'NET005', `NEXT_PUBLIC_API_URL = 'http://192.168.1.1:3000'`, 'tsx');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET005');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('network');
    });
  });

  describe('NET007 - MongoDB Without Auth', () => {
    it('flags mongodb connection string without credentials', () => {
      const result = testLine(networkChecks, 'NET007', `mongodb://localhost:27017/mydb"`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NET007');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('network');
    });

    it('does not flag mongodb connection with credentials', () => {
      const result = testLine(networkChecks, 'NET007', `"mongodb://user:pass@host:27017/db"`);
      expect(result).toBeNull();
    });
  });

  describe('NET002 - Missing Helmet (ProjectCheck)', () => {
    it('flags express project without helmet', async () => {
      const findings = await testProjectCheck(networkChecks, 'NET002', {
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.18.0' } },
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('NET002');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('network');
    });

    it('does not flag express project with helmet installed', async () => {
      const findings = await testProjectCheck(networkChecks, 'NET002', {
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.18.0', helmet: '^7.0.0' } },
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag project without express or fastify', async () => {
      const findings = await testProjectCheck(networkChecks, 'NET002', {
        detectedFrameworks: ['next'],
        packageJson: { dependencies: { next: '^14.0.0' } },
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('Regression: real-world false positives', () => {
    it('NET004: does not flag SVG namespace URI', () => {
      const finding = testLine(networkChecks, 'NET004', 'const svg = `<svg xmlns="http://www.w3.org/2000/svg">`');
      expect(finding).toBeNull();
    });
  });
});
