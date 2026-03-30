import { describe, it, expect } from 'vitest';
import { dosChecks } from '../../src/checks/dos/index.js';
import { testLine, testFileCheck } from '../helpers.js';

describe('dos checks', () => {
  describe('DOS001 - ReDoS Vulnerable Pattern', () => {
    it('flags a regex with nested quantifiers', () => {
      const result = testLine(dosChecks, 'DOS001', `new RegExp('(a+)+b')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DOS001');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('dos');
      expect(result!.message).toContain('backtracking');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('DOS003 - Unbounded Database Query', () => {
    it('flags findMany with no limit', () => {
      const result = testLine(dosChecks, 'DOS003', `.findMany({})`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DOS003');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('dos');
      expect(result!.message).toContain('limit');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag findOne (single result)', () => {
      const result = testLine(dosChecks, 'DOS003', `.findOne({})`);
      expect(result).toBeNull();
    });
  });

  describe('DOS004 - Missing Body Size Limit', () => {
    it('flags express.json() with no limit', () => {
      const result = testLine(dosChecks, 'DOS004', `express.json()`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DOS004');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('dos');
    });

    it('does not flag express.json with a limit option', () => {
      const result = testLine(dosChecks, 'DOS004', `express.json({ limit: '1mb' })`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // DOS002 - No Request Timeout (FileCheck)
  // ---------------------------------------------------------------------------

  describe('DOS002 - No Request Timeout', () => {
    it('flags express app without timeout', async () => {
      const content = `const app = express();\napp.get('/', handler);\napp.listen(3000);`;
      const findings = await testFileCheck(dosChecks, 'DOS002', content);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('DOS002');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('dos');
    });

    it('does not flag when timeout is configured', async () => {
      const content = `const app = express();\nconst server = app.listen(3000);\nserver.timeout = 30000;`;
      const findings = await testFileCheck(dosChecks, 'DOS002', content);
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // DOS005 - Unbounded GraphQL Query Depth (FileCheck)
  // ---------------------------------------------------------------------------

  describe('DOS005 - Unbounded GraphQL Query Depth', () => {
    it('flags ApolloServer without depthLimit', async () => {
      const content = `import { ApolloServer } from '@apollo/server';\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n});`;
      const findings = await testFileCheck(dosChecks, 'DOS005', content);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('DOS005');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('dos');
    });

    it('does not flag ApolloServer with depthLimit', async () => {
      const content = `import { ApolloServer } from '@apollo/server';\nimport depthLimit from 'graphql-depth-limit';\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  validationRules: [depthLimit(10)],\n});`;
      const findings = await testFileCheck(dosChecks, 'DOS005', content);
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // DOS006 - No Connection Pool Limit
  // ---------------------------------------------------------------------------

  describe('DOS006 - No Connection Pool Limit', () => {
    it('flags Pool config without max', () => {
      const result = testLine(dosChecks, 'DOS006', `new Pool({ host: 'localhost' })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DOS006');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('dos');
    });

    it('does not flag Pool config with max', () => {
      const result = testLine(dosChecks, 'DOS006', 'new Pool({ max: 20 })');
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // DOS007 - Timer Duration from User Input
  // ---------------------------------------------------------------------------

  describe('DOS007 - Timer Duration from User Input', () => {
    it('flags setTimeout with user input delay', () => {
      const result = testLine(dosChecks, 'DOS007', 'setTimeout(callback, req.query.delay)');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('DOS007');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('dos');
    });

    it('does not flag setTimeout with static delay', () => {
      const result = testLine(dosChecks, 'DOS007', 'setTimeout(callback, 5000)');
      expect(result).toBeNull();
    });
  });

  describe('Regression: real-world false positives', () => {
    it('DOS002: does not flag Supabase createServerClient as HTTP server', async () => {
      const content = `import { createServerClient } from '@supabase/ssr';
export function createClient() {
  return createServerClient(url, key, { cookies: {} });
}`;
      const findings = await testFileCheck(dosChecks, 'DOS002', content);
      expect(findings).toHaveLength(0);
    });

    it('DOS003: does not flag Supabase .select() (field selection)', () => {
      const finding = testLine(dosChecks, 'DOS003', '.from("users").select("id, name").eq("active", true)');
      expect(finding).toBeNull();
    });
  });
});
