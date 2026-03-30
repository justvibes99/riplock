import { describe, it, expect } from 'vitest';
import type { FileEntry, LineCheck, ScanContext } from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';
import { configChecks } from '../../src/checks/config/index.js';
import { testLine, testProjectCheck } from '../helpers.js';

describe('config checks', () => {
  describe('CONFIG001 - Debug Mode Enabled', () => {
    it('flags unconditional debug: true', () => {
      const result = testLine(configChecks, 'CONFIG001', `debug: true`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG001');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('config');
      expect(result!.message).toContain('Debug');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag debug conditioned on NODE_ENV', () => {
      const result = testLine(configChecks, 'CONFIG001', `debug: process.env.NODE_ENV !== 'production' ? true : false`);
      expect(result).toBeNull();
    });
  });

  describe('CONFIG002 - Default Credentials', () => {
    it('flags hardcoded default password', () => {
      const result = testLine(configChecks, 'CONFIG002', `password: 'admin'`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG002');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('config');
      expect(result!.message).toContain('credential');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('CONFIG004 - GraphQL Playground Enabled', () => {
    it('flags playground: true unconditionally', () => {
      const result = testLine(configChecks, 'CONFIG004', `playground: true`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG004');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('config');
    });

    it('does not flag playground conditioned on NODE_ENV', () => {
      const result = testLine(configChecks, 'CONFIG004', `playground: process.env.NODE_ENV !== 'production'`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG003 - Missing Content Security Policy (ProjectCheck)
  // ---------------------------------------------------------------------------

  describe('CONFIG003 - Missing Content Security Policy', () => {
    it('flags express app without CSP', async () => {
      const findings = await testProjectCheck(configChecks, 'CONFIG003', {
        files: { 'server.ts': `const app = express();\napp.get('/', handler);` },
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('CONFIG003');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('config');
    });

    it('does not flag when CSP is configured', async () => {
      const findings = await testProjectCheck(configChecks, 'CONFIG003', {
        files: { 'server.ts': `const app = express();\napp.use(helmet());\n// Content-Security-Policy configured` },
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG005 - Prisma Studio Exposed
  // ---------------------------------------------------------------------------

  describe('CONFIG005 - Prisma Studio Exposed', () => {
    it('flags prisma studio in start script', () => {
      const result = testLine(configChecks, 'CONFIG005', `"start": "prisma studio & node server.js"`, 'json');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG005');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('config');
    });

    it('does not flag prisma studio in dev:studio script', () => {
      const result = testLine(configChecks, 'CONFIG005', `"dev:studio": "prisma studio"`, 'json');
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG006 - Serving Root Directory as Static Files
  // ---------------------------------------------------------------------------

  describe('CONFIG006 - Serving Root Directory', () => {
    it('flags express.static with root dir', () => {
      const result = testLine(configChecks, 'CONFIG006', `express.static('.')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG006');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('config');
    });

    it('does not flag express.static with public dir', () => {
      const result = testLine(configChecks, 'CONFIG006', `express.static('public')`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG007 - Secrets in Deployment Config
  // ---------------------------------------------------------------------------

  describe('CONFIG007 - Secrets in Deployment Config', () => {
    it('flags secret in vercel.json', () => {
      const check = configChecks.find((c) => c.id === 'CONFIG007') as LineCheck;
      const line = `"SECRET_KEY": "mysecret123456"`;
      const file: FileEntry = {
        absolutePath: '/test/vercel.json',
        relativePath: 'vercel.json',
        sizeBytes: 100,
        extension: 'json',
        basename: 'vercel.json',
        content: line,
        lines: [line],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      expect(match).not.toBeNull();
      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze({ line, lineNumber: 1, regexMatch: match!, file }, ctx);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG007');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('config');
    });

    it('does not flag same pattern in a regular file', () => {
      const check = configChecks.find((c) => c.id === 'CONFIG007') as LineCheck;
      const line = `"SECRET_KEY": "mysecret123456"`;
      const file: FileEntry = {
        absolutePath: '/test/config.json',
        relativePath: 'config.json',
        sizeBytes: 100,
        extension: 'json',
        basename: 'config.json',
        content: line,
        lines: [line],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      expect(match).not.toBeNull();
      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze({ line, lineNumber: 1, regexMatch: match!, file }, ctx);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG008 - Exposed Swagger/OpenAPI Docs
  // ---------------------------------------------------------------------------

  describe('CONFIG008 - Exposed Swagger/OpenAPI Docs', () => {
    it('flags swagger-ui without NODE_ENV check', () => {
      const result = testLine(configChecks, 'CONFIG008', `app.use('/api-docs', swagger-ui.serve, swagger-ui.setup(spec))`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG008');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('config');
    });

    it('does not flag swagger-ui with NODE_ENV check', () => {
      const result = testLine(configChecks, 'CONFIG008', `if (process.env.NODE_ENV !== 'production') app.use(swagger-ui)`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG009 - Public S3 Bucket Config
  // ---------------------------------------------------------------------------

  describe('CONFIG009 - Public S3 Bucket Config', () => {
    it('flags ACL public-read-write', () => {
      const result = testLine(configChecks, 'CONFIG009', `ACL: 'public-read-write'`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG009');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('config');
    });

    it('does not flag ACL private', () => {
      const result = testLine(configChecks, 'CONFIG009', `ACL: 'private'`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG010 - Drizzle Studio Exposed
  // ---------------------------------------------------------------------------

  describe('CONFIG010 - Drizzle Studio Exposed', () => {
    it('flags drizzle-kit studio in start script in package.json', () => {
      const check = configChecks.find((c) => c.id === 'CONFIG010') as LineCheck;
      const line = `"start": "drizzle-kit studio & node server.js"`;
      const file: FileEntry = {
        absolutePath: '/test/package.json',
        relativePath: 'package.json',
        sizeBytes: 100,
        extension: 'json',
        basename: 'package.json',
        content: line,
        lines: [line],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      expect(match).not.toBeNull();
      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze({ line, lineNumber: 1, regexMatch: match!, file }, ctx);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CONFIG010');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('config');
    });

    it('does not flag drizzle-kit studio in non-start scripts', () => {
      const check = configChecks.find((c) => c.id === 'CONFIG010') as LineCheck;
      const line = `"dev:studio": "drizzle-kit studio"`;
      const file: FileEntry = {
        absolutePath: '/test/package.json',
        relativePath: 'package.json',
        sizeBytes: 100,
        extension: 'json',
        basename: 'package.json',
        content: line,
        lines: [line],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      // The pattern specifically matches "start": ... drizzle-kit studio, so it should not match
      expect(match).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG012 - No Error Monitoring (ProjectCheck)
  // ---------------------------------------------------------------------------

  describe('CONFIG012 - No Error Monitoring', () => {
    it('flags project with 50+ files but no monitoring service', async () => {
      // Create a file map with 50+ files
      const files: Record<string, string> = {};
      for (let i = 0; i < 55; i++) {
        files[`src/file${i}.ts`] = `export const x${i} = ${i};`;
      }
      const findings = await testProjectCheck(configChecks, 'CONFIG012', {
        files,
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('CONFIG012');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('config');
      expect(findings[0].message).toContain('error monitoring');
    });

    it('does not flag project with @sentry/node', async () => {
      const files: Record<string, string> = {};
      for (let i = 0; i < 55; i++) {
        files[`src/file${i}.ts`] = `export const x${i} = ${i};`;
      }
      const findings = await testProjectCheck(configChecks, 'CONFIG012', {
        files,
        packageJson: { dependencies: { express: '^4.0.0', '@sentry/node': '^7.0.0' } },
      });
      expect(findings.length).toBe(0);
    });

    it('does not flag small project without monitoring', async () => {
      const findings = await testProjectCheck(configChecks, 'CONFIG012', {
        files: { 'index.ts': 'console.log("hello")' },
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // CONFIG011 - Missing Permissions-Policy Header (ProjectCheck)
  // ---------------------------------------------------------------------------

  describe('CONFIG011 - Missing Permissions-Policy Header', () => {
    it('flags web app without Permissions-Policy', async () => {
      const findings = await testProjectCheck(configChecks, 'CONFIG011', {
        files: { 'server.ts': `const app = express();\napp.get('/', handler);` },
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('CONFIG011');
      expect(findings[0].severity).toBe('low');
      expect(findings[0].category).toBe('config');
    });

    it('does not flag when Permissions-Policy is set', async () => {
      const findings = await testProjectCheck(configChecks, 'CONFIG011', {
        files: { 'server.ts': `const app = express();\nres.setHeader('Permissions-Policy', 'camera=()');` },
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(0);
    });
  });
});
