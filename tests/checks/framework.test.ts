import { describe, it, expect } from 'vitest';
import type { FileEntry, LineCheck, ProjectCheck, ScanContext } from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';
import { frameworkChecks } from '../../src/checks/framework/index.js';
import { testLine, testFileCheck, testProjectCheck } from '../helpers.js';

describe('framework checks', () => {
  describe('NEXT002 - Secret Exposed via NEXT_PUBLIC_', () => {
    it('flags NEXT_PUBLIC_STRIPE_SECRET in code', () => {
      const result = testLine(frameworkChecks, 'NEXT002', `const key = NEXT_PUBLIC_STRIPE_SECRET`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NEXT002');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('framework');
      expect(result!.message).toContain('NEXT_PUBLIC');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('REACT001 - javascript: URL in JSX', () => {
    it('flags href with javascript: protocol', () => {
      const result = testLine(frameworkChecks, 'REACT001', `href="javascript:alert(1)"`, 'tsx');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('REACT001');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('framework');
      expect(result!.message).toContain('javascript:');
      expect(result!.fix).toBeTruthy();
    });
  });

  // REACT002 removed — target="_blank" is handled by modern browsers since 2021

  describe('SUPABASE001 - dangerouslyAllowBrowser', () => {
    it('flags dangerouslyAllowBrowser: true', () => {
      const result = testLine(frameworkChecks, 'SUPABASE001', `dangerouslyAllowBrowser: true`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('SUPABASE001');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('framework');
    });
  });

  // ---------------------------------------------------------------------------
  // NEXT003 - Permissive remotePatterns
  // ---------------------------------------------------------------------------

  describe('NEXT003 - Permissive remotePatterns', () => {
    it('flags hostname wildcard **', () => {
      const result = testLine(frameworkChecks, 'NEXT003', `remotePatterns: [{ hostname: '**' }]`, 'js');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NEXT003');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('framework');
    });

    it('does not flag specific hostname', () => {
      const result = testLine(frameworkChecks, 'NEXT003', `remotePatterns: [{ hostname: 'cdn.example.com' }]`, 'js');
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // NEXT004 - Error Page Leaking Details
  // ---------------------------------------------------------------------------

  describe('NEXT004 - Error Page Leaking Details', () => {
    it('flags error.message in error.tsx', () => {
      const check = frameworkChecks.find((c) => c.id === 'NEXT004') as LineCheck;
      const file: FileEntry = {
        absolutePath: '/test/app/error.tsx',
        relativePath: 'app/error.tsx',
        sizeBytes: 100,
        extension: 'tsx',
        basename: 'error.tsx',
        content: '<p>{error.message}</p>',
        lines: ['<p>{error.message}</p>'],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(file.content!);
      expect(match).not.toBeNull();
      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze({ line: file.content!, lineNumber: 1, regexMatch: match!, file }, ctx);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('NEXT004');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('framework');
    });

    it('does not flag error.message in a regular file', () => {
      const check = frameworkChecks.find((c) => c.id === 'NEXT004') as LineCheck;
      const file: FileEntry = {
        absolutePath: '/test/components/form.tsx',
        relativePath: 'components/form.tsx',
        sizeBytes: 100,
        extension: 'tsx',
        basename: 'form.tsx',
        content: '<p>{error.message}</p>',
        lines: ['<p>{error.message}</p>'],
      };
      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(file.content!);
      expect(match).not.toBeNull();
      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze({ line: file.content!, lineNumber: 1, regexMatch: match!, file }, ctx);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // EXPRESS001 - Missing Body Parser Size Limit (FileCheck)
  // ---------------------------------------------------------------------------

  describe('EXPRESS001 - Missing Body Parser Size Limit', () => {
    it('flags express.json() without limit', async () => {
      const content = `const app = express();\napp.use(express.json());`;
      const findings = await testFileCheck(frameworkChecks, 'EXPRESS001', content);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('EXPRESS001');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag express.json with limit', async () => {
      const content = `const app = express();\napp.use(express.json({ limit: '1mb' }));`;
      const findings = await testFileCheck(frameworkChecks, 'EXPRESS001', content);
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // EXPRESS002 - Express Static Serves Dotfiles
  // ---------------------------------------------------------------------------

  describe('EXPRESS002 - Express Static Serves Dotfiles', () => {
    it('flags express.static without dotfiles option', () => {
      const result = testLine(frameworkChecks, 'EXPRESS002', `express.static('public')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('EXPRESS002');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('framework');
    });

    it('does not flag express.static with dotfiles deny', () => {
      const result = testLine(frameworkChecks, 'EXPRESS002', `express.static('public', { dotfiles: 'deny' })`);
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // EXPRESS003 - Express X-Powered-By (ProjectCheck)
  // ---------------------------------------------------------------------------

  describe('EXPRESS003 - Express X-Powered-By', () => {
    it('flags express app without helmet', async () => {
      const findings = await testProjectCheck(frameworkChecks, 'EXPRESS003', {
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0' } },
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('EXPRESS003');
      expect(findings[0].severity).toBe('low');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag when helmet is installed', async () => {
      const findings = await testProjectCheck(frameworkChecks, 'EXPRESS003', {
        detectedFrameworks: ['express'],
        packageJson: { dependencies: { express: '^4.0.0', helmet: '^7.0.0' } },
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // FIREBASE001 - Firebase Security Rules Wide Open (FileCheck)
  // ---------------------------------------------------------------------------

  describe('FIREBASE001 - Firebase Security Rules Wide Open', () => {
    it('flags allow read, write: if true in firestore.rules', async () => {
      const content = `rules_version = '2';\nservice cloud.firestore {\n  match /{document=**} {\n    allow read, write: if true;\n  }\n}`;
      const findings = await testFileCheck(frameworkChecks, 'FIREBASE001', content, {
        relativePath: 'firestore.rules',
        extension: 'rules',
        basename: 'firestore.rules',
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('FIREBASE001');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag proper authentication rules', async () => {
      const content = `rules_version = '2';\nservice cloud.firestore {\n  match /{document=**} {\n    allow read, write: if request.auth != null;\n  }\n}`;
      const findings = await testFileCheck(frameworkChecks, 'FIREBASE001', content, {
        relativePath: 'firestore.rules',
        extension: 'rules',
        basename: 'firestore.rules',
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // FIREBASE002 - Permissive Firebase Storage Rules (FileCheck)
  // ---------------------------------------------------------------------------

  describe('FIREBASE002 - Permissive Firebase Storage Rules', () => {
    it('flags allow read, write: if true in storage.rules', async () => {
      const content = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if true;\n    }\n  }\n}`;
      const findings = await testFileCheck(frameworkChecks, 'FIREBASE002', content, {
        relativePath: 'storage.rules',
        extension: 'rules',
        basename: 'storage.rules',
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('FIREBASE002');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag restricted storage rules', async () => {
      const content = `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if request.auth != null;\n    }\n  }\n}`;
      const findings = await testFileCheck(frameworkChecks, 'FIREBASE002', content, {
        relativePath: 'storage.rules',
        extension: 'rules',
        basename: 'storage.rules',
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // SUPABASE002 - Supabase RLS Not Enabled (ProjectCheck)
  // ---------------------------------------------------------------------------

  describe('SUPABASE002 - Supabase RLS Not Enabled', () => {
    it('flags SQL with CREATE TABLE but no RLS', async () => {
      const check = frameworkChecks.find((c) => c.id === 'SUPABASE002') as ProjectCheck;
      const sqlContent = `CREATE TABLE users (\n  id uuid PRIMARY KEY,\n  name text\n);`;
      const sqlFile: FileEntry = {
        absolutePath: '/test/migrations/001.sql',
        relativePath: 'migrations/001.sql',
        sizeBytes: sqlContent.length,
        extension: 'sql',
        basename: '001.sql',
        content: sqlContent,
        lines: sqlContent.split('\n'),
      };
      const ctx = {
        config: defaultConfig(),
        detectedFrameworks: [],
        packageJson: { dependencies: { '@supabase/supabase-js': '^2.0.0' }, devDependencies: {}, scripts: {}, raw: {} },
        files: new Map([['migrations/001.sql', sqlFile]]),
        filesByExtension: new Map([['sql', [sqlFile]]]),
        readFile: async () => sqlContent,
        readLines: async () => sqlContent.split('\n'),
      } as unknown as ScanContext;
      const findings = await check.analyze(ctx);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('SUPABASE002');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag when RLS is enabled', async () => {
      const check = frameworkChecks.find((c) => c.id === 'SUPABASE002') as ProjectCheck;
      const sqlContent = `CREATE TABLE users (\n  id uuid PRIMARY KEY\n);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;`;
      const sqlFile: FileEntry = {
        absolutePath: '/test/migrations/001.sql',
        relativePath: 'migrations/001.sql',
        sizeBytes: sqlContent.length,
        extension: 'sql',
        basename: '001.sql',
        content: sqlContent,
        lines: sqlContent.split('\n'),
      };
      const ctx = {
        config: defaultConfig(),
        detectedFrameworks: [],
        packageJson: { dependencies: { '@supabase/supabase-js': '^2.0.0' }, devDependencies: {}, scripts: {}, raw: {} },
        files: new Map([['migrations/001.sql', sqlFile]]),
        filesByExtension: new Map([['sql', [sqlFile]]]),
        readFile: async () => sqlContent,
        readLines: async () => sqlContent.split('\n'),
      } as unknown as ScanContext;
      const findings = await check.analyze(ctx);
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // SUPABASE003 - Service Key in Client Code (FileCheck)
  // ---------------------------------------------------------------------------

  describe('SUPABASE003 - Service Key in Client Code', () => {
    it('flags createClient with service_role in client file', async () => {
      const content = `'use client';\nimport { createClient } from '@supabase/supabase-js';\nconst supabase = createClient(url, service_role);`;
      const findings = await testFileCheck(frameworkChecks, 'SUPABASE003', content, {
        relativePath: 'components/db.ts',
        extension: 'ts',
        basename: 'db.ts',
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('SUPABASE003');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag createClient without service_role', async () => {
      const content = `'use client';\nimport { createClient } from '@supabase/supabase-js';\nconst supabase = createClient(url, anonKey);`;
      const findings = await testFileCheck(frameworkChecks, 'SUPABASE003', content, {
        relativePath: 'components/db.ts',
        extension: 'ts',
        basename: 'db.ts',
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // NEXT001 - Server Action Without Authentication (FileCheck)
  // ---------------------------------------------------------------------------

  describe('NEXT001 - Server Action Without Authentication', () => {
    it('flags use server without auth check', async () => {
      const content = `'use server';\n\nexport async function deleteUser(id: string) {\n  await db.user.delete({ where: { id } });\n}`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT001', content, {
        relativePath: 'app/actions.ts',
        extension: 'ts',
        basename: 'actions.ts',
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('NEXT001');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag use server with getServerSession', async () => {
      const content = `'use server';\nimport { getServerSession } from 'next-auth';\n\nexport async function deleteUser(id: string) {\n  const session = await getServerSession();\n  if (!session) throw new Error('Unauthorized');\n  await db.user.delete({ where: { id } });\n}`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT001', content, {
        relativePath: 'app/actions.ts',
        extension: 'ts',
        basename: 'actions.ts',
      });
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // NEXT005 - Middleware Without Matcher (FileCheck)
  // ---------------------------------------------------------------------------

  describe('NEXT005 - Middleware Without Matcher', () => {
    it('flags middleware.ts without config.matcher', async () => {
      const content = `import { NextResponse } from 'next/server';\n\nexport function middleware(request) {\n  return NextResponse.next();\n}`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT005', content, {
        relativePath: 'middleware.ts',
        extension: 'ts',
        basename: 'middleware.ts',
      });
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('NEXT005');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('framework');
    });

    it('does not flag middleware.ts with matcher', async () => {
      const content = `import { NextResponse } from 'next/server';\n\nexport function middleware(request) {\n  return NextResponse.next();\n}\n\nexport const config = {\n  matcher: ['/dashboard/:path*'],\n};`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT005', content, {
        relativePath: 'middleware.ts',
        extension: 'ts',
        basename: 'middleware.ts',
      });
      expect(findings.length).toBe(0);
    });
  });

  describe('Regression: real-world false positives', () => {
    it('NEXT001: skips login page server actions', async () => {
      const content = `'use server';
export async function login(formData: FormData) {
  const email = formData.get('email');
  await signIn('credentials', { email });
}`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT001', content, {
        relativePath: 'src/app/login/page.tsx',
        extension: 'tsx',
      });
      expect(findings).toHaveLength(0);
    });

    it('NEXT001: skips signup page server actions', async () => {
      const content = `'use server';
export async function signup(formData: FormData) {
  const email = formData.get('email');
}`;
      const findings = await testFileCheck(frameworkChecks, 'NEXT001', content, {
        relativePath: 'src/app/signup/actions.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // GQL001 - GraphQL Without Rate Limiting
  // ---------------------------------------------------------------------------

  describe('GQL001 - GraphQL Without Rate Limiting', () => {
    it('flags type Query { in a graphql file without rate limiting', () => {
      const check = frameworkChecks.find((c) => c.id === 'GQL001') as LineCheck;
      const content = `type Query {\n  users: [User]\n  posts: [Post]\n}`;
      const line = 'type Query {';

      const file: FileEntry = {
        absolutePath: '/test/schema.graphql',
        relativePath: 'schema.graphql',
        sizeBytes: content.length,
        extension: 'graphql',
        basename: 'schema.graphql',
        content,
        lines: content.split('\n'),
      };

      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      expect(match).not.toBeNull();

      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze(
        { line, lineNumber: 1, regexMatch: match!, file },
        ctx,
      );
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('GQL001');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('framework');
    });

    it('does not flag when file has complexity analysis reference', () => {
      const check = frameworkChecks.find((c) => c.id === 'GQL001') as LineCheck;
      const content = `type Query {\n  users: [User]\n}\n// depthLimit(10)`;
      const line = 'type Query {';

      const file: FileEntry = {
        absolutePath: '/test/schema.graphql',
        relativePath: 'schema.graphql',
        sizeBytes: content.length,
        extension: 'graphql',
        basename: 'schema.graphql',
        content,
        lines: content.split('\n'),
      };

      check.pattern.lastIndex = 0;
      const match = check.pattern.exec(line);
      expect(match).not.toBeNull();

      const ctx = { config: defaultConfig() } as ScanContext;
      const result = check.analyze(
        { line, lineNumber: 1, regexMatch: match!, file },
        ctx,
      );
      expect(result).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // GQL002 - Sensitive Field in GraphQL Schema
  // ---------------------------------------------------------------------------

  describe('GQL002 - Sensitive Field in GraphQL Schema', () => {
    it('flags password: String in a graphql file', () => {
      const result = testLine(frameworkChecks, 'GQL002', 'password: String', 'graphql');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('GQL002');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('framework');
    });

    it('does not flag name: String', () => {
      const result = testLine(frameworkChecks, 'GQL002', 'name: String', 'graphql');
      expect(result).toBeNull();
    });
  });
});
