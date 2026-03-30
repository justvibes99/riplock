import type {
  CheckDefinition,
  LineCheck,
  LineMatch,
  ProjectCheck,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck, isCommentLine } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const configChecks: CheckDefinition[] = [
  // CONFIG001 - Debug Mode Enabled
  createLineCheck({
    id: 'CONFIG001',
    name: 'Debug Mode Enabled',
    category: 'config',
    severity: 'medium',
    pattern: /(?:debug|DEBUG)\s*[=:]\s*(?:true|1|['"]true['"])/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // Skip if it is conditioned on NODE_ENV
      if (lower.includes('node_env')) return false;
      if (lower.includes('process.env')) return false;
      // Skip ternary expressions that check environment
      if (/\?\s*true\s*:\s*false/.test(line)) return false;
      if (/\?\s*false\s*:\s*true/.test(line)) return false;
      return true;
    },
    message:
      'Debug mode is enabled unconditionally. This may expose detailed error messages and internal information to users in production.',
    fix: 'Only enable debug mode in development. Condition it on the environment.',
    fixCode: `// Dangerous:
const config = { debug: true };

// Safe - only in development:
const config = { debug: process.env.NODE_ENV !== 'production' };`,
  }),

  // CONFIG002 - Default Credentials (LineCheck)
  createLineCheck({
    id: 'CONFIG002',
    name: 'Default Credentials',
    category: 'config',
    severity: 'high',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"](?:admin|root|password|123456|test|pass|changeme|default|qwerty|letmein)['"]/gi,
    appliesTo: ['js', 'ts', 'json', 'yaml', 'yml'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // Check if there is also a default-looking username on the same line
      const hasDefaultUser =
        /(?:username|user)\s*[=:]\s*['"](?:admin|root|sa|postgres|test|user)['"]/i.test(line);
      // Also flag standalone default passwords even without a username
      const hasDefaultPassword =
        /(?:password|passwd|pwd)\s*[=:]\s*['"](?:admin|root|password|123456|test|pass|changeme|default|qwerty|letmein)['"]/i.test(line);
      return hasDefaultUser || hasDefaultPassword;
    },
    message:
      'Default or common credentials found. Attackers try common username/password combinations first and automated tools scan for these.',
    fix: '1. Remove hardcoded credentials from source code.\n2. Use environment variables for all credentials.\n3. Require strong passwords in production.',
    fixCode: `// Dangerous:
const dbConfig = { user: 'admin', password: 'admin' };

// Safe - use environment variables:
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
};`,
  }),

  // CONFIG003 - Missing Content Security Policy (ProjectCheck)
  {
    level: 'project',
    id: 'CONFIG003',
    name: 'Missing Content Security Policy',
    description: 'No Content Security Policy found in a web application.',
    category: 'config',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      // Only flag if this looks like an Express or Next.js app
      const hasWebFramework =
        ctx.detectedFrameworks.includes('express') ||
        ctx.detectedFrameworks.includes('nextjs') ||
        ctx.detectedFrameworks.includes('koa') ||
        ctx.detectedFrameworks.includes('hapi');

      if (!hasWebFramework) return [];

      // Search all files for CSP references
      const cspPatterns =
        /(?:Content-Security-Policy|contentSecurityPolicy|csp|helmet\s*\()/i;

      for (const file of ctx.files.values()) {
        const content = await ctx.readFile(file.absolutePath);
        if (content && cspPatterns.test(content)) {
          return []; // CSP is configured somewhere
        }
      }

      return [
        {
          checkId: 'CONFIG003',
          title: 'Missing Content Security Policy',
          message:
            'No Content Security Policy found. CSP prevents XSS by controlling which scripts, styles, and resources can load on your page.',
          severity: ctx.config.severityOverrides.get('CONFIG003') ?? 'medium',
          category: 'config',
          fix: 'Add a Content Security Policy header using helmet or a manual header.',
          fixCode: `// Using helmet (recommended):
import helmet from 'helmet';
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));

// Or set the header manually:
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'"
  );
  next();
});`,
        },
      ];
    },
  } satisfies ProjectCheck,

  // CONFIG004 - GraphQL Playground in Production
  createLineCheck({
    id: 'CONFIG004',
    name: 'GraphQL Playground Enabled',
    category: 'config',
    severity: 'medium',
    pattern: /(?:playground|graphiql)\s*:\s*true/gi,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // Skip if wrapped in NODE_ENV check
      if (lower.includes('node_env')) return false;
      if (lower.includes('process.env')) return false;
      if (lower.includes('__dev__')) return false;
      return true;
    },
    message:
      'GraphQL playground or GraphiQL is enabled unconditionally. In production, it lets anyone explore and query your entire API schema.',
    fix: 'Only enable the playground in development environments.',
    fixCode: `// Dangerous:
const server = new ApolloServer({
  playground: true,
});

// Safe - only in development:
const server = new ApolloServer({
  playground: process.env.NODE_ENV !== 'production',
});`,
  }),

  // CONFIG005 - Exposed Prisma Studio
  createLineCheck({
    id: 'CONFIG005',
    name: 'Prisma Studio Exposed',
    category: 'config',
    severity: 'high',
    pattern: /prisma\s+studio|PRISMA_STUDIO/g,
    appliesTo: ['js', 'ts', 'json'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // In package.json scripts, flag if it looks like a start/production script
      if (lower.includes('"start"') || lower.includes('"prod"')) return true;
      // In code, flag if it looks like it is being spawned or configured
      if (lower.includes('exec') || lower.includes('spawn')) return true;
      // In package.json, flag "studio" script without dev qualifier
      if (lower.includes('"studio"')) return false; // dev script is fine
      if (lower.includes('"dev:studio"')) return false;
      return true;
    },
    message:
      'Prisma Studio gives direct database access through a web UI. Make sure it is never exposed in production or on a public network.',
    fix: '1. Only run Prisma Studio locally during development.\n2. Never include it in production start scripts.\n3. If you must run it remotely, put it behind authentication and restrict access by IP.',
    fixCode: `// Dangerous - in package.json:
"start": "prisma studio & node server.js"

// Safe - keep it as a separate dev script:
"dev:studio": "prisma studio"
// And never run it in production`,
  }),

  // CONFIG006 - Wildcard Static Serving
  createLineCheck({
    id: 'CONFIG006',
    name: 'Serving Root Directory as Static Files',
    category: 'config',
    severity: 'medium',
    pattern: /express\.static\s*\(\s*['"]\.?\/?['"]\s*\)/g,
    appliesTo: ['js', 'ts'],
    message:
      'You are serving the entire project directory as static files. This exposes source code, .env files, configuration, and other secrets to anyone who requests them.',
    fix: 'Only serve a specific public directory, never the project root.',
    fixCode: `// Dangerous - serves everything:
app.use(express.static('.'));
app.use(express.static('/'));

// Safe - serve only the public directory:
app.use(express.static('public'));`,
  }),

  // CONFIG007 - Secrets in Deployment Config
  {
    level: 'line',
    id: 'CONFIG007',
    name: 'Secrets in Deployment Config',
    description:
      'Secrets hardcoded in deployment config files like vercel.json or netlify.toml.',
    category: 'config',
    defaultSeverity: 'high',
    appliesTo: ['json', 'toml'],
    pattern: /["'](?:SECRET|TOKEN|PASSWORD|KEY|PRIVATE|SERVICE_ROLE)[^"']*["']\s*:\s*["'][^"']{8,}["']/gi,
    analyze(match: LineMatch, ctx: ScanContext): Finding | null {
      if (isCommentLine(match.line)) return null;

      // Only flag in deployment config files
      const basename = match.file.basename.toLowerCase();
      if (basename !== 'vercel.json' && basename !== 'netlify.toml') {
        return null;
      }

      const lines = match.file.lines ?? [];
      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        match.lineNumber,
        ctx.config.contextLines,
      );

      return {
        checkId: 'CONFIG007',
        title: 'Secrets in Deployment Config',
        message:
          'Deployment config files are committed to git. Secrets here are visible to anyone with repo access.',
        severity: ctx.config.severityOverrides.get('CONFIG007') ?? 'high',
        category: 'config',
        location: {
          filePath: match.file.relativePath,
          startLine: match.lineNumber,
          startColumn: match.regexMatch.index,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: '1. Move secrets to environment variables configured in your deployment platform\'s dashboard.\n2. Use references to environment variables instead of raw values.\n3. Add deployment config files to .gitignore if they contain secrets.',
        fixCode: `// Dangerous - in vercel.json:
{
  "env": {
    "SECRET_KEY": "sk_live_abc123xyz..."
  }
}

// Safe - reference environment variables:
{
  "env": {
    "SECRET_KEY": "@secret-key"
  }
}
// Set the actual value in your deployment platform's dashboard`,
      };
    },
  } satisfies LineCheck,

  // CONFIG008 - Exposed Swagger/OpenAPI Docs (LineCheck)
  createLineCheck({
    id: 'CONFIG008',
    name: 'Exposed Swagger/OpenAPI Docs',
    category: 'config',
    severity: 'medium',
    pattern: /(?:swagger-ui|swaggerUi|swagger\.setup|openapiSpecification)|app\.use\s*\(\s*['"]\/(?:api-docs|swagger|docs)['"]/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      if (lower.includes('node_env')) return false;
      if (lower.includes('process.env')) return false;
      if (lower.includes('__dev__')) return false;
      return true;
    },
    message:
      'API documentation is exposed without environment gating. Attackers use it to discover all your endpoints.',
    fix: 'Only expose Swagger/OpenAPI docs in development or behind authentication.',
    fixCode: `// Dangerous:
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(spec));

// Safe - only in development:
if (process.env.NODE_ENV !== 'production') {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(spec));
}`,
  }),

  // CONFIG009 - Public S3 Bucket Config (LineCheck)
  createLineCheck({
    id: 'CONFIG009',
    name: 'Public S3 Bucket Config',
    category: 'config',
    severity: 'high',
    pattern: /ACL\s*:\s*['"]public-read-write['"]|(?:blockPublicAccess|BlockPublicAccess)\s*.*false/gi,
    appliesTo: ['js', 'ts'],
    message:
      'S3 bucket is configured for public write access. Anyone on the internet can upload or overwrite files.',
    fix: 'Remove public-read-write ACL and enable BlockPublicAccess.',
    fixCode: `// Dangerous:
{ ACL: 'public-read-write' }
{ blockPublicAccess: false }

// Safe:
{ ACL: 'private' }
{ BlockPublicAccess: { BlockPublicAcls: true, BlockPublicPolicy: true } }`,
  }),

  // CONFIG010 - Drizzle Studio Exposed (LineCheck)
  createLineCheck({
    id: 'CONFIG010',
    name: 'Drizzle Studio Exposed',
    category: 'config',
    severity: 'high',
    pattern: /["']start["']\s*:.*drizzle-kit\s+studio/g,
    appliesTo: ['json'],
    validate(_match, _line) {
      // This pattern is specific to package.json start scripts — no extra validation needed
      return true;
    },
    message:
      'Drizzle Studio (database GUI) is in the start script. This exposes direct database access in production.',
    fix: 'Move Drizzle Studio to a dev-only script and never run it in production.',
    fixCode: `// Dangerous - in package.json:
"start": "drizzle-kit studio & node server.js"

// Safe - keep it separate:
"dev:studio": "drizzle-kit studio"`,
  }),

  // CONFIG012 - No Error Monitoring (ProjectCheck)
  {
    level: 'project',
    id: 'CONFIG012',
    name: 'No Error Monitoring',
    description:
      'No error monitoring service detected in a project with many files.',
    category: 'config',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      if (!ctx.packageJson) return [];

      // Only flag projects with 50+ files
      if (ctx.files.size < 50) return [];

      const allDeps = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };

      const monitoringServices = [
        '@sentry/node',
        '@sentry/nextjs',
        '@sentry/react',
        'newrelic',
        '@datadog/dd-trace',
        '@bugsnag/node',
        '@bugsnag/js',
        'bugsnag',
        'rollbar',
        'logrocket',
        '@honeycomb-io/opentelemetry-node',
      ];

      if (monitoringServices.some((svc) => svc in allDeps)) return [];

      return [
        {
          checkId: 'CONFIG012',
          title: 'No Error Monitoring',
          message:
            'No error monitoring service detected. Errors in production will go unnoticed. Consider Sentry, Datadog, or similar.',
          severity: ctx.config.severityOverrides.get('CONFIG012') ?? 'medium',
          category: 'config',
          fix: 'Add an error monitoring service like Sentry, Datadog, or Bugsnag to catch production errors.',
          fixCode: `// Using Sentry (recommended):
npm install @sentry/node

// In your app entry point:
import * as Sentry from '@sentry/node';
Sentry.init({ dsn: process.env.SENTRY_DSN });`,
        },
      ];
    },
  } satisfies ProjectCheck,

  // CONFIG011 - Missing Permissions-Policy Header (ProjectCheck)
  {
    level: 'project',
    id: 'CONFIG011',
    name: 'Missing Permissions-Policy Header',
    description:
      'No Permissions-Policy header found in a web application, allowing unrestricted access to browser features.',
    category: 'config',
    defaultSeverity: 'low',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      // Only flag if a web framework is detected
      const webFrameworks = ['express', 'nextjs', 'fastify', 'koa', 'hono'];
      const hasWebFramework = ctx.detectedFrameworks.some((f) =>
        webFrameworks.includes(f.toLowerCase()),
      );
      if (!hasWebFramework) return [];

      // Search all files for Permissions-Policy references
      const policyPatterns =
        /(?:Permissions-Policy|Feature-Policy|permissionsPolicy)/i;

      for (const file of ctx.files.values()) {
        const content = await ctx.readFile(file.absolutePath);
        if (content && policyPatterns.test(content)) {
          return []; // Policy is configured somewhere
        }
      }

      return [
        {
          checkId: 'CONFIG011',
          title: 'Missing Permissions-Policy Header',
          message:
            "No Permissions-Policy header found. This header controls which browser features (camera, microphone, geolocation) your site can use, preventing malicious scripts from accessing them.",
          severity: ctx.config.severityOverrides.get('CONFIG011') ?? 'low',
          category: 'config',
          fix: 'Add a Permissions-Policy header using helmet or set it manually. Disable browser features you do not use.',
          fixCode: `// Using helmet (recommended):
import helmet from 'helmet';
app.use(helmet({
  permissionsPolicy: {
    features: {
      camera: ["'none'"],
      microphone: ["'none'"],
      geolocation: ["'self'"],
    },
  },
}));

// Or set the header manually:
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(self)'
  );
  next();
});`,
        },
      ];
    },
  } satisfies ProjectCheck,
];
