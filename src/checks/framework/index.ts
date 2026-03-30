import type {
  CheckDefinition,
  FileCheck,
  ProjectCheck,
  FileEntry,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck, isCommentLine } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---------------------------------------------------------------------------
// Next.js checks
// ---------------------------------------------------------------------------

// NEXT001 - Server Action without authentication
const next001: FileCheck = {
  level: 'file',
  id: 'NEXT001',
  name: 'Server Action Without Authentication',
  description:
    'Detects Next.js Server Actions that do not check authentication, allowing unauthenticated access.',
  category: 'framework',
  defaultSeverity: 'high',
  appliesTo: ['js', 'ts', 'jsx', 'tsx'],
  fastFilter: 'use server',
  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    const content = file.content ?? await ctx.readFile(file.absolutePath);
    const lines = file.lines ?? await ctx.readLines(file.absolutePath);

    // Check if this file contains 'use server' (directive or inline)
    if (!content.includes("'use server'") && !content.includes('"use server"')) {
      return [];
    }

    // Skip auth-related pages — login/signup/register pages don't need auth
    const pathLower = file.relativePath.toLowerCase();
    if (/(?:login|signin|sign-in|signup|sign-up|register|forgot|reset-password|verify|onboarding)/.test(pathLower)) {
      return [];
    }

    // Auth-related identifiers commonly used in Next.js apps
    const AUTH_PATTERNS = [
      'getSession',
      'getServerSession',
      'auth(',
      'auth()',
      'currentUser',
      'getUser',
      'requireAuth',
      'requireSession',
      'withAuth',
      'getToken',
      'verifyToken',
      'cookies()',
      'headers()',
    ];

    const hasAuth = AUTH_PATTERNS.some((pattern) => content.includes(pattern));
    if (hasAuth) return [];

    // Find the line with 'use server' for the finding location
    let directiveLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes("'use server'") || lines[i].includes('"use server"')) {
        directiveLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      directiveLine,
      ctx.config.contextLines,
    );

    const severity = ctx.config.severityOverrides.get('NEXT001') ?? 'high';

    return [
      {
        checkId: 'NEXT001',
        title: 'Server Action without authentication',
        message:
          'This Server Action has no authentication check. Server Actions are public HTTP endpoints, and anyone can call them directly without going through your UI.',
        severity,
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: directiveLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: '1. Add an authentication check at the top of every Server Action.\n2. Use getServerSession(), auth(), or your auth library to verify the user.\n3. Return an error or redirect if the user is not authenticated.',
        fixCode: `'use server';
import { getServerSession } from 'next-auth';

export async function myAction(formData: FormData) {
  const session = await getServerSession();
  if (!session) throw new Error('Unauthorized');

  // ... action logic
}`,
      },
    ];
  },
};

// NEXT002 - NEXT_PUBLIC_ secret
const next002 = createLineCheck({
  id: 'NEXT002',
  name: 'Secret Exposed via NEXT_PUBLIC_',
  category: 'framework',
  severity: 'critical',
  pattern: /NEXT_PUBLIC_(?:SECRET|PRIVATE|DB_|DATABASE|STRIPE_SECRET|SUPABASE_SERVICE)/g,
  message:
    'NEXT_PUBLIC_ environment variables are bundled into the browser JavaScript and visible to every visitor. This variable name suggests it contains a secret that should be server-only.',
  fix: '1. Remove the NEXT_PUBLIC_ prefix so the variable is only available on the server.\n2. Access it in Server Components, API routes, or Server Actions instead of client components.',
  fixCode: `// Dangerous - exposed to browser:
// NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...

// Safe - server-only (no NEXT_PUBLIC_ prefix):
// STRIPE_SECRET_KEY=sk_live_...
// Access in server code: process.env.STRIPE_SECRET_KEY`,
});

// ---------------------------------------------------------------------------
// Express checks
// ---------------------------------------------------------------------------

// EXPRESS001 - Missing body parser limit
const express001: FileCheck = {
  level: 'file',
  id: 'EXPRESS001',
  name: 'Missing Body Parser Size Limit',
  description:
    'Detects Express body parsers (express.json, bodyParser.json) without a size limit.',
  category: 'framework',
  defaultSeverity: 'medium',
  appliesTo: ['js', 'ts'],
  fastFilter: /bodyParser|express\.json|express\.urlencoded/,
  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    const lines = file.lines ?? await ctx.readLines(file.absolutePath);
    const findings: Finding[] = [];

    // Patterns that set up body parsing
    const PARSER_RE =
      /(?:express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(/g;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isCommentLine(line)) continue;

      PARSER_RE.lastIndex = 0;
      const match = PARSER_RE.exec(line);
      if (!match) continue;

      // Check if a 'limit' option is present on this line or the next few lines
      // (in case of multi-line calls)
      const nearby = lines.slice(i, Math.min(i + 5, lines.length)).join(' ');
      if (/limit\s*:/.test(nearby)) continue;

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        i + 1,
        ctx.config.contextLines,
      );

      const severity =
        ctx.config.severityOverrides.get('EXPRESS001') ?? 'medium';

      findings.push({
        checkId: 'EXPRESS001',
        title: 'Missing body parser size limit',
        message:
          'No size limit on request bodies. An attacker can send huge payloads to exhaust memory and crash your server.',
        severity,
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: i + 1,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: 'Add a limit option to the body parser. A reasonable default is 1mb.',
        fixCode: `// Dangerous - no limit:
app.use(express.json());

// Safe - with limit:
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));`,
      });
    }

    return findings;
  },
};

// EXPRESS002 - Express static serves dotfiles
const express002 = createLineCheck({
  id: 'EXPRESS002',
  name: 'Express Static Serves Dotfiles',
  category: 'framework',
  severity: 'medium',
  appliesTo: ['js', 'ts'],
  pattern: /express\.static\s*\(/g,
  validate(_match, line) {
    // Flag only if there's no dotfiles: 'deny' option
    // Check the line and a reasonable surrounding context
    if (/dotfiles\s*:\s*['"]deny['"]/.test(line)) return false;
    if (/dotfiles\s*:\s*['"]ignore['"]/.test(line)) return false;
    return true;
  },
  message:
    'Express serves static files including dotfiles (.env, .git, .htpasswd) by default. An attacker can request /.env to read your secrets.',
  fix: 'Set the dotfiles option to "deny" to block access to dotfiles.',
  fixCode: `// Dangerous - dotfiles accessible:
app.use(express.static('public'));

// Safe - block dotfiles:
app.use(express.static('public', { dotfiles: 'deny' }));`,
});

// ---------------------------------------------------------------------------
// React checks
// ---------------------------------------------------------------------------

// REACT001 - javascript: URL
const react001 = createLineCheck({
  id: 'REACT001',
  name: 'javascript: URL in JSX',
  category: 'framework',
  severity: 'high',
  appliesTo: ['jsx', 'tsx'],
  pattern: /(?:href|src|action)\s*=\s*[{'"]\s*(?:javascript:|['"]javascript:)/gi,
  message:
    'javascript: URLs execute arbitrary code and bypass React\'s built-in XSS protection. If user input reaches this attribute, an attacker can run scripts in the context of your page.',
  fix: '1. Never use javascript: URLs. Use onClick handlers for actions.\n2. If the URL comes from user input, validate that it starts with https:// or a relative path.',
  fixCode: `// Dangerous:
<a href="javascript:alert('xss')">Click</a>
<a href={userUrl}>Click</a>  // userUrl could be "javascript:..."

// Safe - use onClick:
<button onClick={handleClick}>Click</button>

// Safe - validate URLs:
const safeUrl = url.startsWith('https://') ? url : '#';
<a href={safeUrl}>Click</a>`,
});

// REACT002 - target="_blank" without rel="noopener"
const react002 = createLineCheck({
  id: 'REACT002',
  name: 'target="_blank" Without rel="noopener"',
  category: 'framework',
  severity: 'low',
  appliesTo: ['jsx', 'tsx', 'html'],
  pattern: /target\s*=\s*['"]_blank['"]/g,
  validate(_match, line) {
    // Only flag if the same line does not contain rel= with noopener
    if (/rel\s*=\s*['"][^'"]*noopener[^'"]*['"]/.test(line)) return false;
    return true;
  },
  message:
    'Links with target="_blank" without rel="noopener" allow the opened page to access window.opener. The linked page could redirect your page to a phishing site.',
  fix: 'Add rel="noopener noreferrer" to all links that use target="_blank".',
  fixCode: `// Dangerous:
<a href="https://example.com" target="_blank">Link</a>

// Safe:
<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>`,
});

// ---------------------------------------------------------------------------
// GraphQL checks
// ---------------------------------------------------------------------------

// GQL001 - No Rate Limiting Directive
const gql001 = createLineCheck({
  id: 'GQL001',
  name: 'GraphQL Without Rate Limiting',
  category: 'framework',
  severity: 'medium',
  pattern: /type\s+(?:Query|Mutation)\s*\{/g,
  appliesTo: ['graphql', 'gql', 'ts', 'js'],
  validate(_match, _line, file) {
    const content = file.content ?? '';
    // Skip if the file already includes rate limiting or complexity analysis
    if (/\b(?:@rateLimit|rateLimiting|costAnalysis|depthLimit|complexity)\b/.test(content)) {
      return false;
    }
    return true;
  },
  message:
    'GraphQL schema defines queries/mutations without rate limiting or complexity analysis.',
  fix: 'Add rate limiting, depth limiting, or query complexity analysis to protect against abusive queries.',
  fixCode: `# Dangerous - no rate limiting:
type Query {
  users: [User]
  posts: [Post]
}

# Safe - add rate limiting directive:
type Query {
  users: [User] @rateLimit(limit: 10, duration: 60)
  posts: [Post] @rateLimit(limit: 20, duration: 60)
}

# Also consider adding depth and complexity limits in server config:
# depthLimit(10)
# costAnalysis({ maximumCost: 1000 })`,
});

// GQL002 - Sensitive Field Exposed
const gql002 = createLineCheck({
  id: 'GQL002',
  name: 'Sensitive Field in GraphQL Schema',
  category: 'framework',
  severity: 'medium',
  pattern: /(?:password|secret|token|ssn|creditCard|hash)\s*:\s*(?:String|ID|Int)/gi,
  appliesTo: ['graphql', 'gql'],
  message:
    'Sensitive field is exposed in the GraphQL schema. Use @auth directives or remove it from the public schema.',
  fix: 'Remove sensitive fields from the public schema or protect them with @auth directives.',
  fixCode: `# Dangerous - password field exposed:
type User {
  id: ID!
  email: String!
  password: String!
}

# Safe - remove sensitive fields:
type User {
  id: ID!
  email: String!
}

# Or protect with auth directive:
type User {
  id: ID!
  email: String!
  password: String! @auth(requires: ADMIN)
}`,
});

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// NEXT003 - Permissive remotePatterns
const next003 = createLineCheck({
  id: 'NEXT003',
  name: 'Permissive Next.js Image remotePatterns',
  category: 'framework',
  severity: 'high',
  appliesTo: ['js', 'ts', 'mjs'],
  pattern: /(?:remotePatterns.*hostname.*['"]\*\*?['"]|domains\s*:\s*\[[^\]]*['"]\*['"])/g,
  message:
    'Next.js image optimization is configured to allow ANY external domain. This can be abused as an open SSRF proxy.',
  fix: '1. Specify exact domains or patterns in remotePatterns instead of wildcards.\n2. Only allow domains you actually serve images from.',
  fixCode: `// Dangerous:
images: {
  remotePatterns: [{ hostname: '**' }],
}

// Safe - specify allowed domains:
images: {
  remotePatterns: [
    { hostname: 'images.myapp.com' },
    { hostname: '*.amazonaws.com' },
  ],
}`,
});

// FIREBASE001 - Firebase Rules Wide Open (FileCheck)
const firebase001: FileCheck = {
  level: 'file',
  id: 'FIREBASE001',
  name: 'Firebase Security Rules Wide Open',
  description:
    'Firebase security rules that allow unrestricted read and write access to all data.',
  category: 'framework',
  defaultSeverity: 'critical',
  fastFilter: 'true',
  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    // Only check Firebase rules files
    const rulesFileNames = ['firestore.rules', 'database.rules.json', 'storage.rules'];
    const isRulesFile =
      rulesFileNames.includes(file.basename) ||
      file.extension === 'rules';
    if (!isRulesFile) return [];

    const content = await ctx.readFile(file.absolutePath);
    if (!content) return [];

    // Check for wide-open rules
    const wideOpenPatterns = [
      /allow\s+read\s*,\s*write\s*:\s*if\s+true/,
      /["']\.read["']\s*:\s*true/,
      /["']\.write["']\s*:\s*true/,
    ];

    const isWideOpen = wideOpenPatterns.some((p) => p.test(content));
    if (!isWideOpen) return [];

    const lines = await ctx.readLines(file.absolutePath);

    // Find the line with the wide-open rule
    let ruleLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (wideOpenPatterns.some((p) => p.test(lines[i]))) {
        ruleLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      ruleLine,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'FIREBASE001',
        title: 'Firebase Security Rules Wide Open',
        message:
          'Your Firebase security rules allow anyone to read and write all data. This is the #1 cause of Firebase data breaches.',
        severity:
          ctx.config.severityOverrides.get('FIREBASE001') ?? 'critical',
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: ruleLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: '1. Replace "if true" with proper authentication and authorization rules.\n2. Require users to be authenticated: "if request.auth != null".\n3. Restrict access to user-owned data: "if request.auth.uid == resource.data.userId".',
        fixCode: `// Dangerous:
allow read, write: if true;

// Safe - require authentication:
allow read, write: if request.auth != null;

// Better - restrict to owned data:
allow read, write: if request.auth.uid == resource.data.userId;`,
      },
    ];
  },
};

// SUPABASE001 - dangerouslyAllowBrowser OpenAI SDK
const supabase001 = createLineCheck({
  id: 'SUPABASE001',
  name: 'dangerouslyAllowBrowser Exposes API Key',
  category: 'framework',
  severity: 'critical',
  appliesTo: ['js', 'ts', 'jsx', 'tsx'],
  pattern: /dangerouslyAllowBrowser\s*:\s*true/g,
  message:
    'This flag sends your OpenAI API key to the browser. Anyone visiting your site can see and use your key.',
  fix: 'Move AI calls to a server-side API route. Never expose API keys in client-side code.',
  fixCode: `// Dangerous - key exposed in browser:
const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY,
  dangerouslyAllowBrowser: true,
});

// Safe - call from a server-side API route:
// app/api/ai/route.ts
const openai = new OpenAI({ apiKey: process.env.OPENAI_KEY });
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const result = await openai.chat.completions.create({ ... });
  return Response.json(result);
}`,
});

// SUPABASE002 - Supabase RLS Not Enabled (ProjectCheck)
const supabase002: ProjectCheck = {
  level: 'project',
  id: 'SUPABASE002',
  name: 'Supabase RLS Not Enabled',
  description:
    'Detects Supabase projects with SQL tables that may not have Row Level Security enabled.',
  category: 'framework',
  defaultSeverity: 'critical',

  async analyze(ctx: ScanContext): Promise<Finding[]> {
    // Only relevant if supabase is in dependencies
    const hasSupabase = ctx.packageJson
      ? 'supabase' in { ...ctx.packageJson.dependencies, ...ctx.packageJson.devDependencies } ||
        '@supabase/supabase-js' in { ...ctx.packageJson.dependencies, ...ctx.packageJson.devDependencies }
      : false;
    if (!hasSupabase) return [];

    // Scan for .sql files
    const sqlFiles = ctx.filesByExtension.get('sql') ?? [];
    if (sqlFiles.length === 0) return [];

    let hasCreateTable = false;
    let hasRLS = false;
    let createTableFile: FileEntry | null = null;
    let createTableLine = 1;

    for (const file of sqlFiles) {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) continue;

      if (/CREATE\s+TABLE/i.test(content)) {
        hasCreateTable = true;
        if (!createTableFile) {
          createTableFile = file;
          const lines = await ctx.readLines(file.absolutePath);
          for (let i = 0; i < lines.length; i++) {
            if (/CREATE\s+TABLE/i.test(lines[i])) {
              createTableLine = i + 1;
              break;
            }
          }
        }
      }

      if (/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content) || /ALTER\s+TABLE.*ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content)) {
        hasRLS = true;
      }
    }

    if (!hasCreateTable || hasRLS) return [];

    const finding: Finding = {
      checkId: 'SUPABASE002',
      title: 'Supabase RLS Not Enabled',
      message:
        'Your Supabase tables may not have Row Level Security enabled. Without RLS, anyone with your anon key can read and modify all data.',
      severity: ctx.config.severityOverrides.get('SUPABASE002') ?? 'critical',
      category: 'framework',
      location: createTableFile
        ? { filePath: createTableFile.relativePath, startLine: createTableLine }
        : undefined,
      fix: 'Add Row Level Security to every table and create appropriate policies.',
      fixCode: `-- Enable RLS on your table:
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;

-- Create a policy:
CREATE POLICY "Users can only access their own data"
  ON your_table FOR ALL
  USING (auth.uid() = user_id);`,
    };

    return [finding];
  },
} satisfies ProjectCheck;

// SUPABASE003 - Service Key in Client Code (FileCheck)
const supabase003: FileCheck = {
  level: 'file',
  id: 'SUPABASE003',
  name: 'Service Key in Client Code',
  description:
    'Detects the Supabase service role key being used in client-side code.',
  category: 'framework',
  defaultSeverity: 'critical',
  appliesTo: ['js', 'ts', 'jsx', 'tsx'],
  fastFilter: 'createClient',

  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    const content = file.content ?? await ctx.readFile(file.absolutePath);
    if (!content.includes('createClient')) return [];

    // Check for service_role or hardcoded JWT
    const hasServiceKey =
      content.includes('service_role') ||
      /eyJ[A-Za-z0-9_-]{100,}/.test(content);
    if (!hasServiceKey) return [];

    // Check if file is client-side
    const isClientSide =
      content.includes("'use client'") ||
      content.includes('"use client"') ||
      file.relativePath.includes('components/') ||
      (file.relativePath.includes('pages/') && !file.relativePath.includes('api/')) ||
      (file.relativePath.includes('app/') && !file.relativePath.includes('api/'));
    if (!isClientSide) return [];

    const lines = file.lines ?? await ctx.readLines(file.absolutePath);

    // Find the line with createClient for location
    let targetLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('createClient')) {
        targetLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      targetLine,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'SUPABASE003',
        title: 'Service Key in Client Code',
        message:
          'The Supabase service role key is used in client-side code. This key bypasses all Row Level Security.',
        severity: ctx.config.severityOverrides.get('SUPABASE003') ?? 'critical',
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: targetLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: '1. Never use the service_role key in client-side code.\n2. Use the anon key for client-side Supabase clients.\n3. Move service_role usage to server-side API routes or Server Actions.',
        fixCode: `// Dangerous - service key in client code:
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Safe - use anon key on the client:
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);`,
      },
    ];
  },
} satisfies FileCheck;

// NEXT004 - Next.js Error Page Leaking Details (LineCheck)
const next004 = createLineCheck({
  id: 'NEXT004',
  name: 'Next.js Error Page Leaking Details',
  category: 'framework',
  severity: 'medium',
  appliesTo: ['tsx', 'jsx'],
  pattern: /error\.message|error\.digest/g,
  validate(_match, _line, file) {
    // Only flag in files named error.tsx, error.jsx, error.js, or error.ts
    const basename = file.basename.toLowerCase();
    return (
      basename === 'error.tsx' ||
      basename === 'error.jsx' ||
      basename === 'error.js' ||
      basename === 'error.ts'
    );
  },
  message:
    'Error details are rendered on the error page. In production, this can leak internal info like SQL errors or file paths.',
  fix: 'Display a generic error message to users. Log the full error server-side.',
  fixCode: `// Dangerous:
<p>{error.message}</p>

// Safe - generic message:
<p>Something went wrong. Please try again.</p>`,
});

// EXPRESS003 - Express x-powered-by (ProjectCheck)
const express003: ProjectCheck = {
  level: 'project',
  id: 'EXPRESS003',
  name: 'Express X-Powered-By Header',
  description:
    'Detects Express apps that expose the X-Powered-By header without helmet.',
  category: 'framework',
  defaultSeverity: 'low',

  async analyze(ctx: ScanContext): Promise<Finding[]> {
    // Only relevant if express is detected
    if (!ctx.detectedFrameworks.includes('express')) return [];

    // Check if helmet is a dependency
    if (ctx.packageJson) {
      const allDeps = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };
      if ('helmet' in allDeps) return [];
    }

    // Check if any file disables x-powered-by
    for (const file of ctx.files.values()) {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) continue;
      if (/disable.*x-powered-by/i.test(content) || /removeHeader.*x-powered-by/i.test(content)) {
        return [];
      }
    }

    return [
      {
        checkId: 'EXPRESS003',
        title: 'Express X-Powered-By Header',
        message:
          'Express sends an X-Powered-By header revealing your framework. Attackers use this for targeted attacks.',
        severity: ctx.config.severityOverrides.get('EXPRESS003') ?? 'low',
        category: 'framework',
        fix: 'Disable the X-Powered-By header using helmet or app.disable().',
        fixCode: `// Option 1 - use helmet (recommended):
import helmet from 'helmet';
app.use(helmet());

// Option 2 - disable just X-Powered-By:
app.disable('x-powered-by');`,
      },
    ];
  },
} satisfies ProjectCheck;

// NEXT005 - Middleware Without Matcher (FileCheck)
const next005: FileCheck = {
  level: 'file',
  id: 'NEXT005',
  name: 'Next.js Middleware Without Matcher',
  description:
    'Detects Next.js middleware files that have no route matcher configured, causing middleware to run on every request.',
  category: 'framework',
  defaultSeverity: 'medium',
  appliesTo: ['js', 'ts'],
  fastFilter: 'middleware',
  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    // Only scan files named middleware.ts or middleware.js
    const basename = file.basename.toLowerCase();
    if (basename !== 'middleware.ts' && basename !== 'middleware.js') {
      return [];
    }

    const content = await ctx.readFile(file.absolutePath);
    if (!content) return [];

    // Confirm the file exports middleware
    if (!/export\s+(?:default\s+)?function\s+middleware|export\s+(?:const|async\s+function)\s+middleware/i.test(content)) {
      return [];
    }

    // Check if a config with matcher is exported
    if (/export\s+const\s+config\s*=/.test(content) && /matcher\s*:/.test(content)) {
      return [];
    }

    const lines = await ctx.readLines(file.absolutePath);

    // Find the middleware function declaration
    let middlewareLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (/export.*function\s+middleware/i.test(lines[i])) {
        middlewareLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      middlewareLine,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'NEXT005',
        title: 'Next.js Middleware Without Matcher',
        message:
          'This Next.js middleware has no route matcher configured. It runs on every request including static files. Add a matcher to specify which routes need protection.',
        severity: ctx.config.severityOverrides.get('NEXT005') ?? 'medium',
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: middlewareLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: 'Export a config object with a matcher array to specify which routes the middleware should run on.',
        fixCode: `export const config = { matcher: ['/api/:path*', '/dashboard/:path*'] };`,
      },
    ];
  },
};

// FIREBASE002 - Permissive Firebase Storage Rules (FileCheck)
const firebase002: FileCheck = {
  level: 'file',
  id: 'FIREBASE002',
  name: 'Permissive Firebase Storage Rules',
  description:
    'Detects Firebase Storage rules that allow unrestricted read and write access to all files.',
  category: 'framework',
  defaultSeverity: 'critical',
  fastFilter: 'allow',
  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    // Only check storage.rules files
    if (file.basename !== 'storage.rules') return [];

    const content = await ctx.readFile(file.absolutePath);
    if (!content) return [];

    // Check for wide-open rules
    const wideOpenPatterns = [
      /allow\s+read\s*,\s*write\s*:\s*if\s+true/,
      /allow\s+read\s*,\s*write\s*;/,
    ];

    // Also check for individually permissive read AND write
    const hasReadTrue = /allow\s+read\s*:\s*if\s+true/.test(content);
    const hasWriteTrue = /allow\s+write\s*:\s*if\s+true/.test(content);

    const isWideOpen = wideOpenPatterns.some((p) => p.test(content)) || (hasReadTrue && hasWriteTrue);
    if (!isWideOpen) return [];

    const lines = await ctx.readLines(file.absolutePath);

    // Find the line with the wide-open rule
    let ruleLine = 1;
    const allPatterns = [...wideOpenPatterns, /allow\s+read\s*:\s*if\s+true/, /allow\s+write\s*:\s*if\s+true/];
    for (let i = 0; i < lines.length; i++) {
      if (allPatterns.some((p) => p.test(lines[i]))) {
        ruleLine = i + 1;
        break;
      }
    }

    const { snippet, contextBefore, contextAfter } = extractSnippet(
      lines,
      ruleLine,
      ctx.config.contextLines,
    );

    return [
      {
        checkId: 'FIREBASE002',
        title: 'Permissive Firebase Storage Rules',
        message:
          'Your Firebase Storage rules allow anyone to read and write files. An attacker can upload malicious files or download all stored data.',
        severity:
          ctx.config.severityOverrides.get('FIREBASE002') ?? 'critical',
        category: 'framework',
        location: {
          filePath: file.relativePath,
          startLine: ruleLine,
        },
        snippet,
        contextBefore,
        contextAfter,
        fix: 'Restrict Firebase Storage rules to authenticated users and validate file types and sizes.',
        fixCode: `// Dangerous:
allow read, write: if true;

// Safe - require authentication:
allow read, write: if request.auth != null;

// Better - restrict by file type and size:
allow read: if request.auth != null;
allow write: if request.auth != null
  && request.resource.size < 5 * 1024 * 1024
  && request.resource.contentType.matches('image/.*');`,
      },
    ];
  },
};

export const frameworkChecks: CheckDefinition[] = [
  next001,
  next002,
  next003,
  express001,
  express002,
  react001,
  // react002 removed — target="_blank" is handled by modern browsers since 2021
  firebase001,
  supabase001,
  supabase002,
  supabase003,
  next004,
  express003,
  next005,
  firebase002,
  gql001,
  gql002,
];
