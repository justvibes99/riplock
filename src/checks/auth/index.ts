import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  ProjectCheck,
  Finding,
  ScanContext,
} from '../types.js';
import { extractSnippet } from '../../utils/snippet.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const authChecks: CheckDefinition[] = [
  // AUTH001 - JWT Weak Secret
  createLineCheck({
    id: 'AUTH001',
    category: 'auth',
    name: 'JWT Signed with Weak Secret',
    severity: 'critical',
    pattern:
      /jwt\.sign\s*\([^)]*,\s*['"](?:secret|password|key|test|dev|123|abc|jwt_?secret|changeme)['"]/gi,
    appliesTo: ['js', 'ts'],
    message:
      'Your JWT is signed with a weak or common secret. An attacker can guess it and forge login tokens.',
    fix: '1. Use a long, random secret (at least 256 bits / 32 bytes).\n2. Store the secret in an environment variable, never in code.\n3. Rotate the secret and invalidate existing tokens.',
    fixCode: `// Dangerous:
jwt.sign(payload, 'secret');

// Safe:
jwt.sign(payload, process.env.JWT_SECRET); // where JWT_SECRET is a long random value`,
  }),

  // AUTH002 - JWT No Algorithm Restriction
  createLineCheck({
    id: 'AUTH002',
    category: 'auth',
    name: 'JWT Verification Without Algorithm Restriction',
    severity: 'high',
    pattern: /jwt\.verify\s*\([^,]+,[^,]+\)\s*[;,)]/g,
    appliesTo: ['js', 'ts'],
    message:
      'JWT verification doesn\'t restrict algorithms. An attacker could forge tokens using the \'none\' algorithm.',
    fix: '1. Always pass an options object with an explicit algorithms array.\n2. Never allow the "none" algorithm in production.',
    fixCode: `// Dangerous:
jwt.verify(token, secret);

// Safe - specify allowed algorithms:
jwt.verify(token, secret, { algorithms: ['HS256'] });`,
  }),

  // AUTH003 - Insecure Cookie Settings
  createLineCheck({
    id: 'AUTH003',
    category: 'auth',
    name: 'Insecure Cookie Settings',
    severity: 'high',
    pattern:
      /(?:res\.cookie|cookies\.set|setCookie)\s*\([^)]*(?:httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['"]none['"])/gi,
    appliesTo: ['js', 'ts'],
    message:
      'Your cookies have weak security settings. Scripts can steal them or they\'re sent over unencrypted connections.',
    fix: '1. Set httpOnly: true to prevent JavaScript access.\n2. Set secure: true to require HTTPS.\n3. Set sameSite to "lax" or "strict" instead of "none".',
    fixCode: `// Dangerous:
res.cookie('session', token, { httpOnly: false, secure: false });

// Safe:
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 24 * 60 * 60 * 1000,
});`,
  }),

  // AUTH004 - Password Stored Without Hashing
  createLineCheck({
    id: 'AUTH004',
    category: 'auth',
    name: 'Password Stored Without Hashing',
    severity: 'critical',
    pattern: /(?:password|passwd)\s*:\s*(?:req\.body|body|input|args)\.\w+/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Not a problem if the line also references hashing
      const lower = line.toLowerCase();
      if (lower.includes('hash')) return false;
      if (lower.includes('bcrypt')) return false;
      if (lower.includes('argon2')) return false;
      if (lower.includes('scrypt')) return false;
      return true;
    },
    message:
      'Passwords are stored without hashing. If your database is breached, every password is visible.',
    fix: '1. Hash passwords with bcrypt, argon2, or scrypt before storing.\n2. Never store, log, or transmit plain text passwords.\n3. Use a unique salt per password (bcrypt and argon2 do this automatically).',
    fixCode: `// Dangerous:
await db.user.create({ password: req.body.password });

// Safe:
import bcrypt from 'bcrypt';
const hashed = await bcrypt.hash(req.body.password, 12);
await db.user.create({ password: hashed });`,
  }),

  // AUTH005 - No Auth on API Route (FileCheck)
  {
    level: 'file',
    id: 'AUTH005',
    name: 'API Route Without Authentication',
    description:
      'API route handlers that lack any authentication or session check.',
    category: 'auth',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: 'export',

    async analyze(file, ctx): Promise<Finding[]> {
      // Only scan files in api/ or routes/ directories
      if (
        !file.relativePath.includes('api/') &&
        !file.relativePath.includes('routes/')
      ) {
        return [];
      }

      // Skip health/status/webhook/callback endpoints (check full path, not just basename)
      const skipNames = ['health', 'ping', 'status', 'webhook', 'cron', 'callback', 'auth-callback'];
      const baseLower = file.basename.toLowerCase().replace(/\.[^.]+$/, '');
      const pathLower = file.relativePath.toLowerCase();
      if (skipNames.some((s) => baseLower.includes(s) || pathLower.includes(s))) {
        return [];
      }

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Check for route handler indicators
      const routePatterns =
        /(?:export\s+(?:default|async)\s+function|export\s+(?:const|function)\s+(?:GET|POST|PUT|PATCH|DELETE)|app\.(?:get|post|put|patch|delete)\s*\(|router\.(?:get|post|put|patch|delete)\s*\()/i;
      if (!routePatterns.test(content)) return [];

      // Check for auth references
      const authPatterns =
        /(?:getSession|getServerSession|requireAuth|verifyToken|jwt\.verify|currentUser|getAuth|middleware|isAuthenticated|authenticate|withAuth|authGuard|protect|ensureAuth|checkAuth|auth\(\)|getToken|useSession)/i;
      if (authPatterns.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);
      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        1,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH005',
          title: 'API Route Without Authentication',
          message:
            'This API route has no authentication check. Any user (or bot) can call it without logging in.',
          severity:
            ctx.config.severityOverrides.get('AUTH005') ?? 'high',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: 1,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Add authentication middleware or a session check at the top of the handler.\n2. Return 401 Unauthorized for unauthenticated requests.\n3. If this route is intentionally public, add a comment like "// public route" to document the decision.',
          fixCode: `// Next.js App Router example:
import { getServerSession } from 'next-auth';
export async function GET(req: Request) {
  const session = await getServerSession();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  // ... handler logic
}`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH006 - Missing Rate Limit on Auth Endpoint
  {
    level: 'file',
    id: 'AUTH006',
    name: 'Missing Rate Limit on Authentication',
    description:
      'Login or authentication endpoints without rate limiting.',
    category: 'auth',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: /\blogin\b|\bsignin\b|\bsign-in\b|\bauthenticate\b/i,

    async analyze(file, ctx): Promise<Finding[]> {
      // Only check files in API/route directories, not scripts
      if (/scripts?\/|test\/|__test__|\.test\.|\.spec\.|playwright|cypress|selenium/i.test(file.relativePath)) {
        return [];
      }

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm the file actually handles authentication via HTTP routes
      // Must have a login/auth related route — not just any POST handler
      const routePattern =
        /(?:app|router)\.(?:post|put)\s*\(\s*['"].*(?:\blogin\b|\bsignin\b|\bsign-in\b|\bauth\b)/i;
      const isAuthFile = /(?:\blogin\b|\bsignin\b|\bsign-in\b|\bauthenticate\b)/i.test(file.relativePath) ||
        routePattern.test(content) ||
        (/export\s+(?:async\s+)?function\s+POST/i.test(content) && /(?:\blogin\b|\bsignin\b|\bsign.in\b|\bpassword\b|\bcredential)/i.test(content));
      if (!isAuthFile) {
        return [];
      }

      // Check for rate limiting references
      const rateLimitPattern =
        /(?:rateLimit|rate-limit|rate_limit|rateLimiter|throttle|slowDown|express-rate-limit|@nestjs\/throttler|limiter|brute)/i;
      if (rateLimitPattern.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with the login handler for better location reporting
      let loginLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/(?:login|signIn|sign_in|signin|authenticate)/i.test(lines[i])) {
          loginLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        loginLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH006',
          title: 'Missing Rate Limit on Authentication',
          message:
            'Your login page has no rate limiting. An attacker can try thousands of passwords per second.',
          severity:
            ctx.config.severityOverrides.get('AUTH006') ?? 'high',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: loginLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Add rate limiting middleware to login and authentication routes.\n2. Limit to 5-10 attempts per IP per minute.\n3. Consider account lockout after repeated failures.',
          fixCode: `// Using express-rate-limit:
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 attempts per window
  message: 'Too many login attempts, please try again later.',
});
app.post('/login', loginLimiter, loginHandler);`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH007 - Admin Routes Without Role Check
  createLineCheck({
    id: 'AUTH007',
    category: 'auth',
    name: 'Admin Route Without Role Check',
    severity: 'high',
    pattern:
      /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]*\/admin/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      if (lower.includes('role')) return false;
      if (lower.includes('isadmin')) return false;
      if (lower.includes('permission')) return false;
      if (lower.includes('authorize')) return false;
      // Check for admin middleware reference (e.g., adminMiddleware, adminAuth)
      if (/admin\w*(?:middleware|auth|guard|check)/i.test(line)) return false;
      return true;
    },
    message:
      'Admin routes don\'t verify the user is actually an admin. Any logged-in user could access admin features.',
    fix: '1. Add role-checking middleware to all admin routes.\n2. Verify the user\'s role on the server side, never trust the client.\n3. Use a middleware like requireRole("admin") applied to all /admin routes.',
    fixCode: `// Dangerous:
app.get('/admin/users', getUsers);

// Safe - add role-checking middleware:
app.get('/admin/users', requireAuth, requireRole('admin'), getUsers);

// Or use a router-level middleware:
const adminRouter = express.Router();
adminRouter.use(requireAuth, requireRole('admin'));
adminRouter.get('/users', getUsers);
app.use('/admin', adminRouter);`,
  }),

  // AUTH008 - Webhook Without Signature Verification (FileCheck)
  {
    level: 'file',
    id: 'AUTH008',
    name: 'Webhook Without Signature Verification',
    description:
      'Webhook endpoint that processes request body without verifying the request signature.',
    category: 'auth',
    defaultSeverity: 'critical',
    appliesTo: ['js', 'ts'],

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Only scan files whose path or name contains 'webhook'
      if (!/webhook/i.test(file.relativePath)) return [];

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Must process request body (req.body, req.json(), req.text())
      if (!/req\.body|req\.json\(\)|req\.text\(\)|await\s+req\.json/.test(content)) return [];

      // Check for signature verification patterns
      // Strip comments before checking for verification patterns
      const codeOnly = content.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      const verificationPatterns =
        /(?:constructEvent|svix\.verify|Webhook\.verify|timingSafeEqual|verifySignature|verify_signature|webhookSecret|webhook_secret|stripe\.webhooks)/i;
      if (verificationPatterns.test(codeOnly)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with req.body for location
      let bodyLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('req.body')) {
          bodyLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        bodyLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH008',
          title: 'Webhook Without Signature Verification',
          message:
            'This webhook endpoint doesn\'t verify the request signature. An attacker can forge webhook events to trigger fake payments or account changes.',
          severity:
            ctx.config.severityOverrides.get('AUTH008') ?? 'critical',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: bodyLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Verify the webhook signature before processing the payload.\n2. Use the provider\'s SDK (e.g. Stripe constructEvent, Svix verify) to validate signatures.\n3. Compare signatures using crypto.timingSafeEqual to prevent timing attacks.',
          fixCode: `// Stripe example:
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(
    req.body, sig, process.env.STRIPE_WEBHOOK_SECRET
  );
  // ... handle event
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH009 - Cookie Set Without httpOnly
  createLineCheck({
    id: 'AUTH009',
    category: 'auth',
    name: 'Cookie Set Without httpOnly',
    severity: 'high',
    pattern: /res\.cookie\s*\(\s*['"](?:token|session|jwt|auth|sid|access)['"]\s*,[^,)]+\)\s*;/g,
    appliesTo: ['js', 'ts'],
    message:
      'This cookie is set without security options. By default, httpOnly is false, meaning JavaScript can steal it.',
    fix: 'Always pass security options when setting sensitive cookies: { httpOnly: true, secure: true, sameSite: \'lax\' }.',
    fixCode: `// Dangerous:
res.cookie('token', jwt);

// Safe - with security options:
res.cookie('token', jwt, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
});`,
  }),

  // AUTH010 - Unvalidated OAuth Redirect
  createLineCheck({
    id: 'AUTH010',
    category: 'auth',
    name: 'Unvalidated OAuth Redirect',
    severity: 'high',
    pattern: /(?:callbackUrl|redirect_uri|returnTo|redirectUrl)\s*[:=]\s*(?:req\.query|req\.body|searchParams|params)\./g,
    appliesTo: ['js', 'ts'],
    message:
      'The OAuth callback/redirect URL comes from user input without validation. An attacker can steal auth tokens by redirecting to their own site.',
    fix: '1. Validate the redirect URL against an allowlist of trusted domains.\n2. Only allow relative paths or specific known callback URLs.\n3. Parse the URL and verify the hostname before using it.',
    fixCode: `// Dangerous:
const callbackUrl = req.query.callbackUrl;
res.redirect(callbackUrl);

// Safe - validate against allowlist:
const ALLOWED_CALLBACKS = ['https://myapp.com/callback', 'https://myapp.com/auth'];
const callbackUrl = req.query.callbackUrl;
if (!ALLOWED_CALLBACKS.includes(callbackUrl)) {
  return res.status(400).send('Invalid callback URL');
}
res.redirect(callbackUrl);`,
  }),

  // AUTH011 - Missing Ownership Check / IDOR (FileCheck)
  {
    level: 'file',
    id: 'AUTH011',
    name: 'Missing Ownership Check (IDOR)',
    description:
      'Route modifies a resource by ID from params but does not verify the logged-in user owns it.',
    category: 'auth',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: 'params',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Only scan files in api/ or routes/ paths
      if (
        !file.relativePath.includes('api/') &&
        !file.relativePath.includes('routes/')
      ) {
        return [];
      }

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Check if file uses params.id or params.someId in a DB operation
      const paramIdPattern = /params\.(?:\w*[Ii]d|id)\b/;
      if (!paramIdPattern.test(content)) return [];

      // Check for delete/update DB operations
      const dbMutationPattern =
        /\.(?:delete|update|destroy|remove|findByIdAndDelete|findByIdAndUpdate|findOneAndDelete|findOneAndUpdate)\s*\(/;
      if (!dbMutationPattern.test(content)) return [];

      // Check for ownership verification patterns
      const ownershipPatterns =
        /(?:userId|authorId|ownerId|createdBy|session\.user\.id|currentUser\.id|user\.id)/;
      if (ownershipPatterns.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with params.id for location
      let paramLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (paramIdPattern.test(lines[i])) {
          paramLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        paramLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH011',
          title: 'Missing Ownership Check (IDOR)',
          message:
            'This route modifies a resource by ID but doesn\'t verify the logged-in user owns it. Any user can modify another user\'s data by changing the ID.',
          severity:
            ctx.config.severityOverrides.get('AUTH011') ?? 'high',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: paramLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Always check that the logged-in user owns the resource before modifying it.\n2. Include the user ID in the database query (e.g. WHERE id = ? AND userId = ?).\n3. Return 403 Forbidden if the user does not own the resource.',
          fixCode: `// Dangerous - any user can delete any post:
app.delete('/posts/:id', async (req, res) => {
  await Post.findByIdAndDelete(req.params.id);
});

// Safe - verify ownership:
app.delete('/posts/:id', async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.userId !== req.session.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  await post.delete();
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH012 - GraphQL Mutations Without Auth (FileCheck)
  {
    level: 'file',
    id: 'AUTH012',
    name: 'GraphQL Mutations Without Auth',
    description:
      'Detects GraphQL mutation resolvers that lack authentication checks.',
    category: 'auth',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: 'Mutation',

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Check for Mutation resolver definitions
      if (!/Mutation/i.test(content)) return [];

      // Check for auth references
      const authPatterns =
        /(?:context\.user|context\.session|requireAuth|isAuthenticated|authorize)/i;
      if (authPatterns.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with Mutation
      let mutationLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/Mutation/i.test(lines[i])) {
          mutationLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        mutationLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH012',
          title: 'GraphQL Mutations Without Auth',
          message:
            'GraphQL mutations perform data changes without checking authentication.',
          severity: ctx.config.severityOverrides.get('AUTH012') ?? 'high',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: mutationLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Check context.user or context.session at the top of every mutation resolver.\n2. Use an auth middleware or directive for GraphQL.',
          fixCode: `// Dangerous:
const resolvers = {
  Mutation: {
    deleteUser: (_, args) => db.user.delete(args.id),
  },
};

// Safe - check auth in context:
const resolvers = {
  Mutation: {
    deleteUser: (_, args, context) => {
      if (!context.user) throw new Error('Unauthorized');
      return db.user.delete(args.id);
    },
  },
};`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH013 - Missing CSRF Protection (ProjectCheck)
  {
    level: 'project',
    id: 'AUTH013',
    name: 'Missing CSRF Protection',
    description:
      'Detects apps using session cookies without CSRF protection.',
    category: 'auth',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      if (!ctx.packageJson) return [];

      const allDeps = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };

      // Check if session cookies are in use
      const hasSessionLib =
        'express-session' in allDeps || 'cookie-session' in allDeps;
      if (!hasSessionLib) return [];

      // Check if a CSRF library is installed
      const csrfLibs = ['csurf', 'csrf-csrf', 'lusca', 'csrf'];
      if (csrfLibs.some((lib) => lib in allDeps)) return [];

      // Check if any file references csrf
      for (const file of ctx.files.values()) {
        const content = await ctx.readFile(file.absolutePath);
        if (content && (/csrf/i.test(content) || /csrfToken/i.test(content))) {
          return [];
        }
      }

      return [
        {
          checkId: 'AUTH013',
          title: 'Missing CSRF Protection',
          message:
            'Your app uses session cookies but has no CSRF protection. A malicious site can make your users perform actions without their knowledge.',
          severity: ctx.config.severityOverrides.get('AUTH013') ?? 'medium',
          category: 'auth',
          fix: '1. Add a CSRF protection library (csrf-csrf, lusca, or csurf).\n2. Include CSRF tokens in all state-changing forms and AJAX requests.',
          fixCode: `// Using csrf-csrf:
import { doubleCsrf } from 'csrf-csrf';
const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET });
app.use(doubleCsrfProtection);`,
        },
      ];
    },
  } satisfies ProjectCheck,

  // AUTH014 - WebSocket Without Auth (FileCheck)
  {
    level: 'file',
    id: 'AUTH014',
    name: 'WebSocket Without Auth',
    description:
      'Detects WebSocket servers that accept connections without authentication.',
    category: 'auth',
    defaultSeverity: 'medium',
    appliesTo: ['js', 'ts'],
    fastFilter: /socket\.io|new\s+WebSocket\.Server|wss\./,

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm socket.io or ws server setup
      const hasWsServer =
        /(?:socket\.io|new\s+WebSocket\.Server|new\s+Server\s*\(\s*\{|wss\.on)/i.test(content);
      if (!hasWsServer) return [];

      // Check for auth in connection handler
      const authPatterns =
        /(?:authenticate|verifyToken|getSession|jwt\.verify|authorization|token|auth|middleware)/i;
      if (authPatterns.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with WebSocket setup
      let wsLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/(?:socket\.io|WebSocket\.Server|wss\.on)/i.test(lines[i])) {
          wsLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        wsLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH014',
          title: 'WebSocket Without Auth',
          message:
            'WebSocket connections are accepted without authentication. Anyone can connect and receive private data.',
          severity: ctx.config.severityOverrides.get('AUTH014') ?? 'medium',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: wsLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Verify authentication during the WebSocket handshake.\n2. Check the token or session cookie in the connection event.',
          fixCode: `// Dangerous:
io.on('connection', (socket) => { /* no auth */ });

// Safe - verify auth on connection:
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    const user = jwt.verify(token, secret);
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Unauthorized'));
  }
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH015 - Race Condition on Balance/Credits (LineCheck)
  createLineCheck({
    id: 'AUTH015',
    category: 'auth',
    name: 'Race Condition on Balance/Credits',
    severity: 'medium',
    appliesTo: ['js', 'ts'],
    pattern: /\.update\s*\([^)]*(?:balance|credits|quantity|stock|inventory|points|coins)\s*:/g,
    validate(_match, line) {
      // Flag if the line does NOT contain transaction-related keywords
      const lower = line.toLowerCase();
      if (lower.includes('$transaction')) return false;
      if (lower.includes('begin')) return false;
      if (lower.includes('lock')) return false;
      if (lower.includes('serializable')) return false;
      if (lower.includes('for update')) return false;
      return true;
    },
    message:
      'Financial/inventory updates without a transaction allow race conditions. An attacker can send concurrent requests to double-spend.',
    fix: '1. Wrap balance/credit updates in a database transaction.\n2. Use SELECT ... FOR UPDATE or serializable isolation level.\n3. Use atomic increment operations when possible.',
    fixCode: `// Dangerous:
await db.user.update({ where: { id }, data: { balance: user.balance - amount } });

// Safe - use a transaction with atomic operations:
await db.$transaction(async (tx) => {
  const user = await tx.user.findUnique({ where: { id } });
  if (user.balance < amount) throw new Error('Insufficient balance');
  await tx.user.update({ where: { id }, data: { balance: { decrement: amount } } });
});`,
  }),

  // AUTH016 - Client-Side Role Check (LineCheck)
  createLineCheck({
    id: 'AUTH016',
    category: 'auth',
    name: 'Client-Side Role Check',
    severity: 'medium',
    appliesTo: ['jsx', 'tsx'],
    pattern: /(?:isAdmin|is_admin|role\s*===?\s*['"]admin['"])/g,
    message:
      'Admin role checks in client-side code can be bypassed. Always verify roles on the server.',
    fix: '1. Move role checks to server-side API routes or middleware.\n2. Use client-side checks only for UI display, never for access control.',
    fixCode: `// Dangerous - client-only check:
{isAdmin && <AdminPanel />}

// Safe - server verifies role, client only hides UI:
// Server: if (user.role !== 'admin') return 403;
// Client: {isAdmin && <AdminPanel />} // UI hint only`,
  }),

  // AUTH017 - JWT Missing Audience/Issuer Validation
  createLineCheck({
    id: 'AUTH017',
    category: 'auth',
    name: 'JWT Missing Audience/Issuer Validation',
    severity: 'medium',
    appliesTo: ['js', 'ts'],
    pattern: /jwt\.verify\s*\([^)]+\)/g,
    validate(_match, line) {
      // Only flag jwt.verify calls that don't check audience or issuer
      if (!line.includes('jwt.verify')) return false;
      const lower = line.toLowerCase();
      if (lower.includes('audience') || lower.includes('aud')) return false;
      if (lower.includes('issuer') || lower.includes('iss')) return false;
      return true;
    },
    message:
      "JWT verification doesn't check the audience or issuer claims. An attacker can reuse tokens from a different application or service.",
    fix: 'Add audience and issuer options to jwt.verify() to ensure tokens are intended for your application.',
    fixCode: `// Dangerous - no audience or issuer check:
jwt.verify(token, secret);
jwt.verify(token, secret, { algorithms: ['HS256'] });

// Safe - validate audience and issuer:
jwt.verify(token, secret, { algorithms: ['HS256'], audience: 'my-app', issuer: 'my-server' });`,
  }),

  // AUTH018 - Plaintext Password Comparison
  createLineCheck({
    id: 'AUTH018',
    category: 'auth',
    name: 'Plaintext Password Comparison',
    severity: 'critical',
    pattern: /(?:\.password|password)\s*(?:===|!==|==|!=)\s*(?:password|req\.body|body\.|input\.|args\.|formData|pass\b)/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Skip if bcrypt.compare or argon2.verify is used
      if (/bcrypt\.compare|argon2\.verify|scrypt|compare.*hash|hash.*compare/i.test(line)) return false;
      return true;
    },
    message:
      'Passwords are compared in plaintext. This means passwords are stored without hashing — if your database is breached, every password is immediately visible.',
    fix: '1. Hash passwords with bcrypt when storing them.\n2. Use bcrypt.compare() to verify passwords at login.\n3. Never compare password strings directly.',
    fixCode: `// Dangerous:
if (user.password === req.body.password) { ... }

// Safe:
const valid = await bcrypt.compare(req.body.password, user.passwordHash);
if (valid) { ... }`,
  }),

  // AUTH019 - No Account Lockout (FileCheck)
  {
    level: 'file',
    id: 'AUTH019',
    name: 'No Account Lockout',
    description:
      'Login handler has no account lockout mechanism to prevent brute force attacks.',
    category: 'auth',
    defaultSeverity: 'medium',
    appliesTo: ['js', 'ts'],
    fastFilter: /login|signin|authenticate/i,

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Skip test files
      if (/test\/|__test__|\.test\.|\.spec\.|playwright|cypress/i.test(file.relativePath)) {
        return [];
      }

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm this is a login handler
      const routePattern =
        /(?:app|router)\.(?:post|put)\s*\(\s*['"].*(?:\blogin\b|\bsignin\b|\bsign-in\b|\bauth\b)/i;
      const isAuthFile = /(?:\blogin\b|\bsignin\b|\bsign-in\b|\bauthenticate\b)/i.test(file.relativePath) ||
        routePattern.test(content) ||
        (/export\s+(?:async\s+)?function\s+POST/i.test(content) && /(?:\blogin\b|\bsignin\b|\bsign.in\b|\bpassword\b|\bcredential)/i.test(content));
      if (!isAuthFile) return [];

      // Check for lockout references
      const lockoutPatterns =
        /(?:maxAttempts|lockout|failedAttempts|loginAttempts|accountLocked|MAX_LOGIN_ATTEMPTS|max_attempts|login_attempts|failed_attempts|account_locked)/i;
      if (lockoutPatterns.test(content)) return [];

      // Also skip if rate limiting is present (covered by AUTH006 but still a mitigation)
      const rateLimitPattern =
        /(?:rateLimit|rate-limit|rate_limit|rateLimiter|throttle|slowDown|express-rate-limit|@nestjs\/throttler|limiter|brute)/i;
      if (rateLimitPattern.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      let loginLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/(?:login|signIn|sign_in|signin|authenticate)/i.test(lines[i])) {
          loginLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        loginLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH019',
          title: 'No Account Lockout',
          message:
            'Login handler has no account lockout mechanism. An attacker can try unlimited passwords.',
          severity:
            ctx.config.severityOverrides.get('AUTH019') ?? 'medium',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: loginLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Track failed login attempts per account.\n2. Lock the account or add exponential backoff after 5-10 failures.\n3. Notify the user when their account is locked.',
          fixCode: `// Example lockout logic:
const MAX_ATTEMPTS = 5;
const user = await db.user.findUnique({ where: { email } });
if (user.failedAttempts >= MAX_ATTEMPTS) {
  return res.status(423).json({ error: 'Account locked. Try again later.' });
}
// On failed login:
await db.user.update({ where: { id: user.id }, data: { failedAttempts: { increment: 1 } } });
// On successful login:
await db.user.update({ where: { id: user.id }, data: { failedAttempts: 0 } });`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH020 - Session Not Regenerated After Login (FileCheck)
  {
    level: 'file',
    id: 'AUTH020',
    name: 'Session Not Regenerated After Login',
    description:
      'Session is modified without regeneration, risking session fixation attacks.',
    category: 'auth',
    defaultSeverity: 'medium',
    appliesTo: ['js', 'ts'],
    fastFilter: 'session',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Check if file sets session properties
      const sessionSetPattern = /(?:req\.session\.\w+\s*=|session\.user\s*=)/;
      if (!sessionSetPattern.test(content)) return [];

      // Check for session regeneration
      const regeneratePattern = /(?:session\.regenerate|req\.session\.regenerate|session\.destroy)/;
      if (regeneratePattern.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line where session is set
      let sessionLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (sessionSetPattern.test(lines[i])) {
          sessionLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        sessionLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'AUTH020',
          title: 'Session Not Regenerated After Login',
          message:
            'Session is modified without regeneration. Regenerate the session ID after login to prevent session fixation.',
          severity:
            ctx.config.severityOverrides.get('AUTH020') ?? 'medium',
          category: 'auth',
          location: {
            filePath: file.relativePath,
            startLine: sessionLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Call req.session.regenerate() before setting session properties after login.\n2. This prevents session fixation attacks where an attacker sets a known session ID.',
          fixCode: `// Dangerous:
app.post('/login', (req, res) => {
  req.session.user = user;  // session ID unchanged
});

// Safe - regenerate session:
app.post('/login', (req, res) => {
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Error');
    req.session.user = user;  // new session ID
    res.redirect('/dashboard');
  });
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // AUTH021 - No Authentication Event Logging (ProjectCheck)
  {
    level: 'project',
    id: 'AUTH021',
    name: 'No Authentication Event Logging',
    description:
      'Detects projects with authentication code but no audit/auth logging for incident response.',
    category: 'auth',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      // First, check if auth-related files exist
      let hasAuthFiles = false;
      for (const [relPath] of ctx.files) {
        if (/(?:\blogin\b|\bsignin\b|\bsign-in\b|\bauth\b|\bauthenticate\b)/i.test(relPath)) {
          hasAuthFiles = true;
          break;
        }
      }

      // Also check file contents for auth patterns if no auth filenames found
      if (!hasAuthFiles) {
        for (const file of ctx.files.values()) {
          if (file.extension !== 'js' && file.extension !== 'ts') continue;
          const content = await ctx.readFile(file.absolutePath);
          if (content && /(?:bcrypt\.compare|argon2\.verify|jwt\.sign|passport\.authenticate)/i.test(content)) {
            hasAuthFiles = true;
            break;
          }
        }
      }

      if (!hasAuthFiles) return [];

      // Search for auth/audit logging patterns across the project
      const authLogPatterns =
        /(?:authLog|auditLog|securityLog|loginLog|auth_log|audit_log|logAuthEvent|logLoginAttempt|logFailedLogin|log_auth|log_login|authAudit|security_event)/i;

      for (const file of ctx.files.values()) {
        const content = await ctx.readFile(file.absolutePath);
        if (content && authLogPatterns.test(content)) {
          return []; // Auth logging exists somewhere
        }
      }

      return [
        {
          checkId: 'AUTH021',
          title: 'No Authentication Event Logging',
          message:
            'No authentication event logging detected. Log failed login attempts, password changes, and privilege escalations for incident response.',
          severity: ctx.config.severityOverrides.get('AUTH021') ?? 'medium',
          category: 'auth',
          fix: '1. Add structured logging for all authentication events (login success/failure, password reset, privilege changes).\n2. Include timestamp, user identifier, IP address, and event type.\n3. Send auth logs to a centralized logging service for monitoring and alerting.',
          fixCode: `// Create an auth event logger:
function logAuthEvent(event: {
  type: 'login_success' | 'login_failure' | 'password_change' | 'privilege_change';
  userId?: string;
  ip: string;
  details?: string;
}) {
  logger.info({ ...event, timestamp: new Date().toISOString() }, 'auth_event');
}

// Use it in your login handler:
if (!validPassword) {
  logAuthEvent({ type: 'login_failure', ip: req.ip, details: email });
  return res.status(401).json({ error: 'Invalid credentials' });
}
logAuthEvent({ type: 'login_success', userId: user.id, ip: req.ip });`,
        },
      ];
    },
  } satisfies ProjectCheck,

  // AUTH022 - No Input Validation Library (ProjectCheck)
  {
    level: 'project',
    id: 'AUTH022',
    name: 'No Input Validation Library',
    description:
      'Detects API projects without a schema validation library, risking injection and type confusion.',
    category: 'auth',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      if (!ctx.packageJson) return [];

      // Check if the project has API routes
      let hasApiRoutes = false;
      for (const [relPath] of ctx.files) {
        if (/(?:api\/|routes\/)/i.test(relPath)) {
          hasApiRoutes = true;
          break;
        }
      }
      if (!hasApiRoutes) return [];

      const allDeps = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };

      // Check for known validation libraries
      const validationLibs = [
        'zod', 'joi', 'yup', 'ajv', 'class-validator', 'superstruct',
        'valibot', 'io-ts', 'runtypes', 'typebox', '@sinclair/typebox',
        'fastest-validator', 'express-validator', 'celebrate',
      ];

      if (validationLibs.some((lib) => lib in allDeps)) return [];

      return [
        {
          checkId: 'AUTH022',
          title: 'No Input Validation Library',
          message:
            'API project without an input validation library. Validate all user input against a schema to prevent injection and type confusion.',
          severity: ctx.config.severityOverrides.get('AUTH022') ?? 'medium',
          category: 'auth',
          fix: '1. Install a validation library (zod, joi, yup, or ajv).\n2. Define schemas for all API request bodies, query params, and path params.\n3. Validate input at the start of every handler before processing.',
          fixCode: `// Using zod (recommended):
import { z } from 'zod';

const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  age: z.number().int().min(0).max(150).optional(),
});

export async function POST(req: Request) {
  const body = CreateUserSchema.parse(await req.json());
  // body is now fully typed and validated
}`,
        },
      ];
    },
  } satisfies ProjectCheck,
];
