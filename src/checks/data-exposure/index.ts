import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const dataExposureChecks: CheckDefinition[] = [
  // DATA001 - NEXT_PUBLIC_ Secret Leak
  createLineCheck({
    id: 'DATA001',
    category: 'data-exposure',
    name: 'Secret Exposed via NEXT_PUBLIC_ Variable',
    severity: 'critical',
    pattern:
      /NEXT_PUBLIC_(?:SECRET|PRIVATE|TOKEN|PASSWORD|API_SECRET|DB_|DATABASE|SUPABASE_SERVICE|STRIPE_SECRET|AUTH_SECRET|JWT_SECRET)\w*\s*=/g,
    appliesTo: ['env'],
    message:
      'Variables starting with NEXT_PUBLIC_ are sent to the browser. This secret is visible to everyone.',
    fix: '1. Remove the NEXT_PUBLIC_ prefix so this variable stays server-side only.\n2. Access it through a server-side API route or server component instead.\n3. Never expose secrets, tokens, or passwords to the browser.',
    fixCode: `# Dangerous - sent to the browser:
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc123

# Safe - server-only (no NEXT_PUBLIC_ prefix):
STRIPE_SECRET_KEY=sk_live_abc123`,
  }),

  // DATA002 - Stack Trace in Response
  createLineCheck({
    id: 'DATA002',
    category: 'data-exposure',
    name: 'Stack Trace Sent in Response',
    severity: 'high',
    pattern: /(?:err|error)\.stack/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Only flag if the line or nearby context suggests sending to a response
      const lower = line.toLowerCase();
      if (
        lower.includes('res.') ||
        lower.includes('response.') ||
        lower.includes('json(') ||
        lower.includes('send(') ||
        lower.includes('status(')
      ) {
        return true;
      }
      // Also flag if it appears in an object being returned/sent
      if (lower.includes('stack:') || lower.includes('stack,')) {
        return true;
      }
      return false;
    },
    message:
      'Error stack traces are sent to users. These reveal your file structure and code internals to attackers.',
    fix: '1. Log the full error server-side for debugging.\n2. Send a generic error message to the client.\n3. Use different error handling for development vs production.',
    fixCode: `// Dangerous:
res.json({ error: err.message, stack: err.stack });

// Safe:
console.error(err); // log full error server-side
res.status(500).json({ error: 'Internal server error' });`,
  }),

  // DATA003 - Debug Endpoint
  createLineCheck({
    id: 'DATA003',
    category: 'data-exposure',
    name: 'Debug Endpoint Exposed',
    severity: 'critical',
    pattern:
      /(?:app|router)\.(?:get|post|all)\s*\(\s*['"]\/(?:debug|_debug|_internal|phpinfo|test\/)/g,
    appliesTo: ['js', 'ts'],
    message:
      'Debug endpoints are exposed. Attackers can use these to discover your server\'s internals.',
    fix: '1. Remove debug endpoints before deploying to production.\n2. If needed for development, gate them behind NODE_ENV === "development".\n3. Use a middleware that disables these routes in production.',
    fixCode: `// Dangerous:
app.get('/debug/env', (req, res) => res.json(process.env));

// Safe - only in development:
if (process.env.NODE_ENV === 'development') {
  app.get('/debug/env', (req, res) => res.json(process.env));
}`,
  }),

  // DATA004 - process.env Exposed in Response
  createLineCheck({
    id: 'DATA004',
    category: 'data-exposure',
    name: 'All Environment Variables Sent in Response',
    severity: 'critical',
    pattern: /(?:res\.(?:json|send)|JSON\.stringify)\s*\(\s*process\.env\b/g,
    appliesTo: ['js', 'ts'],
    message:
      'All environment variables (including secrets) are sent in a response. This exposes everything.',
    fix: '1. Never send process.env in a response.\n2. If you need to expose specific config values, pick them explicitly.\n3. Remove any debug endpoints that expose environment variables.',
    fixCode: `// Dangerous:
res.json(process.env);

// Safe - only expose what's needed:
res.json({
  nodeEnv: process.env.NODE_ENV,
  appVersion: process.env.APP_VERSION,
});`,
  }),

  // DATA005 - Console.log Sensitive Data
  createLineCheck({
    id: 'DATA005',
    category: 'data-exposure',
    name: 'Sensitive Data in Console Log',
    severity: 'low',
    pattern:
      /console\.log\s*\([^)]*(?:password|secret|token|apiKey|api_key|private_key|authToken|auth_token)/gi,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Only flag when a sensitive variable/key is being logged, not when a
      // sensitive word appears inside a string message.
      // e.g., flag: console.log(token)  console.log('data:', secret)
      // skip: console.log('Authenticated as:', email)  console.log('auth page')

      // Check if the sensitive word is inside a string literal (single/double/backtick)
      // by testing if it's preceded by a quote character within the console.log parens
      const inParens = line.slice(line.indexOf('console.log'));
      // If the ONLY sensitive words are inside string literals, skip
      const withoutStrings = inParens
        .replace(/'[^']*'/g, '')
        .replace(/"[^"]*"/g, '')
        .replace(/`[^`]*`/g, '');
      return /(?:password|secret|token|apiKey|api_key|private_key|authToken|auth_token)/i.test(withoutStrings);
    },
    message:
      'Sensitive data is logged to the console. In production, logs may be stored or visible to others.',
    fix: '1. Remove console.log statements that contain sensitive data.\n2. Use a structured logger that can redact sensitive fields.\n3. If logging for debugging, ensure it is stripped in production builds.',
    fixCode: `// Dangerous:
console.log('User token:', token);
console.log('Login attempt', { password: req.body.password });

// Safe - redact sensitive fields:
console.log('Login attempt', { email: req.body.email });
// Or use a logger with redaction:
logger.info('Auth event', { userId: user.id });`,
  }),

  // DATA006 - Source Maps Enabled in Production
  createLineCheck({
    id: 'DATA006',
    category: 'data-exposure',
    name: 'Source Maps Enabled in Production',
    severity: 'medium',
    pattern:
      /(?:productionBrowserSourceMaps|productionSourceMap|devtool)\s*[=:]\s*(?:true|['"]source-map['"])/g,
    appliesTo: ['js', 'ts', 'json'],
    message:
      'Source maps are enabled for production. Anyone can see your original source code.',
    fix: '1. Disable source maps in production builds.\n2. If you need source maps for error tracking, upload them privately to your error monitoring service (e.g. Sentry) and do not serve them publicly.',
    fixCode: `// next.config.js - Dangerous:
module.exports = { productionBrowserSourceMaps: true };

// next.config.js - Safe:
module.exports = { productionBrowserSourceMaps: false };

// webpack.config.js - Dangerous:
module.exports = { devtool: 'source-map' };

// webpack.config.js - Safe (production):
module.exports = { devtool: false };`,
  }),

  // DATA007 - Full DB Object in Response (LineCheck)
  createLineCheck({
    id: 'DATA007',
    category: 'data-exposure',
    name: 'Full DB Object in Response',
    severity: 'high',
    pattern: /(?:NextResponse\.json|res\.json|res\.send)\s*\(\s*(?:user|users|account|profile|customer|order|record)\s*\)/g,
    appliesTo: ['js', 'ts'],
    message:
      'A full database object is sent in the response. This likely includes sensitive fields like passwordHash, internal IDs, or personal data.',
    fix: 'Use `select` in your query or explicitly pick fields: `res.json({ id: user.id, name: user.name })`',
    fixCode: `// Dangerous:
res.json(user);

// Safe - pick specific fields:
res.json({ id: user.id, name: user.name, email: user.email });

// Or use select in the query:
const user = await db.user.findUnique({ where: { id }, select: { id: true, name: true } });`,
  }),

  // DATA008 - Secrets in URL Query Parameters (LineCheck)
  createLineCheck({
    id: 'DATA008',
    category: 'data-exposure',
    name: 'Secrets in URL Query Parameters',
    severity: 'medium',
    pattern: /(?:fetch|axios|got|http)\s*\(\s*`[^`]*\?[^`]*(?:token|password|secret|key|apiKey|api_key)=\$\{/g,
    appliesTo: ['js', 'ts'],
    message:
      'Tokens or secrets are passed in URL query parameters. These get logged in server access logs, browser history, and CDN logs.',
    fix: 'Pass secrets in request headers (Authorization header) instead.',
    fixCode: `// Dangerous:
fetch(\`https://api.example.com?token=\${token}\`);

// Safe - use Authorization header:
fetch('https://api.example.com', {
  headers: { Authorization: \`Bearer \${token}\` },
});`,
  }),

  // DATA009 - Error.tsx Leaks Error Details (LineCheck)
  createLineCheck({
    id: 'DATA009',
    category: 'data-exposure',
    name: 'Error Component Leaks Error Details',
    severity: 'medium',
    pattern: /\{[^}]*error\.(?:message|stack|cause|digest)/g,
    appliesTo: ['tsx', 'jsx'],
    validate(_match, _line) {
      // Since this is tsx/jsx only and the pattern is specific, we accept it broadly
      // and rely on the pattern being rare outside error components.
      return true;
    },
    message:
      'Error details are displayed to users. In production this can reveal SQL errors, file paths, and internal state.',
    fix: 'Display a generic error message. Log the full error server-side or to an error tracking service.',
    fixCode: `// Dangerous:
<p>{error.message}</p>

// Safe:
<p>Something went wrong. Please try again.</p>`,
  }),
];
