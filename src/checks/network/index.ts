import type {
  CheckDefinition,
  ProjectCheck,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const networkChecks: CheckDefinition[] = [
  // NET001 - Open CORS
  createLineCheck({
    id: 'NET001',
    category: 'network',
    name: 'Open CORS Policy',
    severity: 'high',
    pattern:
      /(?:origin\s*:\s*(?:true|['"]\*['"])|Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"])/g,
    appliesTo: ['js', 'ts'],
    severityOverride(line) {
      // Upgrade to critical if credentials are also enabled
      if (/credentials\s*:\s*true/i.test(line)) return 'critical';
      return null;
    },
    message:
      'Your API allows requests from any website. A malicious site can make requests using your users\' cookies.',
    fix: '1. Set a specific list of allowed origins instead of "*".\n2. Never combine wildcard origin with credentials: true.\n3. Validate the Origin header against an allowlist.',
    fixCode: `// Dangerous:
app.use(cors({ origin: '*' }));

// Safe - specify allowed origins:
app.use(cors({
  origin: ['https://myapp.com', 'https://staging.myapp.com'],
  credentials: true,
}));`,
  }),

  // NET002 - Missing Helmet (ProjectCheck)
  {
    level: 'project',
    id: 'NET002',
    name: 'Missing Security Headers (Helmet)',
    description:
      'Express or Fastify project without the helmet security headers package.',
    category: 'network',
    defaultSeverity: 'medium',

    async analyze(ctx: ScanContext): Promise<Finding[]> {
      // Only relevant if express or fastify is detected
      const hasExpressOrFastify = ctx.detectedFrameworks.some((f) =>
        /^(express|fastify)$/i.test(f),
      );
      if (!hasExpressOrFastify) return [];

      // Check if helmet is already a dependency
      if (ctx.packageJson) {
        const allDeps = {
          ...ctx.packageJson.dependencies,
          ...ctx.packageJson.devDependencies,
        };
        if ('helmet' in allDeps) return [];
      }

      return [
        {
          checkId: 'NET002',
          title: 'Missing Security Headers (Helmet)',
          message:
            'Your server is missing security headers. The `helmet` package adds them in one line.',
          severity:
            ctx.config.severityOverrides.get('NET002') ?? 'medium',
          category: 'network',
          location: undefined,
          fix: '1. Install helmet: npm install helmet\n2. Add it as middleware: app.use(helmet())\n3. This sets headers like X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options, and more.',
          fixCode: `// Install: npm install helmet
import helmet from 'helmet';
app.use(helmet());`,
        },
      ];
    },
  } satisfies ProjectCheck,

  // NET003 removed — duplicated by INJ014 (SSRF) which has a tighter pattern

  // NET004 - HTTP URLs (non-localhost)
  createLineCheck({
    id: 'NET004',
    category: 'network',
    name: 'Insecure HTTP URL',
    severity: 'medium',
    pattern:
      /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"]/g,
    appliesTo: ['js', 'ts', 'json', 'env'],
    validate(_match, line) {
      // Skip XML/SVG namespace URIs — these are identifiers, not network requests
      if (/xmlns|w3\.org|xmlsoap\.org|schemas\.microsoft|purl\.org/i.test(line)) return false;
      // Skip schema.org and other well-known non-network URIs
      if (/schema\.org|doctype|dtd/i.test(line)) return false;
      return true;
    },
    message:
      'External connection uses plain HTTP. Data can be intercepted by anyone on the network.',
    fix: '1. Replace http:// with https:// for all external URLs.\n2. If the service does not support HTTPS, consider a different provider.\n3. For APIs, always use TLS-encrypted connections.',
    fixCode: `// Dangerous:
const apiUrl = 'http://api.example.com/data';

// Safe:
const apiUrl = 'https://api.example.com/data';`,
  }),

  // NET005 - Internal URLs in Client-Side Env Vars
  createLineCheck({
    id: 'NET005',
    category: 'network',
    name: 'Internal URL Exposed in Client-Side Config',
    severity: 'medium',
    pattern:
      /(?:NEXT_PUBLIC|REACT_APP|VITE)_\w*(?:URL|HOST|ENDPOINT)\s*=\s*['"]?http:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    message:
      'Internal server addresses are exposed in client-side code, revealing your infrastructure.',
    fix: '1. Use a public-facing URL or API gateway instead of internal addresses.\n2. Move internal URLs to server-only environment variables (without NEXT_PUBLIC_, REACT_APP_, or VITE_ prefix).\n3. Use a reverse proxy to hide internal services.',
    fixCode: `// Dangerous:
NEXT_PUBLIC_API_URL=http://192.168.1.50:3000

// Safe - use a public URL or proxy:
NEXT_PUBLIC_API_URL=https://api.myapp.com`,
  }),

  // NET006 - cors() with No Arguments
  createLineCheck({
    id: 'NET006',
    category: 'network',
    name: 'cors() with No Arguments',
    severity: 'high',
    pattern: /cors\s*\(\s*\)/g,
    appliesTo: ['js', 'ts'],
    message:
      'cors() with no arguments defaults to allowing ALL origins. This is the same as setting origin: \'*\'.',
    fix: 'Specify allowed origins explicitly instead of calling cors() with no arguments.',
    fixCode: `// Dangerous:
app.use(cors());

// Safe - specify allowed origins:
app.use(cors({
  origin: ['https://myapp.com', 'https://staging.myapp.com'],
}));`,
  }),

  // NET007 - MongoDB Without Auth
  createLineCheck({
    id: 'NET007',
    category: 'network',
    name: 'MongoDB Without Auth',
    severity: 'medium',
    pattern: /mongodb:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+\/\w+['"](?!.*@)/g,
    appliesTo: ['js', 'ts'],
    message:
      'MongoDB connection has no authentication. On a server, this database is open to the network.',
    fix: '1. Add authentication credentials to the MongoDB connection string.\n2. Enable MongoDB authentication and create a dedicated database user.',
    fixCode: `// Dangerous:
mongoose.connect('mongodb://localhost:27017/mydb');

// Safe - with authentication:
mongoose.connect('mongodb://user:password@localhost:27017/mydb?authSource=admin');

// Best - use environment variable:
mongoose.connect(process.env.MONGODB_URI);`,
  }),

  // NET008 - CORS Origin Reflection
  createLineCheck({
    id: 'NET008',
    category: 'network',
    name: 'CORS Origin Reflection',
    severity: 'high',
    pattern: /origin\s*:\s*(?:req\.headers\.origin|req\.header\s*\(\s*['"]origin['"]\)|req\.get\s*\(\s*['"]origin['"]\))/gi,
    appliesTo: ['js', 'ts'],
    message:
      "CORS origin is set to whatever the browser sends. This is equivalent to allowing all origins but WORSE — it also works with credentials, letting any site make authenticated requests.",
    fix: 'Validate the origin against an explicit allowlist of trusted domains instead of reflecting it back.',
    fixCode: `// Dangerous - reflects the origin:
app.use(cors({
  origin: req.headers.origin,
  credentials: true,
}));

// Safe - validate against an allowlist:
const ALLOWED_ORIGINS = ['https://myapp.com', 'https://staging.myapp.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));`,
  }),
];
