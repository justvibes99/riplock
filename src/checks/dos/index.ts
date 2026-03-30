import type {
  CheckDefinition,
  FileCheck,
  Finding,
  ScanContext,
} from '../types.js';
import { extractSnippet } from '../../utils/snippet.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const dosChecks: CheckDefinition[] = [
  // DOS001 - ReDoS Pattern
  createLineCheck({
    id: 'DOS001',
    category: 'dos',
    name: 'ReDoS Vulnerable Pattern',
    severity: 'high',
    pattern: /new\s+RegExp\s*\(\s*['"][^'"]*(?:\([^)]+[+*]\)[+*]|\([^)]+\|[^)]+\)[+*])[^'"]*['"]/g,
    appliesTo: ['js', 'ts'],
    message:
      'This regex has nested quantifiers or alternation with quantifiers that can cause catastrophic backtracking. An attacker can freeze your server with a crafted input string.',
    fix: '1. Simplify the regex to avoid nested quantifiers like (a+)+ or (a|b)*.\n2. Use the re2 library for regexes applied to untrusted input.\n3. Add a timeout when matching against user input.',
    fixCode: `// Dangerous - nested quantifiers cause exponential backtracking:
const pattern = new RegExp('(a+)+b');

// Safe - simplify the pattern:
const pattern = new RegExp('a+b');

// Safe - use re2 for untrusted input:
import RE2 from 're2';
const pattern = new RE2('user-provided-pattern');`,
  }),

  // DOS002 - No Request Timeout (FileCheck)
  {
    level: 'file',
    id: 'DOS002',
    name: 'No Request Timeout',
    description: 'HTTP server has no request timeout configured.',
    category: 'dos',
    defaultSeverity: 'medium',
    appliesTo: ['js', 'ts'],
    fastFilter: /createServer|express\s*\(|fastify/i,

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm there is an HTTP server in this file (not ORM/SDK clients)
      // Use a pattern that explicitly excludes createServerClient via negative lookbehind
      const hasHttpServer = /(?:(?:^|[^a-zA-Z])createServer\s*\(|express\s*\(|fastify\s*\(|new\s+Hapi\.Server)/im.test(content);
      const isOnlySdkClient = /createServerClient|createBrowserClient/.test(content) && !hasHttpServer;
      if (!hasHttpServer || isOnlySdkClient) return [];

      // Check for timeout configuration
      const timeoutPattern =
        /(?:\.timeout\s*=|\.setTimeout\s*\(|timeout\s*:|requestTimeout|connectionTimeout|server\.headersTimeout)/i;
      if (timeoutPattern.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with server creation
      const serverLinePattern = /(?:createServer\s*\(|express\s*\(|fastify\s*\(|new\s+Hapi\.Server)/i;
      let serverLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (serverLinePattern.test(lines[i])) {
          serverLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        serverLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'DOS002',
          title: 'No Request Timeout',
          message:
            'Your server has no request timeout. Slow requests can hold connections open and exhaust resources.',
          severity: ctx.config.severityOverrides.get('DOS002') ?? 'medium',
          category: 'dos',
          location: {
            filePath: file.relativePath,
            startLine: serverLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Set a request timeout on your server to close slow or idle connections.',
          fixCode: `// For Node.js HTTP server:
server.timeout = 30000;       // 30 seconds
server.headersTimeout = 10000; // 10 seconds for headers

// For Express with a middleware:
import timeout from 'connect-timeout';
app.use(timeout('30s'));`,
        },
      ];
    },
  } satisfies FileCheck,

  // DOS003 - Unbounded Query
  createLineCheck({
    id: 'DOS003',
    category: 'dos',
    name: 'Unbounded Database Query',
    severity: 'medium',
    pattern: /\.(?:findMany|findAll)\s*\(\s*(?:\{[^}]*\}|\))/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // Not a problem if the line already has a limit
      if (lower.includes('take')) return false;
      if (lower.includes('limit')) return false;
      if (lower.includes('top')) return false;
      if (lower.includes('pagesize')) return false;
      if (lower.includes('per_page')) return false;
      if (lower.includes('perpage')) return false;
      // Skip findOne/findById which return a single result
      if (/\.findOne|\.findById|\.findUnique|\.findFirst/i.test(line)) return false;
      return true;
    },
    message:
      'Database query has no result limit. An attacker can request all records at once, crashing your server or using excessive memory.',
    fix: 'Always add a LIMIT/take/pageSize to queries. Set a reasonable maximum (e.g., 100).',
    fixCode: `// Dangerous - returns all rows:
const users = await db.user.findMany({});

// Safe - always limit results:
const users = await db.user.findMany({
  take: 100,
});

// SQL:
const results = await db.query('SELECT * FROM users LIMIT 100');`,
  }),

  // DOS004 - Missing Body Size Limit
  createLineCheck({
    id: 'DOS004',
    category: 'dos',
    name: 'Missing Body Size Limit',
    severity: 'medium',
    pattern: /express\.json\s*\(\s*\)/g,
    appliesTo: ['js', 'ts'],
    message:
      'express.json() has no size limit. Attackers can send huge JSON payloads to consume memory and crash your server.',
    fix: 'Add a size limit to express.json() to reject oversized request bodies.',
    fixCode: `// Dangerous - no size limit:
app.use(express.json());

// Safe - limit to 1MB:
app.use(express.json({ limit: '1mb' }));

// Also limit URL-encoded bodies:
app.use(express.urlencoded({ extended: true, limit: '1mb' }));`,
  }),

  // DOS005 - Unbounded GraphQL Query Depth (FileCheck)
  {
    level: 'file',
    id: 'DOS005',
    name: 'Unbounded GraphQL Query Depth',
    description:
      'Detects GraphQL servers without query depth or complexity limits.',
    category: 'dos',
    defaultSeverity: 'medium',
    appliesTo: ['js', 'ts'],
    fastFilter: /ApolloServer|GraphQLServer|createSchema|graphqlHTTP/,

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm file creates a GraphQL server
      const serverPattern = /(?:ApolloServer|GraphQLServer|createSchema|graphqlHTTP)/i;
      if (!serverPattern.test(content)) return [];

      // Check for depth/complexity limiting
      const limitPattern =
        /(?:depthLimit|queryComplexity|maxDepth|costAnalysis)/i;
      if (limitPattern.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with the GraphQL server setup
      let serverLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (serverPattern.test(lines[i])) {
          serverLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        serverLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'DOS005',
          title: 'Unbounded GraphQL Query Depth',
          message:
            'Your GraphQL server has no query depth or complexity limits. An attacker can send deeply nested queries to crash your server.',
          severity: ctx.config.severityOverrides.get('DOS005') ?? 'medium',
          category: 'dos',
          location: {
            filePath: file.relativePath,
            startLine: serverLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: '1. Install graphql-depth-limit or graphql-query-complexity.\n2. Add validation rules to your GraphQL server.',
          fixCode: `// Install: npm install graphql-depth-limit
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(10)],
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // DOS006 - No Connection Pool Limit
  createLineCheck({
    id: 'DOS006',
    category: 'dos',
    name: 'No Connection Pool Limit',
    severity: 'medium',
    pattern: /new\s+(?:Pool|createPool)\s*\(\s*\{/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      if (lower.includes('max')) return false;
      if (lower.includes('connectionlimit')) return false;
      if (lower.includes('poolsize')) return false;
      if (lower.includes('pool_size')) return false;
      return true;
    },
    message:
      'Database connection pool has no size limit. Under load, it can exhaust database connections.',
    fix: 'Set a maximum pool size to prevent connection exhaustion.',
    fixCode: `// Dangerous - no pool limit:
const pool = new Pool({ host: 'localhost' });

// Safe - set a max pool size:
const pool = new Pool({
  host: 'localhost',
  max: 20,  // PostgreSQL (pg)
});

// For MySQL:
const pool = mysql.createPool({
  host: 'localhost',
  connectionLimit: 20,
});`,
  }),

  // DOS007 - setTimeout/setInterval with User Input
  createLineCheck({
    id: 'DOS007',
    category: 'dos',
    name: 'Timer Duration from User Input',
    severity: 'high',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*[^,]+,\s*(?:req\.|body\.|query\.|params\.|input|parseInt\s*\(\s*req)/g,
    appliesTo: ['js', 'ts'],
    message:
      'Timer duration comes from user input. An attacker can set extremely long timeouts to consume resources.',
    fix: 'Never use user input directly as a timer duration. Validate and cap the value.',
    fixCode: `// Dangerous - user controls the delay:
setTimeout(callback, parseInt(req.query.delay));

// Safe - cap the value:
const MAX_DELAY = 30000; // 30 seconds
const delay = Math.min(parseInt(req.query.delay) || 0, MAX_DELAY);
setTimeout(callback, delay);`,
  }),
];
