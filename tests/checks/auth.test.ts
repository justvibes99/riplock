import { describe, it, expect } from 'vitest';
import { authChecks } from '../../src/checks/auth/index.js';
import { testLine, testFileCheck, testProjectCheck } from '../helpers.js';

describe('auth checks', () => {
  describe('AUTH001 - JWT Weak Secret', () => {
    it('flags jwt.sign with a hardcoded weak secret', () => {
      const result = testLine(authChecks, 'AUTH001', `jwt.sign(payload, 'secret')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH001');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('auth');
      expect(result!.message).toContain('JWT');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag jwt.sign with an env var', () => {
      const result = testLine(authChecks, 'AUTH001', `jwt.sign(payload, process.env.JWT_SECRET)`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH003 - Insecure Cookie Settings', () => {
    it('flags cookie with httpOnly: false', () => {
      const result = testLine(authChecks, 'AUTH003', `res.cookie('session', token, { httpOnly: false })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH003');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('auth');
      expect(result!.message).toContain('cookie');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('AUTH004 - Password Stored Without Hashing', () => {
    it('flags storing password directly from request body', () => {
      const result = testLine(authChecks, 'AUTH004', `create({ password: req.body.password })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH004');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('auth');
    });

    it('does not flag when bcrypt.hash is used', () => {
      const result = testLine(authChecks, 'AUTH004', `create({ password: await bcrypt.hash(req.body.password, 12) })`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH007 - Admin Route Without Role Check', () => {
    it('flags admin route without role middleware', () => {
      const result = testLine(authChecks, 'AUTH007', `app.get('/admin/users', handler)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH007');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('auth');
    });

    it('does not flag admin route with isAdmin middleware', () => {
      const result = testLine(authChecks, 'AUTH007', `app.get('/admin/users', isAdmin, handler)`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH009 - Cookie Set Without httpOnly', () => {
    it('flags res.cookie with no options', () => {
      const result = testLine(authChecks, 'AUTH009', `res.cookie('token', jwt);`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH009');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('auth');
    });
  });

  describe('AUTH010 - Unvalidated OAuth Redirect', () => {
    it('flags redirect URL taken from user input', () => {
      const result = testLine(authChecks, 'AUTH010', `callbackUrl = req.query.redirect`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH010');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('auth');
    });
  });

  describe('AUTH002 - JWT No Algorithm Restriction', () => {
    it('flags jwt.verify with no options (2-arg call)', () => {
      const result = testLine(authChecks, 'AUTH002', `jwt.verify(token, secret);`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH002');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('auth');
    });

    it('does not flag jwt.verify with options object', () => {
      const result = testLine(authChecks, 'AUTH002', `jwt.verify(token, secret, { algorithms: ['HS256'] })`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH015 - Race Condition on Balance/Credits', () => {
    it('flags .update with balance field and no transaction', () => {
      const result = testLine(authChecks, 'AUTH015', `.update({ balance: user.balance - amount })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH015');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('auth');
    });

    it('does not flag when $transaction is present', () => {
      const result = testLine(authChecks, 'AUTH015', `tx.user.update({ balance: user.balance - amount }) // inside $transaction`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH016 - Client-Side Role Check', () => {
    it('flags isAdmin in tsx file', () => {
      const result = testLine(authChecks, 'AUTH016', `{isAdmin && <AdminPanel />}`, 'tsx');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH016');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('auth');
    });

    it('still matches in ts file (appliesTo filtering is done by the scanner, not the check)', () => {
      // AUTH016 has appliesTo: ['jsx', 'tsx']. The scanner skips .ts files,
      // but the check itself does not enforce extension — so testLine still returns a finding.
      const result = testLine(authChecks, 'AUTH016', `if (isAdmin) { doStuff() }`, 'ts');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH016');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('auth');
    });
  });

  describe('AUTH017 - JWT Missing Audience/Issuer', () => {
    it('flags jwt.verify without audience or issuer', () => {
      const result = testLine(authChecks, 'AUTH017', `jwt.verify(token, secret)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('AUTH017');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('auth');
    });

    it('does not flag jwt.verify with audience', () => {
      const result = testLine(authChecks, 'AUTH017', `jwt.verify(token, secret, { audience: 'my-app' })`);
      expect(result).toBeNull();
    });
  });

  describe('AUTH005 - API Route Without Authentication', () => {
    it('flags API route file without auth', async () => {
      const content = `export async function GET(req: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}`;
      const findings = await testFileCheck(authChecks, 'AUTH005', content, {
        relativePath: 'api/users.ts',
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('AUTH005');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('auth');
    });

    it('does not flag API route file with getServerSession', async () => {
      const content = `import { getServerSession } from 'next-auth';
export async function GET(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  const users = await db.user.findMany();
  return Response.json(users);
}`;
      const findings = await testFileCheck(authChecks, 'AUTH005', content, {
        relativePath: 'api/users.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH006 - Missing Rate Limit on Authentication', () => {
    it('flags login handler without rate limiting', async () => {
      const content = `app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid' });
});`;
      const findings = await testFileCheck(authChecks, 'AUTH006', content, {
        relativePath: 'routes/auth.ts',
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('AUTH006');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('auth');
    });

    it('does not flag login handler with rateLimit', async () => {
      const content = `import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
export async function login(req, res) {
  const { email, password } = req.body;
}`;
      const findings = await testFileCheck(authChecks, 'AUTH006', content, {
        relativePath: 'auth/login.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH008 - Webhook Without Signature Verification', () => {
    it('flags webhook file using req.body without signature check', async () => {
      const content = `export default function handler(req, res) {
  const event = req.body;
  processEvent(event);
  res.status(200).send('ok');
}`;
      const findings = await testFileCheck(authChecks, 'AUTH008', content, {
        relativePath: 'api/webhook.ts',
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('AUTH008');
      expect(findings[0].severity).toBe('critical');
      expect(findings[0].category).toBe('auth');
    });

    it('does not flag webhook file with constructEvent', async () => {
      const content = `export default function handler(req, res) {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(req.body, sig, secret);
  processEvent(event);
  res.status(200).send('ok');
}`;
      const findings = await testFileCheck(authChecks, 'AUTH008', content, {
        relativePath: 'api/webhook.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH011 - Missing Ownership Check (IDOR)', () => {
    it('flags route modifying by params.id without ownership check', async () => {
      const content = `export async function DELETE(req, { params }) {
  await db.post.delete({ where: { id: params.id } });
  return Response.json({ ok: true });
}`;
      const findings = await testFileCheck(authChecks, 'AUTH011', content, {
        relativePath: 'app/api/posts/[id]/route.ts',
      });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH011');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('auth');
    });

    it('skips route that includes userId in query', async () => {
      const content = `export async function DELETE(req, { params }) {
  const session = await getServerSession();
  await db.post.delete({ where: { id: params.id, userId: session.user.id } });
  return Response.json({ ok: true });
}`;
      const findings = await testFileCheck(authChecks, 'AUTH011', content, {
        relativePath: 'app/api/posts/[id]/route.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH012 - GraphQL Mutations Without Auth', () => {
    it('flags Mutation resolvers without auth', async () => {
      const content = `const resolvers = {
  Mutation: {
    createPost: (_, args) => db.post.create(args),
    deletePost: (_, { id }) => db.post.delete(id),
  },
};`;
      const findings = await testFileCheck(authChecks, 'AUTH012', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH012');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('auth');
    });

    it('skips mutations that check context.user', async () => {
      const content = `const resolvers = {
  Mutation: {
    createPost: (_, args, context) => {
      if (!context.user) throw new Error('Unauthorized');
      return db.post.create(args);
    },
  },
};`;
      const findings = await testFileCheck(authChecks, 'AUTH012', content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH013 - Missing CSRF Protection', () => {
    it('flags session app without CSRF library', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH013', {
        packageJson: { dependencies: { 'express-session': '^1.17.0', express: '^4.18.0' } },
        detectedFrameworks: ['express'],
      });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH013');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
    });

    it('skips when CSRF library is present', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH013', {
        packageJson: { dependencies: { 'express-session': '^1.17.0', 'csrf-csrf': '^3.0.0' } },
        detectedFrameworks: ['express'],
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH014 - WebSocket Without Auth', () => {
    it('flags socket.io server without auth', async () => {
      const content = `import { Server } from 'socket.io';
const io = new Server(httpServer);
io.on('connection', (socket) => {
  socket.on('message', (data) => console.log(data));
});`;
      const findings = await testFileCheck(authChecks, 'AUTH014', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH014');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
    });

    it('skips when auth is checked in connection handler', async () => {
      const content = `import { Server } from 'socket.io';
const io = new Server(httpServer);
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (verifyToken(token)) next();
});
io.on('connection', (socket) => {
  socket.on('message', (data) => console.log(data));
});`;
      const findings = await testFileCheck(authChecks, 'AUTH014', content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH019 - No Account Lockout', () => {
    it('flags login handler without lockout mechanism', async () => {
      const content = `app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid' });
  req.session.user = user;
  res.json({ ok: true });
});`;
      const findings = await testFileCheck(authChecks, 'AUTH019', content, {
        relativePath: 'routes/login.ts',
      });
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('AUTH019');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
      expect(findings[0].message).toContain('lockout');
    });

    it('does not flag login handler with maxAttempts', async () => {
      const content = `app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  if (user.failedAttempts >= MAX_LOGIN_ATTEMPTS) {
    return res.status(423).json({ error: 'Account locked' });
  }
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    await db.user.update({ where: { id: user.id }, data: { failedAttempts: { increment: 1 } } });
    return res.status(401).json({ error: 'Invalid' });
  }
  req.session.user = user;
  res.json({ ok: true });
});`;
      const findings = await testFileCheck(authChecks, 'AUTH019', content, {
        relativePath: 'routes/login.ts',
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag login handler with rate limiting', async () => {
      const content = `import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const valid = await bcrypt.compare(password, user.passwordHash);
});`;
      const findings = await testFileCheck(authChecks, 'AUTH019', content, {
        relativePath: 'routes/login.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH020 - Session Not Regenerated After Login', () => {
    it('flags session assignment without regeneration', async () => {
      const content = `app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.user = user;
  res.redirect('/dashboard');
});`;
      const findings = await testFileCheck(authChecks, 'AUTH020', content);
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('AUTH020');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
      expect(findings[0].message).toContain('regenerat');
    });

    it('does not flag when session.regenerate is called', async () => {
      const content = `app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.regenerate((err) => {
    req.session.user = user;
    res.redirect('/dashboard');
  });
});`;
      const findings = await testFileCheck(authChecks, 'AUTH020', content);
      expect(findings).toHaveLength(0);
    });

    it('does not flag when session.destroy is called', async () => {
      const content = `app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  session.destroy();
  req.session.user = user;
  res.redirect('/dashboard');
});`;
      const findings = await testFileCheck(authChecks, 'AUTH020', content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH021 - No Authentication Event Logging', () => {
    it('flags project with auth files but no auth logging', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH021', {
        files: {
          'routes/login.ts': `app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid' });
  res.json({ ok: true });
});`,
        },
      });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH021');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
      expect(findings[0].message).toContain('logging');
    });

    it('does not flag when auditLog function exists', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH021', {
        files: {
          'routes/login.ts': `app.post('/login', async (req, res) => {
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    auditLog('login_failure', { email, ip: req.ip });
    return res.status(401).json({ error: 'Invalid' });
  }
});`,
        },
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag project without auth files', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH021', {
        files: {
          'routes/users.ts': `app.get('/users', async (req, res) => {
  const users = await db.user.findMany();
  res.json(users);
});`,
        },
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('AUTH022 - No Input Validation Library', () => {
    it('flags API project without validation library', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH022', {
        files: {
          'api/users.ts': `export async function POST(req) { return Response.json({}); }`,
        },
        packageJson: { dependencies: { express: '^4.18.0' } },
      });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].checkId).toBe('AUTH022');
      expect(findings[0].severity).toBe('medium');
      expect(findings[0].category).toBe('auth');
      expect(findings[0].message).toContain('validation');
    });

    it('does not flag when zod is installed', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH022', {
        files: {
          'api/users.ts': `export async function POST(req) { return Response.json({}); }`,
        },
        packageJson: { dependencies: { express: '^4.18.0', zod: '^3.0.0' } },
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag when joi is in devDependencies', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH022', {
        files: {
          'api/users.ts': `export async function POST(req) { return Response.json({}); }`,
        },
        packageJson: { dependencies: { express: '^4.18.0' }, devDependencies: { joi: '^17.0.0' } },
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag project without API routes', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH022', {
        files: {
          'src/utils.ts': `export function helper() { return 1; }`,
        },
        packageJson: { dependencies: { express: '^4.18.0' } },
      });
      expect(findings).toHaveLength(0);
    });

    it('does not flag when no package.json exists', async () => {
      const findings = await testProjectCheck(authChecks, 'AUTH022', {
        files: {
          'api/users.ts': `export async function POST(req) { return Response.json({}); }`,
        },
        packageJson: null,
      });
      expect(findings).toHaveLength(0);
    });
  });

  describe('Regression: real-world false positives', () => {
    it('AUTH005: skips webhook routes by path (not just basename)', async () => {
      const content = `import Stripe from 'stripe';
export async function POST(req) {
  const body = await req.text();
  const event = stripe.webhooks.constructEvent(body, sig, secret);
}`;
      // The file is at api/webhooks/stripe/route.ts — basename is "route.ts"
      // but path contains "webhook" which should cause it to be skipped
      const findings = await testFileCheck(authChecks, 'AUTH005', content, {
        relativePath: 'src/app/api/webhooks/stripe/route.ts',
      });
      expect(findings).toHaveLength(0);
    });

    it('AUTH006: does not flag file containing "designing" (substring of signin)', async () => {
      // "designing" contains "signin" as a substring — should NOT trigger
      const content = `export async function POST(req) {
  const prompt = "You are an expert designing individualized training programs";
  return Response.json({ result: await generate(prompt) });
}`;
      const findings = await testFileCheck(authChecks, 'AUTH006', content, {
        relativePath: 'src/app/api/generate/route.ts',
      });
      expect(findings).toHaveLength(0);
    });
  });
});
