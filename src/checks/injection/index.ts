import type { CheckDefinition, FileCheck, FileEntry, LineMatch, Finding, ScanContext } from '../types.js';
import { createLineCheck, isCommentLine, hasUserInput } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---- Checks ----

export const injectionChecks: CheckDefinition[] = [
  // INJ001 - SQL Injection (Template Literal)
  {
    level: 'line' as const,
    id: 'INJ001',
    name: 'SQL Injection (Template Literal)',
    description: 'SQL query built with template literal interpolation.',
    category: 'injection' as const,
    defaultSeverity: 'critical' as const,
    pattern: /(?:query|exec|execute|run|raw|prepare|sql)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+(?:FROM|INTO|SET|TABLE|\*)[^`]*\$\{|`\s*(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE)\s[^`]*\$\{/gi,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    analyze(match: LineMatch, ctx: ScanContext): Finding | null {
      if (isCommentLine(match.line)) return null;

      const userInput = hasUserInput(match.line);
      const severity = userInput ? 'critical' : 'high';

      const lines = match.file.lines ?? [];
      const { snippet, contextBefore, contextAfter } = extractSnippet(lines, match.lineNumber, ctx.config.contextLines);

      return {
        checkId: 'INJ001',
        title: userInput ? 'SQL Injection (Template Literal)' : 'Dynamic SQL with Template Literal',
        message: userInput
          ? 'User input is inserted directly into a database query. An attacker can modify the query to read, change, or delete all your data.'
          : 'A SQL query is built with template literal interpolation. Use parameterized queries to prevent SQL injection if these values ever come from user input.',
        severity: ctx.config.severityOverrides.get('INJ001') ?? severity,
        category: 'injection',
        location: { filePath: match.file.relativePath, startLine: match.lineNumber, startColumn: match.regexMatch.index },
        snippet, contextBefore, contextAfter,
        fix: '1. Use parameterized queries instead of template literals.\n2. Pass user values as parameters, never inside the query string.',
        fixCode: `// Dangerous:\ndb.query(\`SELECT * FROM users WHERE id = \${userId}\`);\n\n// Safe - use parameterized queries:\ndb.query('SELECT * FROM users WHERE id = $1', [userId]);`,
      };
    },
  },

  // INJ002 - SQL Injection (String Concat)
  createLineCheck({
    id: 'INJ002',
    category: 'injection',
    name: 'SQL Injection (String Concatenation)',
    severity: 'critical',
    pattern: /(?:query|exec|execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^'"]*['"]\s*\+/gi,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    message:
      'User input is inserted directly into a database query. An attacker can modify the query to read, change, or delete all your data.',
    fix: '1. Replace string concatenation with parameterized queries.\n2. Never build SQL by joining strings with user input.',
    fixCode: `// Dangerous:
db.query("SELECT * FROM users WHERE name = '" + name + "'");

// Safe - use parameterized queries:
db.query('SELECT * FROM users WHERE name = $1', [name]);`,
  }),

  // INJ003 - NoSQL Injection (MongoDB)
  createLineCheck({
    id: 'INJ003',
    category: 'injection',
    name: 'NoSQL Injection (MongoDB)',
    severity: 'high',
    pattern: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\(\s*(?:req\.(?:body|query|params)|JSON\.parse)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input goes directly to a MongoDB query. An attacker can send special objects like {"$gt": ""} to bypass filters.',
    fix: '1. Validate and sanitize input before passing it to MongoDB queries.\n2. Use a schema validation library (e.g. Joi, zod) to enforce expected types.\n3. Strip keys starting with "$" from user input.',
    fixCode: `// Dangerous:
User.find(req.body);

// Safe - validate and pick only expected fields:
const { email } = req.body;
User.find({ email: String(email) });`,
  }),

  // INJ004 - Command Injection (exec)
  {
    level: 'line' as const,
    id: 'INJ004',
    name: 'Command Injection (exec)',
    description: 'Shell command execution with string interpolation.',
    category: 'injection' as const,
    defaultSeverity: 'critical' as const,
    pattern: /(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/g,
    appliesTo: ['js', 'ts'],
    analyze(match: LineMatch, ctx: ScanContext): Finding | null {
      if (isCommentLine(match.line)) return null;
      // Skip execFile which uses array args and is safer
      if (match.line.includes('execFile')) return null;
      // Skip db.exec, sqlite.exec — these are SQL, not shell
      if (/(?:db|sqlite|sequelize|knex|prisma|connection|pool|client)\.\s*exec/i.test(match.line)) return null;

      // Determine severity: CRITICAL if user input is involved, MEDIUM otherwise
      const userInput = hasUserInput(match.line);
      const severity = userInput ? 'critical' : 'medium';

      const lines = match.file.lines ?? [];
      const { snippet, contextBefore, contextAfter } = extractSnippet(lines, match.lineNumber, ctx.config.contextLines);

      return {
        checkId: 'INJ004',
        title: userInput ? 'Command Injection (exec)' : 'Shell Command with String Interpolation',
        message: userInput
          ? 'User input is passed to a system command. An attacker can add commands like "; rm -rf /" to take over your server.'
          : 'A shell command is built with string interpolation. Use execFile() with array arguments instead — this is safer even with internal variables.',
        severity: ctx.config.severityOverrides.get('INJ004') ?? severity,
        category: 'injection',
        location: { filePath: match.file.relativePath, startLine: match.lineNumber },
        snippet, contextBefore, contextAfter,
        fix: '1. Use execFile() or spawn() with an array of arguments instead of exec().\n2. Never pass user input into a shell command string.',
        fixCode: `// Dangerous:\nexec(\`ls \${userInput}\`);\n\n// Safe - use execFile with array args:\nexecFile('ls', [userInput]);`,
      };
    },
  },

  // INJ005 - Command Injection (Python)
  createLineCheck({
    id: 'INJ005',
    category: 'injection',
    name: 'Command Injection (Python)',
    severity: 'critical',
    pattern: /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*(?:f['"]|.*\.format\()/g,
    appliesTo: ['py'],
    message:
      'User input is passed to a system command. An attacker can inject additional commands to take over your server.',
    fix: '1. Use subprocess.run() with a list of arguments and shell=False.\n2. Never use f-strings or .format() to build shell commands.',
    fixCode: `# Dangerous:
subprocess.run(f"ls {user_input}", shell=True)

# Safe - use a list of arguments:
subprocess.run(["ls", user_input], shell=False)`,
  }),

  // INJ006 - Path Traversal
  createLineCheck({
    id: 'INJ006',
    category: 'injection',
    name: 'Path Traversal',
    severity: 'high',
    pattern: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input determines which file to read or write. An attacker can use "../" to access sensitive files like /etc/passwd or your .env.',
    fix: '1. Use path.resolve() and verify the resolved path is inside the allowed directory.\n2. Reject any input containing ".." or absolute paths.\n3. Use a whitelist of allowed filenames when possible.',
    fixCode: `// Dangerous:
fs.readFileSync(req.query.filename);

// Safe - resolve and validate the path:
const resolved = path.resolve(UPLOADS_DIR, req.query.filename);
if (!resolved.startsWith(UPLOADS_DIR)) {
  return res.status(403).send('Access denied');
}
fs.readFileSync(resolved);`,
  }),

  // INJ007 - XSS innerHTML
  createLineCheck({
    id: 'INJ007',
    category: 'injection',
    name: 'XSS via innerHTML',
    severity: 'high',
    pattern: /\.innerHTML\s*[=+](?!=)/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx', 'html'],
    validate(_match, line) {
      // Skip static string assignments: .innerHTML = '...' or .innerHTML = "..."
      // Also skip template literals with no interpolation
      const afterInner = line.slice(line.indexOf('innerHTML'));
      // Static single-quoted string (may contain double quotes inside)
      if (/innerHTML\s*=\s*'[^']*'\s*;?\s*$/.test(afterInner)) return false;
      // Static double-quoted string (may contain single quotes inside)
      if (/innerHTML\s*=\s*"[^"]*"\s*;?\s*$/.test(afterInner)) return false;
      // Template literal without interpolation (no ${})
      if (/innerHTML\s*=\s*`[^`]*`\s*;?\s*$/.test(afterInner) && !/\$\{/.test(afterInner)) return false;
      // Assignment to empty string
      if (/innerHTML\s*=\s*['"]{2}\s*;?\s*$/.test(afterInner)) return false;
      return true;
    },
    message:
      'Setting innerHTML with dynamic content lets attackers inject scripts that steal cookies and passwords.',
    fix: '1. Use textContent instead of innerHTML for plain text.\n2. If you need HTML, sanitize with DOMPurify before inserting.\n3. In frameworks, use their built-in escaping (React JSX, Vue templates).',
    fixCode: `// Dangerous:
el.innerHTML = userInput;

// Safe - for text:
el.textContent = userInput;

// Safe - for HTML (with DOMPurify):
el.innerHTML = DOMPurify.sanitize(userInput);`,
  }),

  // INJ008 - XSS dangerouslySetInnerHTML
  createLineCheck({
    id: 'INJ008',
    category: 'injection',
    name: 'XSS via dangerouslySetInnerHTML',
    severity: 'high',
    pattern: /dangerouslySetInnerHTML/g,
    appliesTo: ['jsx', 'tsx'],
    validate(_match, line) {
      // Skip if the value is wrapped in DOMPurify.sanitize
      return !line.includes('DOMPurify.sanitize');
    },
    message:
      'React named this "dangerously" for a reason. If the content comes from users, attackers can inject scripts.',
    fix: '1. Sanitize the HTML with DOMPurify before passing it.\n2. Consider whether you truly need raw HTML, or if a markdown renderer or text would suffice.',
    fixCode: `// Dangerous:
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// Safe - sanitize first:
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />`,
  }),

  // INJ009 - eval()
  createLineCheck({
    id: 'INJ009',
    category: 'injection',
    name: 'eval() Usage',
    severity: 'critical',
    pattern: /\beval\s*\(/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    validate(_match, line) {
      // Skip if in a comment
      return !isCommentLine(line);
    },
    message:
      'eval() runs any string as code. If an attacker can influence what is passed to eval, they control your server.',
    fix: '1. Replace eval() with JSON.parse() if you are parsing JSON.\n2. Use a safe expression parser (e.g. mathjs, expr-eval) for math.\n3. If you need dynamic behavior, use a sandboxed approach or a configuration-driven design.',
    fixCode: `// Dangerous:
eval(userInput);

// Safe - for JSON:
const data = JSON.parse(userInput);

// Safe - for math expressions:
import { evaluate } from 'mathjs';
const result = evaluate(expression);`,
  }),

  // INJ010 - new Function()
  createLineCheck({
    id: 'INJ010',
    category: 'injection',
    name: 'new Function() Usage',
    severity: 'critical',
    pattern: /new\s+Function\s*\(/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    message:
      'new Function() is eval() in disguise. It compiles and runs arbitrary strings as code.',
    fix: '1. Replace with JSON.parse(), a safe expression parser, or a configuration-driven approach.\n2. If absolutely necessary, use a sandboxed environment (e.g. vm2, isolated-vm).',
    fixCode: `// Dangerous:
const fn = new Function('return ' + userInput);

// Safe - use a dedicated parser or configuration:
const config = JSON.parse(userInput);`,
  }),

  // INJ011 - document.write
  createLineCheck({
    id: 'INJ011',
    category: 'injection',
    name: 'document.write Usage',
    severity: 'medium',
    pattern: /document\.write\s*\(/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx', 'html'],
    message:
      'document.write() can overwrite the entire page and is an XSS risk when used with dynamic content. Modern browsers may also block it in some contexts.',
    fix: '1. Use DOM methods like document.createElement() or element.textContent.\n2. In frameworks, use the standard rendering approach (React JSX, Vue templates, etc.).',
    fixCode: `// Dangerous:
document.write('<p>' + userInput + '</p>');

// Safe:
const p = document.createElement('p');
p.textContent = userInput;
document.body.appendChild(p);`,
  }),

  // INJ012 - Prototype Pollution
  createLineCheck({
    id: 'INJ012',
    category: 'injection',
    name: 'Prototype Pollution',
    severity: 'high',
    pattern: /(?:Object\.assign\s*\([^)]*(?:req\.body|req\.query|req\.params)|\.\.\.(?:req\.body|req\.query|req\.params))/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input merged into objects can let attackers modify application behavior via __proto__ or constructor.prototype.',
    fix: '1. Validate that user input does not contain __proto__, constructor, or prototype keys.\n2. Use Object.create(null) as the target for merges.\n3. Use a schema validation library (zod, Joi) to whitelist allowed fields.',
    fixCode: `// Dangerous:
const settings = Object.assign({}, req.body);

// Safe - validate and pick specific fields:
const { theme, language } = req.body;
const settings = { theme, language };

// Or strip dangerous keys:
function sanitize(obj) {
  const clean = Object.create(null);
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    clean[key] = obj[key];
  }
  return clean;
}`,
  }),

  // INJ013 - Open Redirect
  createLineCheck({
    id: 'INJ013',
    category: 'injection',
    name: 'Open Redirect',
    severity: 'medium',
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*(?:=|\()\s*(?:req\.|params\.|query\.)/g,
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    message:
      'Redirecting to a user-provided URL lets attackers send your users to phishing sites that look like yours.',
    fix: '1. Validate the redirect URL against an allowlist of trusted domains.\n2. Only allow relative paths, not full URLs.\n3. Use URL parsing to verify the hostname before redirecting.',
    fixCode: `// Dangerous:
res.redirect(req.query.next);

// Safe - allow only relative paths:
const next = req.query.next;
if (!next || !next.startsWith('/') || next.startsWith('//')) {
  return res.redirect('/');
}
res.redirect(next);`,
  }),

  // INJ014 - SSRF
  createLineCheck({
    id: 'INJ014',
    category: 'injection',
    name: 'Server-Side Request Forgery (SSRF)',
    severity: 'critical',
    pattern: /(?:fetch|axios\.(?:get|post|put)|got|http\.get|https\.get)\s*\(\s*(?:req\.(?:query|params|body)\.\w|params\.\w|query\.\w|body\.\w|`[^`]*\$\{[^}]*(?:req\.|params\.|query\.|body\.))/g,
    appliesTo: ['js', 'ts'],
    message:
      'Your server fetches a URL from user input. An attacker can use this to access internal services, cloud metadata endpoints, or private APIs.',
    fix: '1. Validate and allowlist the target URL, hostname, or IP before fetching.\n2. Block private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254, etc.).\n3. Use a URL parser to verify the hostname, and do not follow redirects blindly.',
    fixCode: `// Dangerous:
const response = await fetch(req.query.url);

// Safe - validate against an allowlist:
const url = new URL(req.query.url);
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
if (!ALLOWED_HOSTS.includes(url.hostname)) {
  return res.status(400).send('Host not allowed');
}
const response = await fetch(url.toString());`,
  }),

  // INJ015 - Regex Injection
  createLineCheck({
    id: 'INJ015',
    category: 'injection',
    name: 'Regex Injection (ReDoS)',
    severity: 'medium',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input used to create a regex can crash your server via catastrophic backtracking (ReDoS) or match unintended content.',
    fix: '1. Escape special regex characters in user input before using it in a RegExp.\n2. Use a library like escape-string-regexp.\n3. Consider whether a simple string includes/startsWith check would work instead.',
    fixCode: `// Dangerous:
const pattern = new RegExp(req.query.search);

// Safe - escape special characters:
function escapeRegExp(str) {
  return str.replace(/[.*+?^\${}()|[\\]\\\\]/g, '\\\\$&');
}
const pattern = new RegExp(escapeRegExp(req.query.search));`,
  }),

  // INJ016 - Template Injection
  createLineCheck({
    id: 'INJ016',
    category: 'injection',
    name: 'Server-Side Template Injection (SSTI)',
    severity: 'critical',
    pattern: /(?:ejs|pug|handlebars|nunjucks|mustache)\.(?:render|compile)\s*\(\s*(?:req\.|body\.|query\.)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input is used as a template, not template data. An attacker can execute arbitrary code on your server.',
    fix: '1. Never pass user input as the template source. Pass it as data to a pre-defined template.\n2. Keep templates in files, not in user-controlled strings.',
    fixCode: `// Dangerous - user input IS the template:
ejs.render(req.body.template, data);

// Safe - user input is DATA for a fixed template:
ejs.render('<h1><%= title %></h1>', { title: req.body.title });`,
  }),

  // INJ017 - Prisma $queryRawUnsafe
  createLineCheck({
    id: 'INJ017',
    category: 'injection',
    name: 'Prisma $queryRawUnsafe',
    severity: 'critical',
    pattern: /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g,
    appliesTo: ['js', 'ts'],
    message:
      'Prisma\'s Unsafe raw query methods do not parameterize inputs. Use $queryRaw with tagged template literals instead.',
    fix: '1. Replace $queryRawUnsafe with $queryRaw using tagged template literals.\n2. Use Prisma.sql for dynamic query composition with parameterized values.',
    fixCode: `// Dangerous:
const result = await prisma.$queryRawUnsafe(
  \`SELECT * FROM users WHERE id = \${userId}\`
);

// Safe - use $queryRaw with tagged template:
const result = await prisma.$queryRaw\`
  SELECT * FROM users WHERE id = \${userId}
\`;`,
  }),

  // INJ018 - Mass Assignment via req.body spread
  createLineCheck({
    id: 'INJ018',
    category: 'injection',
    name: 'Mass Assignment via req.body Spread',
    severity: 'high',
    pattern: /\.(?:create|update|upsert)\s*\(\s*\{[^}]*(?:\.\.\.(?:req\.body|body|input|data)|data\s*:\s*(?:req\.body|body))/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input is spread directly into a database operation. An attacker can add fields like {role: \'admin\'} to escalate privileges.',
    fix: 'Explicitly pick allowed fields instead of spreading user input into database operations.',
    fixCode: `// Dangerous:
await prisma.user.create({ data: req.body });
await prisma.user.create({ data: { ...req.body } });

// Safe - pick allowed fields explicitly:
const { name, email } = req.body;
await prisma.user.create({ data: { name, email } });`,
  }),

  // INJ019 - AI Prompt Injection
  createLineCheck({
    id: 'INJ019',
    category: 'injection',
    name: 'AI Prompt Injection',
    severity: 'medium',
    pattern: /(?:content|text)\s*:\s*`[^`]*\$\{(?:req\.|body\.|input|query\.|user|message)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input is interpolated directly into an AI prompt. An attacker can inject instructions to override your system prompt or extract sensitive information.',
    fix: '1. Pass user input as a separate user message, never interpolated into system prompts.\n2. Use structured message arrays with clear role separation.\n3. Validate and sanitize user input before including it in prompts.',
    fixCode: `// Dangerous:
const response = await openai.chat.completions.create({
  messages: [{ role: 'user', content: \`Summarize: \${req.body.text}\` }],
});

// Safe - separate system and user messages:
const response = await openai.chat.completions.create({
  messages: [
    { role: 'system', content: 'You are a summarizer. Only summarize the provided text.' },
    { role: 'user', content: req.body.text },
  ],
});`,
  }),

  // INJ020 - Email Header Injection
  createLineCheck({
    id: 'INJ020',
    category: 'injection',
    name: 'Email Header Injection',
    severity: 'medium',
    pattern: /(?:sendMail|transporter\.sendMail|send)\s*\(\s*\{[^}]*(?:from|to|subject|cc|bcc)\s*:\s*(?:req\.|body\.|query\.|params\.|input|user)/g,
    appliesTo: ['js', 'ts'],
    message:
      'User input is used in email headers. An attacker can inject additional recipients or headers to send spam through your email.',
    fix: '1. Validate and sanitize email addresses before using them.\n2. Strip newlines and carriage returns from all header values.\n3. Use a whitelist of allowed recipients if possible.',
    fixCode: `// Dangerous:
transporter.sendMail({ to: req.body.email, subject: req.body.subject });

// Safe - validate input:
const email = validateEmail(req.body.email);
const subject = req.body.subject.replace(/[\\r\\n]/g, '');
transporter.sendMail({ to: email, subject });`,
  }),

  // INJ021 - Insecure Deserialization
  createLineCheck({
    id: 'INJ021',
    category: 'injection',
    name: 'Insecure Deserialization',
    severity: 'medium',
    pattern: /JSON\.parse\s*\(\s*(?:req\.body|req\.query|localStorage|sessionStorage|document\.cookie)/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Skip if the line also contains try (indicating some error handling)
      if (line.includes('try')) return false;
      return true;
    },
    message:
      'Untrusted input is parsed and potentially used without validation. Validate the parsed data against a schema.',
    fix: '1. Validate the parsed data against a schema using zod, Joi, or similar.\n2. Wrap in try/catch to handle malformed input.\n3. Never trust the structure of data from external sources.',
    fixCode: `// Dangerous:
const data = JSON.parse(req.body);

// Safe - validate with a schema:
import { z } from 'zod';
const schema = z.object({ name: z.string(), age: z.number() });
const data = schema.parse(JSON.parse(req.body));`,
  }),

  // INJ022 - Zip Slip / Archive Path Traversal (FileCheck)
  {
    level: 'file',
    id: 'INJ022',
    category: 'injection',
    name: 'Zip Slip / Archive Path Traversal',
    description:
      'Archive extraction without path validation allows Zip Slip attacks where malicious archives write files outside the target directory.',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: /unzip|extract|tar\.extract|decompress|archiver|adm-zip|yauzl|node-tar/,

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Check if the file uses archive extraction
      const extractionPattern =
        /(?:unzip|extract|tar\.extract|decompress|archiver|adm-zip|yauzl|node-tar)\s*\(/;
      if (!extractionPattern.test(content)) return [];

      // Check if the file has path validation
      const pathValidation =
        /(?:path\.normalize|path\.resolve|startsWith|includes\s*\(\s*['"]\.\.['"])/;
      if (pathValidation.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with archive extraction for location
      let extractLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (extractionPattern.test(lines[i])) {
          extractLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        extractLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'INJ022',
          title: 'Zip Slip / Archive Path Traversal',
          message:
            "Archive extraction without path validation allows 'Zip Slip' attacks. A malicious archive can write files anywhere on your server.",
          severity: ctx.config.severityOverrides.get('INJ022') ?? 'high',
          category: 'injection',
          location: {
            filePath: file.relativePath,
            startLine: extractLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Validate that extracted file paths stay within the target directory. Use path.resolve() and check startsWith().',
          fixCode: `// Dangerous - no path validation:
zip.extractAllTo(targetDir);

// Safe - validate each entry path:
for (const entry of zip.getEntries()) {
  const resolvedPath = path.resolve(targetDir, entry.entryName);
  if (!resolvedPath.startsWith(path.resolve(targetDir) + path.sep)) {
    throw new Error('Zip Slip detected: ' + entry.entryName);
  }
  zip.extractEntryTo(entry, targetDir);
}`,
        },
      ];
    },
  } satisfies FileCheck,
];
