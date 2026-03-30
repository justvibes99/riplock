import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  LineCheck,
  LineMatch,
  Finding,
  ScanContext,
  Severity,
} from '../types.js';
import { isCommentLine } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';
import { isPlaceholder } from '../../utils/entropy.js';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const DOC_EXTENSIONS = new Set(['md', 'txt', 'rst', 'adoc']);

/** Returns true when a line looks like a comment or doc-only content. */
function isCommentOrDoc(line: string, ext: string): boolean {
  if (DOC_EXTENSIONS.has(ext)) return true;
  return isCommentLine(line);
}

/** Build a Finding with snippet context from a LineMatch. */
function buildFinding(
  match: LineMatch,
  opts: {
    checkId: string;
    title: string;
    message: string;
    severity: Severity;
    fix: string;
    fixCode?: string;
  },
): Finding {
  const { snippet, contextBefore, contextAfter } = extractSnippet(
    match.file.lines!,
    match.lineNumber,
    2,
  );
  return {
    checkId: opts.checkId,
    title: opts.title,
    message: opts.message,
    severity: opts.severity,
    category: 'secrets',
    location: {
      filePath: match.file.relativePath,
      startLine: match.lineNumber,
    },
    snippet,
    contextBefore,
    contextAfter,
    fix: opts.fix,
    fixCode: opts.fixCode,
  };
}

/**
 * Factory that removes most of the boilerplate from individual check
 * definitions. Every check produced by this helper automatically:
 *  - skips comments and documentation files
 *  - calls `isPlaceholder` on the matched value
 *  - invokes an optional `validate` callback for extra filtering
 *  - builds a complete Finding with snippet context
 */
function secretCheck(opts: {
  id: string;
  name: string;
  description?: string;
  severity: Severity;
  pattern: RegExp;
  title?: string;
  message: string;
  fix: string;
  fixCode?: string;
  appliesTo?: string[];
  /** Return false to suppress the finding (false-positive reduction). */
  validate?: (regexMatch: RegExpExecArray, line: string) => boolean;
  /** Override which part of the match is tested against isPlaceholder.
   *  Defaults to `regexMatch[1] ?? regexMatch[0]`. */
  placeholderValue?: (regexMatch: RegExpExecArray) => string;
}): LineCheck {
  return {
    level: 'line',
    id: opts.id,
    name: opts.name,
    description: opts.description ?? opts.message,
    category: 'secrets',
    defaultSeverity: opts.severity,
    appliesTo: opts.appliesTo,
    pattern: opts.pattern,
    analyze(match: LineMatch, _ctx: ScanContext): Finding | null {
      // Skip comments and documentation files
      if (isCommentOrDoc(match.line, match.file.extension)) return null;

      // Skip .env files — secrets belong there. The real check is GIT002 (is .env gitignored?)
      if (match.file.extension === 'env') return null;

      // Determine the "secret value" for placeholder detection
      const secretValue = opts.placeholderValue
        ? opts.placeholderValue(match.regexMatch)
        : (match.regexMatch[1] ?? match.regexMatch[0]);

      if (isPlaceholder(secretValue)) return null;

      // Additional validation hook
      if (opts.validate && !opts.validate(match.regexMatch, match.line)) {
        return null;
      }

      return buildFinding(match, {
        checkId: opts.id,
        title: opts.title ?? opts.name,
        message: opts.message,
        severity: opts.severity,
        fix: opts.fix,
        fixCode: opts.fixCode,
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const secretChecks: CheckDefinition[] = [
  // SEC001 – AWS Access Key ID
  secretCheck({
    id: 'SEC001',
    name: 'AWS Access Key ID',
    severity: 'critical',
    pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    message:
      'An AWS access key ID is hardcoded in this file. Anyone with access to this code can use it to authenticate to your AWS account.',
    fix: '1. Immediately rotate the key in the AWS IAM console.\n2. Remove the key from source code.\n3. Use environment variables or AWS Secrets Manager instead.\n4. If the code was committed, consider the key compromised and rotate it.',
    fixCode: 'const accessKeyId = process.env.AWS_ACCESS_KEY_ID;',
  }),

  // SEC002 – AWS Secret Access Key
  secretCheck({
    id: 'SEC002',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    pattern:
      /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    message:
      'An AWS secret access key is hardcoded in this file. This key grants full access to the associated AWS account and must be kept secret.',
    fix: '1. Rotate the secret key in the AWS IAM console immediately.\n2. Remove the key from source code.\n3. Store it in environment variables, AWS Secrets Manager, or a .env file excluded from version control.\n4. Audit CloudTrail for unauthorised usage.',
    fixCode: 'const secretKey = process.env.AWS_SECRET_ACCESS_KEY;',
  }),

  // SEC003 – GitHub PAT (Classic)
  secretCheck({
    id: 'SEC003',
    name: 'GitHub Personal Access Token (Classic)',
    severity: 'critical',
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    message:
      'A GitHub classic personal access token is hardcoded. This token can read and write to repositories on your behalf.',
    fix: '1. Revoke the token at https://github.com/settings/tokens immediately.\n2. Remove the token from source code.\n3. Use environment variables or a secrets manager.\n4. Prefer fine-grained tokens with minimal scopes.',
    fixCode: 'const githubToken = process.env.GITHUB_TOKEN;',
  }),

  // SEC004 – GitHub Fine-Grained PAT
  secretCheck({
    id: 'SEC004',
    name: 'GitHub Fine-Grained PAT',
    severity: 'critical',
    pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g,
    message:
      'A GitHub fine-grained personal access token is hardcoded. Even scoped tokens should never be checked into source code.',
    fix: '1. Revoke the token at https://github.com/settings/tokens immediately.\n2. Remove the token from source code.\n3. Store it in an environment variable or secrets manager.',
    fixCode: 'const githubToken = process.env.GITHUB_TOKEN;',
  }),

  // SEC005 – GitHub OAuth / App Token
  secretCheck({
    id: 'SEC005',
    name: 'GitHub OAuth or App Token',
    severity: 'critical',
    pattern: /gh[ouhsr]_[A-Za-z0-9]{36}/g,
    message:
      'A GitHub OAuth or app token is hardcoded. These tokens grant access to the GitHub API on behalf of a user or application.',
    fix: '1. Revoke the token in GitHub settings.\n2. Remove it from source code.\n3. Use environment variables or your platform\'s secret storage.',
    fixCode: 'const ghToken = process.env.GITHUB_TOKEN;',
  }),

  // SEC006 – Stripe Secret Key
  secretCheck({
    id: 'SEC006',
    name: 'Stripe Secret Key',
    severity: 'critical',
    pattern: /sk_live_[A-Za-z0-9]{24,99}/g,
    message:
      'A live Stripe secret key is hardcoded. This key can create charges, refunds, and access your entire Stripe account.',
    fix: '1. Roll the key in the Stripe dashboard immediately.\n2. Remove the key from source code.\n3. Store it in environment variables or a secrets manager.\n4. Use restricted keys with only the permissions you need.',
    fixCode: 'const stripeKey = process.env.STRIPE_SECRET_KEY;',
  }),

  // SEC007 – Stripe Restricted Key
  secretCheck({
    id: 'SEC007',
    name: 'Stripe Restricted Key',
    severity: 'high',
    pattern: /rk_live_[A-Za-z0-9]{24,99}/g,
    message:
      'A live Stripe restricted key is hardcoded. Although scoped, it still grants access to parts of your Stripe account.',
    fix: '1. Roll the key in the Stripe dashboard.\n2. Remove the key from source code.\n3. Store it in environment variables or a secrets manager.',
    fixCode: 'const stripeKey = process.env.STRIPE_RESTRICTED_KEY;',
  }),

  // SEC008 – OpenAI API Key
  secretCheck({
    id: 'SEC008',
    name: 'OpenAI API Key',
    severity: 'critical',
    pattern: /sk-proj-[A-Za-z0-9_-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    message:
      'An OpenAI API key is hardcoded. This key allows anyone to make API calls billed to your account.',
    fix: '1. Revoke the key in the OpenAI dashboard.\n2. Remove it from source code.\n3. Use environment variables: process.env.OPENAI_API_KEY.',
    fixCode: 'const openaiKey = process.env.OPENAI_API_KEY;',
  }),

  // SEC009 – Anthropic API Key
  secretCheck({
    id: 'SEC009',
    name: 'Anthropic API Key',
    severity: 'critical',
    pattern: /sk-ant-api03-[A-Za-z0-9_-]{90,100}/g,
    message:
      'An Anthropic API key is hardcoded. This key allows anyone to make API calls billed to your account.',
    fix: '1. Revoke the key in the Anthropic console.\n2. Remove it from source code.\n3. Use environment variables: process.env.ANTHROPIC_API_KEY.',
    fixCode: 'const anthropicKey = process.env.ANTHROPIC_API_KEY;',
  }),

  // SEC010 – Google API Key
  secretCheck({
    id: 'SEC010',
    name: 'Google API Key',
    severity: 'high',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    message:
      'A Google API key is hardcoded. Depending on its restrictions, it may allow access to Google Cloud services billed to your account.',
    fix: '1. Restrict or delete the key in the Google Cloud console.\n2. Remove it from source code.\n3. Use environment variables or a secrets manager.\n4. Add API key restrictions (HTTP referrer, IP, API scope).',
    fixCode: 'const googleApiKey = process.env.GOOGLE_API_KEY;',
  }),

  // SEC011 – Google OAuth Client Secret
  secretCheck({
    id: 'SEC011',
    name: 'Google OAuth Client Secret',
    severity: 'critical',
    pattern: /GOCSPX-[A-Za-z0-9_-]{28}/g,
    message:
      'A Google OAuth client secret is hardcoded. This secret is used during the OAuth flow and should be kept confidential.',
    fix: '1. Rotate the client secret in the Google Cloud console.\n2. Remove it from source code.\n3. Store it in environment variables or a secrets manager.',
    fixCode: 'const googleSecret = process.env.GOOGLE_CLIENT_SECRET;',
  }),

  // SEC012 – Supabase Service Role Key
  secretCheck({
    id: 'SEC012',
    name: 'Supabase Service Role Key',
    severity: 'critical',
    pattern:
      /(?:supabase|SUPABASE)[_\s]*(?:service_role|SERVICE_ROLE)[_\s]*(?:key|KEY)?\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{100,})['"]?/gi,
    message:
      'A Supabase service role key is hardcoded. This key bypasses Row Level Security and grants full database access.',
    fix: '1. Rotate the service role key in your Supabase project settings.\n2. Remove it from source code.\n3. Store it in environment variables, only used server-side.\n4. Never expose service role keys to the browser.',
    fixCode:
      'const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;',
  }),

  // SEC013 – Slack Bot Token
  secretCheck({
    id: 'SEC013',
    name: 'Slack Bot Token',
    severity: 'high',
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/g,
    message:
      'A Slack bot token is hardcoded. This token can read messages, post to channels, and access workspace data.',
    fix: '1. Regenerate the token in the Slack app settings.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const slackToken = process.env.SLACK_BOT_TOKEN;',
  }),

  // SEC014 – Slack Webhook URL
  secretCheck({
    id: 'SEC014',
    name: 'Slack Webhook URL',
    severity: 'high',
    pattern:
      /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g,
    message:
      'A Slack incoming webhook URL is hardcoded. Anyone with this URL can post messages to your Slack channel.',
    fix: '1. Regenerate the webhook in Slack app settings.\n2. Remove the URL from source code.\n3. Store it in environment variables.',
    fixCode: 'const slackWebhook = process.env.SLACK_WEBHOOK_URL;',
  }),

  // SEC015 – Twilio Account SID
  secretCheck({
    id: 'SEC015',
    name: 'Twilio Account SID',
    severity: 'critical',
    pattern: /AC[a-f0-9]{32}/g,
    message:
      'A Twilio Account SID is hardcoded. Combined with an auth token, it provides full access to your Twilio account including SMS, calls, and billing.',
    fix: '1. Review Twilio access and rotate the auth token if also exposed.\n2. Remove the SID from source code.\n3. Store it in environment variables.',
    fixCode: 'const twilioSid = process.env.TWILIO_ACCOUNT_SID;',
  }),

  // SEC016 – SendGrid API Key
  secretCheck({
    id: 'SEC016',
    name: 'SendGrid API Key',
    severity: 'high',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    message:
      'A SendGrid API key is hardcoded. This key can send emails on your behalf and access your SendGrid account.',
    fix: '1. Delete and recreate the key in the SendGrid dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const sendgridKey = process.env.SENDGRID_API_KEY;',
  }),

  // SEC017 – Discord Bot Token
  secretCheck({
    id: 'SEC017',
    name: 'Discord Bot Token',
    severity: 'high',
    pattern: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g,
    message:
      'A Discord bot token is hardcoded. This token gives full control over the associated Discord bot.',
    fix: '1. Regenerate the token in the Discord Developer Portal.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const discordToken = process.env.DISCORD_BOT_TOKEN;',
  }),

  // SEC018 – Telegram Bot Token
  secretCheck({
    id: 'SEC018',
    name: 'Telegram Bot Token',
    severity: 'high',
    pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g,
    message:
      'A Telegram bot token is hardcoded. This token allows full control over the associated Telegram bot.',
    fix: '1. Revoke the token via @BotFather on Telegram.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const telegramToken = process.env.TELEGRAM_BOT_TOKEN;',
  }),

  // SEC019 – Private Key
  secretCheck({
    id: 'SEC019',
    name: 'Private Key',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY/g,
    message:
      'A private key is embedded in this file. Private keys are the most sensitive type of credential and should never appear in source code.',
    fix: '1. Treat this key as compromised and generate a new key pair.\n2. Remove the private key from source code.\n3. Store private keys in a secure file outside the repository, or use a secrets manager.\n4. Add the key file to .gitignore.',
    fixCode: 'const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH, "utf-8");',
  }),

  // SEC020 – Database Connection URL with Credentials
  secretCheck({
    id: 'SEC020',
    name: 'Database Connection URL with Credentials',
    severity: 'critical',
    pattern:
      /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s'"]+/gi,
    message:
      'A database connection string with embedded credentials is hardcoded. This exposes both the database location and login credentials.',
    fix: '1. Change the database password immediately.\n2. Remove the connection string from source code.\n3. Store it in an environment variable (e.g. DATABASE_URL).\n4. Restrict database access to known IP addresses.',
    fixCode: 'const databaseUrl = process.env.DATABASE_URL;',
  }),

  // SEC021 – JWT / Token Secret
  secretCheck({
    id: 'SEC021',
    name: 'JWT or Token Secret',
    severity: 'critical',
    pattern: /(?:jwt_secret|token_secret|secret_key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    message:
      'A JWT or token signing secret is hardcoded. Anyone who knows this secret can forge valid authentication tokens.',
    fix: '1. Rotate the secret and invalidate all existing tokens.\n2. Remove the secret from source code.\n3. Store it in environment variables or a secrets manager.\n4. Use a long, random value (at least 256 bits).',
    fixCode: 'const jwtSecret = process.env.JWT_SECRET;',
  }),

  // SEC022 – Generic Password Assignment
  secretCheck({
    id: 'SEC022',
    name: 'Hardcoded Password',
    severity: 'high',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    message:
      'A password appears to be hardcoded. Hardcoded passwords are easily discovered and cannot be rotated without a code change.',
    fix: '1. Remove the hardcoded password.\n2. Load it from an environment variable or secrets manager.\n3. If this is for testing, use a clearly named test fixture or mock.',
    fixCode: 'const password = process.env.DB_PASSWORD;',
    validate(regexMatch, line) {
      // Ignore comparisons like `password == "..."` or `password === "..."`
      if (/[=!]=/.test(line.slice(0, regexMatch.index))) return false;
      // Catch `== "value"` patterns directly around the match
      const beforeMatch = line.slice(
        Math.max(0, regexMatch.index! - 5),
        regexMatch.index,
      );
      if (/[=!]=\s*$/.test(beforeMatch)) return false;
      return true;
    },
  }),

  // SEC023 – Mailgun API Key
  secretCheck({
    id: 'SEC023',
    name: 'Mailgun API Key',
    severity: 'high',
    pattern: /key-[a-f0-9]{32}/g,
    message:
      'A Mailgun API key is hardcoded. This key can send emails and access your Mailgun account.',
    fix: '1. Rotate the key in the Mailgun dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const mailgunKey = process.env.MAILGUN_API_KEY;',
  }),

  // SEC024 – Resend API Key
  secretCheck({
    id: 'SEC024',
    name: 'Resend API Key',
    severity: 'high',
    pattern: /re_[A-Za-z0-9]{32,}/g,
    message:
      'A Resend API key is hardcoded. This key can send emails on your behalf.',
    fix: '1. Revoke and recreate the key in the Resend dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const resendKey = process.env.RESEND_API_KEY;',
  }),

  // SEC025 – Hugging Face Token
  secretCheck({
    id: 'SEC025',
    name: 'Hugging Face Token',
    severity: 'high',
    pattern: /hf_[A-Za-z0-9]{34,}/g,
    message:
      'A Hugging Face access token is hardcoded. This token can access models, datasets, and Spaces on your behalf.',
    fix: '1. Revoke the token at https://huggingface.co/settings/tokens.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const hfToken = process.env.HF_TOKEN;',
  }),

  // SEC026 – Replicate API Token
  secretCheck({
    id: 'SEC026',
    name: 'Replicate API Token',
    severity: 'high',
    pattern: /r8_[A-Za-z0-9]{38}/g,
    message:
      'A Replicate API token is hardcoded. This token can run models billed to your account.',
    fix: '1. Revoke the token in the Replicate dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const replicateToken = process.env.REPLICATE_API_TOKEN;',
  }),

  // SEC027 – Clerk Secret Key
  secretCheck({
    id: 'SEC027',
    name: 'Clerk Secret Key',
    severity: 'high',
    pattern:
      /(?:clerk|CLERK)[_\s]*(?:secret|SECRET)[_\s]*(?:key|KEY)?\s*[=:]\s*['"]?(sk_(?:live|test)_[A-Za-z0-9]{27,})['"]?/gi,
    message:
      'A Clerk secret key is hardcoded. This key provides full access to your Clerk authentication backend.',
    fix: '1. Rotate the key in the Clerk dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const clerkSecret = process.env.CLERK_SECRET_KEY;',
  }),

  // SEC028 – Vercel Token
  secretCheck({
    id: 'SEC028',
    name: 'Vercel Token',
    severity: 'high',
    pattern:
      /(?:vercel_token|VERCEL_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?/gi,
    message:
      'A Vercel authentication token is hardcoded. This token can deploy, manage, and delete projects on your Vercel account.',
    fix: '1. Revoke the token in Vercel account settings.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const vercelToken = process.env.VERCEL_TOKEN;',
  }),

  // SEC029 – Cloudflare API Token
  secretCheck({
    id: 'SEC029',
    name: 'Cloudflare API Token',
    severity: 'high',
    pattern:
      /(?:cloudflare_api_token|CF_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{37,})['"]?/gi,
    message:
      'A Cloudflare API token is hardcoded. This token can manage DNS, firewall rules, and other Cloudflare resources.',
    fix: '1. Revoke the token in the Cloudflare dashboard.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const cfToken = process.env.CF_API_TOKEN;',
  }),

  // SEC030 – Pinecone API Key
  secretCheck({
    id: 'SEC030',
    name: 'Pinecone API Key',
    severity: 'high',
    pattern:
      /(?:pinecone_api_key|PINECONE_API_KEY)\s*[=:]\s*['"]?([a-f0-9-]{36})['"]?/gi,
    message:
      'A Pinecone API key is hardcoded. This key grants access to your vector database and stored embeddings.',
    fix: '1. Rotate the key in the Pinecone console.\n2. Remove it from source code.\n3. Store it in environment variables.',
    fixCode: 'const pineconeKey = process.env.PINECONE_API_KEY;',
  }),

  // SEC031 – Generic High-Entropy Secret
  secretCheck({
    id: 'SEC031',
    name: 'Generic High-Entropy Secret',
    severity: 'high',
    pattern:
      /(?:secret|api_key|auth_key|private_key|access_key)\s*[=:]\s*['"]([A-Za-z0-9+/=_-]{20,})['"]/gi,
    message:
      'A value that looks like a secret or API key is hardcoded. High-entropy strings assigned to secret-sounding variables are almost always real credentials.',
    fix: '1. Determine what service this key belongs to and rotate it.\n2. Remove it from source code.\n3. Store it in environment variables or a secrets manager.',
    fixCode: 'const secret = process.env.MY_SECRET;',
    validate(regexMatch, _line) {
      const value = regexMatch[1];
      if (!value) return false;
      // Require the value to have reasonable entropy (Shannon > 3.5)
      // Inline a quick Shannon entropy check to avoid importing the full function
      // for this single use — but we already have it in entropy.ts.
      // We'll do a simpler heuristic: require mixed-case or digits + letters.
      const hasUpper = /[A-Z]/.test(value);
      const hasLower = /[a-z]/.test(value);
      const hasDigit = /[0-9]/.test(value);
      const charCategories = [hasUpper, hasLower, hasDigit].filter(Boolean).length;
      return charCategories >= 2;
    },
  }),

  // SEC032 – Hardcoded Bearer Token
  secretCheck({
    id: 'SEC032',
    name: 'Hardcoded Bearer Token',
    severity: 'high',
    pattern: /['"]Bearer\s+[A-Za-z0-9._-]{20,}['"]/g,
    message:
      'A Bearer authentication token is hardcoded. This token can impersonate the associated user or service.',
    fix: '1. Revoke and rotate the token with the issuing service.\n2. Remove the hardcoded value from source code.\n3. Load the token from environment variables or fetch it dynamically at runtime.',
    fixCode:
      'const authHeader = `Bearer ${process.env.API_TOKEN}`;',
  }),

  // SEC033 – Base64-Encoded Secret (FileCheck)
  {
    level: 'file',
    id: 'SEC033',
    name: 'Base64-Encoded Secret',
    description:
      'Detects secrets that have been base64-encoded to evade simple pattern matching.',
    category: 'secrets',
    defaultSeverity: 'critical',
    appliesTo: ['js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'go', 'php'],
    fastFilter: /atob|Buffer\.from|base64|b64decode/,

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      const content = file.content ?? await ctx.readFile(file.absolutePath);
      if (!content) return [];

      const lines = file.lines ?? await ctx.readLines(file.absolutePath);
      const findings: Finding[] = [];

      // Patterns to detect in decoded base64 strings
      const secretPatterns: Array<{ name: string; pattern: RegExp }> = [
        { name: 'AWS key', pattern: /AKIA[0-9A-Z]{16}/ },
        { name: 'Stripe key', pattern: /sk_live_[A-Za-z0-9]{24,}/ },
        { name: 'GitHub PAT', pattern: /ghp_[A-Za-z0-9]{36}/ },
        { name: 'OpenAI key', pattern: /sk-proj-[A-Za-z0-9_-]{40,}/ },
        { name: 'Private key', pattern: /-----BEGIN.*PRIVATE KEY-----/ },
        { name: 'Database URL', pattern: /(postgres|mysql|mongodb):\/\/.*:.*@/ },
        { name: 'Generic secret', pattern: /(?:password|secret|token|api_key)=/ },
      ];

      // Extract base64 strings from the file content
      // 1. Raw base64 string literals (40+ chars)
      const rawB64Re = /['"`]([A-Za-z0-9+/]{40,}={0,2})['"`]/g;
      // 2. Buffer.from('...', 'base64')
      const bufferFromRe = /Buffer\.from\(\s*['"`]([A-Za-z0-9+/]+=*)['"`]\s*,\s*['"`]base64['"`]\s*\)/g;
      // 3. atob('...')
      const atobRe = /atob\(\s*['"`]([A-Za-z0-9+/]+=*)['"`]\s*\)/g;
      // 4. base64.b64decode('...')
      const b64decodeRe = /b64decode\(\s*['"`]([A-Za-z0-9+/]+=*)['"`]\s*\)/g;

      const candidates = new Map<string, number>(); // encoded string -> line number

      // Helper: find the line number for a match index in content
      function lineNumberForIndex(idx: number): number {
        let line = 1;
        for (let i = 0; i < idx && i < content.length; i++) {
          if (content[i] === '\n') line++;
        }
        return line;
      }

      // Collect candidates from all patterns
      for (const re of [bufferFromRe, atobRe, b64decodeRe]) {
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          const encoded = m[1];
          if (encoded && encoded.length >= 8) {
            candidates.set(encoded, lineNumberForIndex(m.index));
          }
        }
      }

      // Raw base64 strings (only when file also contains a base64-related keyword)
      if (/atob|Buffer\.from|base64|b64decode/i.test(content)) {
        let m: RegExpExecArray | null;
        while ((m = rawB64Re.exec(content)) !== null) {
          const encoded = m[1];
          if (encoded && !candidates.has(encoded)) {
            candidates.set(encoded, lineNumberForIndex(m.index));
          }
        }
      }

      // Decode each candidate and check for secrets
      for (const [encoded, lineNum] of candidates) {
        let decoded: string;
        try {
          decoded = Buffer.from(encoded, 'base64').toString('utf-8');
        } catch {
          continue;
        }

        // Skip if decoded output is not valid text (likely binary/image data)
        // eslint-disable-next-line no-control-regex
        if (/[\x00-\x08\x0E-\x1F]/.test(decoded)) continue;

        for (const { name, pattern } of secretPatterns) {
          if (pattern.test(decoded)) {
            // Redact the decoded secret: show first 8 chars then ***
            const redacted =
              decoded.length > 8
                ? decoded.slice(0, 8) + '***'
                : '***';

            const { snippet, contextBefore, contextAfter } = extractSnippet(
              lines,
              lineNum,
              2,
            );

            findings.push({
              checkId: 'SEC033',
              title: 'Base64-Encoded Secret',
              message: `A base64-encoded secret was found (${name}). Decoded (redacted): "${redacted}"`,
              severity: 'critical',
              category: 'secrets',
              location: {
                filePath: file.relativePath,
                startLine: lineNum,
              },
              snippet,
              contextBefore,
              contextAfter,
              fix: '1. Remove the encoded secret from source code.\n2. Rotate the exposed credential immediately.\n3. Store secrets in environment variables or a secrets manager.\n4. Base64 encoding is not encryption — it provides no security.',
              fixCode: 'const secret = process.env.MY_SECRET;',
            });

            // Only report one finding per encoded string
            break;
          }
        }
      }

      return findings;
    },
  } satisfies FileCheck,
];
