import { describe, it, expect } from 'vitest';
import { secretChecks } from '../../src/checks/secrets/index.js';
import { testLine, testFileCheck } from '../helpers.js';

// ---------------------------------------------------------------------------
// SEC001 - AWS Access Key ID
// ---------------------------------------------------------------------------

describe('SEC001 - AWS Access Key ID', () => {
  it('detects a real AWS access key', () => {
    // Use a realistic key that does NOT contain placeholder words
    const finding = testLine(
      secretChecks,
      'SEC001',
      'const key = "AKIAI44QH8DHBFNRGM3Q";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
    expect(finding!.message).toContain('AWS');
    expect(finding!.fix).toBeTruthy();
  });

  it('skips placeholder keys (contains "EXAMPLE")', () => {
    const finding = testLine(
      secretChecks,
      'SEC001',
      'const key = "AKIAIOSFODNN7EXAMPLE";',
    );
    // isPlaceholder detects "EXAMPLE" in the value
    expect(finding).toBeNull();
  });

  it('skips comment lines', () => {
    const finding = testLine(
      secretChecks,
      'SEC001',
      '// const key = "AKIAI44QH8DHBFNRGM3Q";',
    );
    expect(finding).toBeNull();
  });

  it('skips lines starting with # (shell/yaml comments)', () => {
    const finding = testLine(
      secretChecks,
      'SEC001',
      '# AKIAI44QH8DHBFNRGM3Q',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC003 - GitHub PAT (Classic)
// ---------------------------------------------------------------------------

describe('SEC003 - GitHub Personal Access Token', () => {
  it('detects a GitHub classic PAT (36 chars after ghp_)', () => {
    // Pattern requires exactly 36 alphanumeric chars after ghp_
    const finding = testLine(
      secretChecks,
      'SEC003',
      'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC003');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
    expect(finding!.message).toContain('GitHub');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not match a token that is too short', () => {
    // Only 34 chars after ghp_ -- pattern requires 36
    const finding = testLine(
      secretChecks,
      'SEC003',
      'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC006 - Stripe Secret Key
// ---------------------------------------------------------------------------

describe('SEC006 - Stripe Secret Key', () => {
  it('detects a live Stripe secret key', () => {
    const finding = testLine(
      secretChecks,
      'SEC006',
      'const stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC006');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match test Stripe keys (pattern only matches sk_live_)', () => {
    const finding = testLine(
      secretChecks,
      'SEC006',
      'const stripe = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC008 - OpenAI API Key
// ---------------------------------------------------------------------------

describe('SEC008 - OpenAI API Key', () => {
  it('detects an OpenAI project key (sk-proj-)', () => {
    const key = 'sk-proj-' + 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEF';
    const finding = testLine(
      secretChecks,
      'SEC008',
      `const key = "${key}";`,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC008');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });
});

// ---------------------------------------------------------------------------
// SEC019 - Private Key
// ---------------------------------------------------------------------------

describe('SEC019 - Private Key', () => {
  it('detects a private key header embedded in code', () => {
    // The bare header line starts with --, which the COMMENT_RE treats as
    // a comment (SQL -- comments). Embed in an assignment instead.
    const finding = testLine(
      secretChecks,
      'SEC019',
      'const key = "-----BEGIN RSA PRIVATE KEY-----";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC019');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('detects an EC private key header', () => {
    const finding = testLine(
      secretChecks,
      'SEC019',
      'const key = "-----BEGIN EC PRIVATE KEY-----";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC019');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('skips when line is a comment', () => {
    const finding = testLine(
      secretChecks,
      'SEC019',
      '// -----BEGIN RSA PRIVATE KEY-----',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC020 - Database Connection URL with Credentials
// ---------------------------------------------------------------------------

describe('SEC020 - Database Connection URL', () => {
  it('detects a MongoDB connection URL with credentials', () => {
    const finding = testLine(
      secretChecks,
      'SEC020',
      'const url = "mongodb://user:pass@host:27017/db";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC020');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('detects a PostgreSQL connection URL with credentials', () => {
    // Avoid "example" in the hostname (triggers isPlaceholder)
    const finding = testLine(
      secretChecks,
      'SEC020',
      'const url = "postgres://admin:s3cret@db.prod.internal:5432/mydb";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC020');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('skips placeholder passwords in connection URLs', () => {
    const finding = testLine(
      secretChecks,
      'SEC020',
      'const url = "mongodb://user:your-password-here@host/db";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC022 - Hardcoded Password
// ---------------------------------------------------------------------------

describe('SEC022 - Hardcoded Password', () => {
  it('detects a hardcoded password assignment', () => {
    const finding = testLine(
      secretChecks,
      'SEC022',
      'password = "mysecret123"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC022');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('skips password comparison (===)', () => {
    const finding = testLine(
      secretChecks,
      'SEC022',
      'if (password === "expected") {',
    );
    expect(finding).toBeNull();
  });

  it('skips password comparison (==)', () => {
    const finding = testLine(
      secretChecks,
      'SEC022',
      'if (password == "expected") {',
    );
    expect(finding).toBeNull();
  });

  it('detects password in config object', () => {
    const finding = testLine(
      secretChecks,
      'SEC022',
      '  password: "db_hunter2_prod"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC022');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });
});

// ---------------------------------------------------------------------------
// SEC031 - Generic High-Entropy Secret
// ---------------------------------------------------------------------------

describe('SEC031 - Generic High-Entropy Secret', () => {
  it('detects a high-entropy secret value (mixed case + digits)', () => {
    const finding = testLine(
      secretChecks,
      'SEC031',
      'secret = "aB3dEf7hIjKlMn0pQrStUv"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC031');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('skips low-entropy placeholder values', () => {
    const finding = testLine(
      secretChecks,
      'SEC031',
      'secret = "your-placeholder-key-here"',
    );
    expect(finding).toBeNull();
  });

  it('skips values with only one character category (all lowercase)', () => {
    // SEC031 validate requires at least 2 of: uppercase, lowercase, digits
    const finding = testLine(
      secretChecks,
      'SEC031',
      'api_key = "abcdefghijklmnopqrstuvwxyz"',
    );
    expect(finding).toBeNull();
  });

  it('detects api_key with mixed alphanumeric value', () => {
    const finding = testLine(
      secretChecks,
      'SEC031',
      'api_key = "kR9x4mZq2YwBvN7jLpG3hTdC"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC031');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });
});

// ---------------------------------------------------------------------------
// SEC002 - AWS Secret Access Key
// ---------------------------------------------------------------------------

describe('SEC002 - AWS Secret Access Key', () => {
  it('detects an AWS secret access key', () => {
    const finding = testLine(
      secretChecks,
      'SEC002',
      'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYKEYVALUE99"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('skips placeholder values', () => {
    const finding = testLine(
      secretChecks,
      'SEC002',
      'aws_secret = "your-aws-secret-key-here-placeholder1234"',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC004 - GitHub Fine-Grained PAT
// ---------------------------------------------------------------------------

describe('SEC004 - GitHub Fine-Grained PAT', () => {
  it('detects a GitHub fine-grained PAT', () => {
    // Pattern: github_pat_ + 22 alphanums + _ + 59 alphanums
    const part1 = 'Abc1Def2Ghi3Jkl4Mnop56'; // 22 chars
    const part2 = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvW'; // 59 chars
    const finding = testLine(
      secretChecks,
      'SEC004',
      `const token = "github_pat_${part1}_${part2}";`,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC004');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a non-matching string', () => {
    const finding = testLine(
      secretChecks,
      'SEC004',
      'const token = "github_pat_short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC005 - GitHub OAuth / App Token
// ---------------------------------------------------------------------------

describe('SEC005 - GitHub OAuth or App Token', () => {
  it('detects a GitHub OAuth token', () => {
    // Pattern: gho_ + 36 alphanums
    const finding = testLine(
      secretChecks,
      'SEC005',
      'const token = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC005');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a token that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC005',
      'const token = "gho_ABCDEFshort";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC007 - Stripe Restricted Key
// ---------------------------------------------------------------------------

describe('SEC007 - Stripe Restricted Key', () => {
  it('detects a live Stripe restricted key', () => {
    const finding = testLine(
      secretChecks,
      'SEC007',
      'const key = "rk_live_4eC39HqLyjWDarjtT1zdp7dc";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC007');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match test Stripe restricted keys', () => {
    const finding = testLine(
      secretChecks,
      'SEC007',
      'const key = "rk_test_4eC39HqLyjWDarjtT1zdp7dc";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC009 - Anthropic API Key
// ---------------------------------------------------------------------------

describe('SEC009 - Anthropic API Key', () => {
  it('detects an Anthropic API key', () => {
    const key = 'sk-ant-api03-' + 'A'.repeat(93) + 'AA';
    const finding = testLine(
      secretChecks,
      'SEC009',
      `const key = "${key}";`,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC009');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a partial/short key', () => {
    const finding = testLine(
      secretChecks,
      'SEC009',
      'const key = "sk-ant-api03-tooshort";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC010 - Google API Key
// ---------------------------------------------------------------------------

describe('SEC010 - Google API Key', () => {
  it('detects a Google API key', () => {
    const finding = testLine(
      secretChecks,
      'SEC010',
      'const key = "AIzaSyA1234567890abcdefghijklmnopqrstuv";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC010');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a key that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC010',
      'const key = "AIzaShort";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC011 - Google OAuth Client Secret
// ---------------------------------------------------------------------------

describe('SEC011 - Google OAuth Client Secret', () => {
  it('detects a Google OAuth client secret', () => {
    // Pattern: GOCSPX- + 28 alphanums/dashes/underscores
    const finding = testLine(
      secretChecks,
      'SEC011',
      'const secret = "GOCSPX-abcdefghijklmnopqrstuvwxyz12";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC011');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a string that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC011',
      'const secret = "GOCSPX-short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC012 - Supabase Service Role Key
// ---------------------------------------------------------------------------

describe('SEC012 - Supabase Service Role Key', () => {
  it('detects a Supabase service role key', () => {
    const jwt = 'eyJ' + 'A'.repeat(100);
    const finding = testLine(
      secretChecks,
      'SEC012',
      `SUPABASE_SERVICE_ROLE_KEY = "${jwt}"`,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC012');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match without supabase context', () => {
    const jwt = 'eyJ' + 'A'.repeat(100);
    const finding = testLine(
      secretChecks,
      'SEC012',
      `SOME_OTHER_KEY = "${jwt}"`,
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC013 - Slack Bot Token
// ---------------------------------------------------------------------------

describe('SEC013 - Slack Bot Token', () => {
  it('detects a Slack bot token', () => {
    const finding = testLine(
      secretChecks,
      'SEC013',
      'const token = "xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVwx";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC013');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a malformed Slack token', () => {
    const finding = testLine(
      secretChecks,
      'SEC013',
      'const token = "xoxb-short-bad";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC014 - Slack Webhook URL
// ---------------------------------------------------------------------------

describe('SEC014 - Slack Webhook URL', () => {
  it('detects a Slack webhook URL', () => {
    const finding = testLine(
      secretChecks,
      'SEC014',
      'const url = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC014');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match an incomplete Slack webhook', () => {
    const finding = testLine(
      secretChecks,
      'SEC014',
      'const url = "https://hooks.slack.com/services/T123/B123/short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC015 - Twilio Account SID
// ---------------------------------------------------------------------------

describe('SEC015 - Twilio Account SID', () => {
  it('detects a Twilio Account SID', () => {
    const finding = testLine(
      secretChecks,
      'SEC015',
      'const sid = "AC1234567890abcdef1234567890abcdef";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC015');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a string that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC015',
      'const sid = "AC12345";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC016 - SendGrid API Key
// ---------------------------------------------------------------------------

describe('SEC016 - SendGrid API Key', () => {
  it('detects a SendGrid API key', () => {
    const finding = testLine(
      secretChecks,
      'SEC016',
      'const key = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijk";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC016');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a malformed SendGrid key', () => {
    const finding = testLine(
      secretChecks,
      'SEC016',
      'const key = "SG.short.short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC017 - Discord Bot Token
// ---------------------------------------------------------------------------

describe('SEC017 - Discord Bot Token', () => {
  it('detects a Discord bot token', () => {
    const finding = testLine(
      secretChecks,
      'SEC017',
      'const token = "MTExMjIzMzQ0NTU2Njc3ODkw.GAbCdE.abcdefghijklmnopqrstuvwxyz123";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC017');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a non-matching string', () => {
    const finding = testLine(
      secretChecks,
      'SEC017',
      'const token = "not-a-discord-token";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC018 - Telegram Bot Token
// ---------------------------------------------------------------------------

describe('SEC018 - Telegram Bot Token', () => {
  it('detects a Telegram bot token', () => {
    const finding = testLine(
      secretChecks,
      'SEC018',
      'const token = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC018');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a non-matching string', () => {
    const finding = testLine(
      secretChecks,
      'SEC018',
      'const token = "12345:short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC021 - JWT / Token Secret
// ---------------------------------------------------------------------------

describe('SEC021 - JWT or Token Secret', () => {
  it('detects a hardcoded JWT secret', () => {
    const finding = testLine(
      secretChecks,
      'SEC021',
      'jwt_secret = "mysupersecretkey123"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC021');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('secrets');
  });

  it('skips when value is an env var reference (no string literal)', () => {
    const finding = testLine(
      secretChecks,
      'SEC021',
      'jwt_secret = process.env.JWT_SECRET',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC023 - Mailgun API Key
// ---------------------------------------------------------------------------

describe('SEC023 - Mailgun API Key', () => {
  it('detects a Mailgun API key', () => {
    const finding = testLine(
      secretChecks,
      'SEC023',
      'const key = "key-1234567890abcdef1234567890abcdef";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC023');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a key that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC023',
      'const key = "key-short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC024 - Resend API Key
// ---------------------------------------------------------------------------

describe('SEC024 - Resend API Key', () => {
  it('detects a Resend API key', () => {
    const finding = testLine(
      secretChecks,
      'SEC024',
      'const key = "re_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC024');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a key that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC024',
      'const key = "re_short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC025 - Hugging Face Token
// ---------------------------------------------------------------------------

describe('SEC025 - Hugging Face Token', () => {
  it('detects a Hugging Face token', () => {
    const finding = testLine(
      secretChecks,
      'SEC025',
      'const token = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC025');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a token that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC025',
      'const token = "hf_short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC026 - Replicate API Token
// ---------------------------------------------------------------------------

describe('SEC026 - Replicate API Token', () => {
  it('detects a Replicate API token', () => {
    const finding = testLine(
      secretChecks,
      'SEC026',
      'const token = "r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC026');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a token that is too short', () => {
    const finding = testLine(
      secretChecks,
      'SEC026',
      'const token = "r8_short";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC027 - Clerk Secret Key
// ---------------------------------------------------------------------------

describe('SEC027 - Clerk Secret Key', () => {
  it('detects a Clerk secret key', () => {
    const finding = testLine(
      secretChecks,
      'SEC027',
      'CLERK_SECRET_KEY = "sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz123"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC027');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match without Clerk context', () => {
    const finding = testLine(
      secretChecks,
      'SEC027',
      'const key = "sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz123";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC028 - Vercel Token
// ---------------------------------------------------------------------------

describe('SEC028 - Vercel Token', () => {
  it('detects a Vercel token', () => {
    const finding = testLine(
      secretChecks,
      'SEC028',
      'VERCEL_TOKEN = "abcdefghijklmnopqrstuvwx"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC028');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match without VERCEL_TOKEN context', () => {
    const finding = testLine(
      secretChecks,
      'SEC028',
      'const token = "abcdefghijklmnopqrstuvwx";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC029 - Cloudflare API Token
// ---------------------------------------------------------------------------

describe('SEC029 - Cloudflare API Token', () => {
  it('detects a Cloudflare API token', () => {
    const finding = testLine(
      secretChecks,
      'SEC029',
      'CLOUDFLARE_API_TOKEN = "abcdefghijklmnopqrstuvwxyz1234567890A"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC029');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match without Cloudflare context', () => {
    const finding = testLine(
      secretChecks,
      'SEC029',
      'const token = "abcdefghijklmnopqrstuvwxyz1234567890A";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC030 - Pinecone API Key
// ---------------------------------------------------------------------------

describe('SEC030 - Pinecone API Key', () => {
  it('detects a Pinecone API key', () => {
    const finding = testLine(
      secretChecks,
      'SEC030',
      'PINECONE_API_KEY = "12345678-1234-1234-1234-123456789012"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC030');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match without Pinecone context', () => {
    const finding = testLine(
      secretChecks,
      'SEC030',
      'const key = "12345678-1234-1234-1234-123456789012";',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC032 - Hardcoded Bearer Token
// ---------------------------------------------------------------------------

describe('SEC032 - Hardcoded Bearer Token', () => {
  it('detects a hardcoded Bearer token', () => {
    const finding = testLine(
      secretChecks,
      'SEC032',
      '"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SEC032');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('secrets');
  });

  it('does not match a short Bearer value', () => {
    const finding = testLine(
      secretChecks,
      'SEC032',
      '"Bearer short"',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SEC033 - Base64-Encoded Secret
// ---------------------------------------------------------------------------

describe('SEC033 - Base64-Encoded Secret', () => {
  it('detects a base64-encoded Stripe key in Buffer.from()', async () => {
    // "sk_live_4eC39HqLyjWDarjtT1zdp7dc" base64-encoded
    const content = `const secret = Buffer.from('c2tfbGl2ZV80ZUMzOUhxTHlqV0Rhcmp0VDF6ZHA3ZGM=', 'base64');`;
    const findings = await testFileCheck(secretChecks, 'SEC033', content, {
      extension: 'ts',
      relativePath: 'config.ts',
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].checkId).toBe('SEC033');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('secrets');
    expect(findings[0].message).toContain('base64-encoded secret');
    expect(findings[0].message).toContain('Stripe key');
  });

  it('does not flag base64 that decodes to harmless text', async () => {
    // "hello world" base64-encoded
    const content = `const greeting = Buffer.from('aGVsbG8gd29ybGQ=', 'base64');`;
    const findings = await testFileCheck(secretChecks, 'SEC033', content, {
      extension: 'ts',
      relativePath: 'utils.ts',
    });
    expect(findings).toHaveLength(0);
  });
});
