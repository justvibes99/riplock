import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

/** Words that indicate password context. */
const PASSWORD_WORDS = /(?:password|passwd|pwd|pass)/i;

/** Words that indicate security-sensitive context for Math.random(). */
const SECURITY_CONTEXT =
  /(?:token|secret|password|key|session|(?<![a-z])id(?![a-z])|uuid|nonce|salt|hash)/i;

export const cryptoChecks: CheckDefinition[] = [
  // CRYPTO001 - MD5 for Passwords
  createLineCheck({
    id: 'CRYPTO001',
    category: 'crypto',
    name: 'MD5 Used for Password Hashing',
    severity: 'critical',
    appliesTo: ['js', 'ts', 'jsx', 'tsx', 'py'],
    pattern: /(?:md5|MD5)\s*\(\s*(?:password|passwd|pwd|pass)|createHash\s*\(\s*['"]md5['"]\)/gi,
    validate(regexMatch, line) {
      // For createHash('md5'), only flag if there's password context on the line
      if (/createHash/i.test(regexMatch[0])) {
        return PASSWORD_WORDS.test(line);
      }
      return true;
    },
    message:
      'MD5 is broken for passwords. Attackers can crack MD5 hashes in seconds using rainbow tables or brute force.',
    fix: '1. Replace MD5 with bcrypt (recommended: cost factor 12+) or argon2.\n2. Never use a general-purpose hash function for passwords.',
    fixCode: `// Dangerous:
const hash = crypto.createHash('md5').update(password).digest('hex');

// Safe - use bcrypt:
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);`,
  }),

  // CRYPTO002 - SHA for Passwords
  createLineCheck({
    id: 'CRYPTO002',
    category: 'crypto',
    name: 'SHA Used for Password Hashing',
    severity: 'high',
    appliesTo: ['js', 'ts', 'jsx', 'tsx', 'py'],
    pattern: /createHash\s*\(\s*['"]sha(?:1|256)['"]\).*(?:password|passwd)/gi,
    message:
      'SHA-1 and SHA-256 without salting are too fast for password hashing. An attacker with a GPU can try billions of guesses per second.',
    fix: '1. Use bcrypt with salt rounds of 12 or higher, or use argon2.\n2. These algorithms are designed to be slow, making brute force infeasible.',
    fixCode: `// Dangerous:
const hash = crypto.createHash('sha256').update(password).digest('hex');

// Safe - use bcrypt:
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);

// Safe - use argon2:
import argon2 from 'argon2';
const hash = await argon2.hash(password);`,
  }),

  // CRYPTO003 - Math.random for Security
  createLineCheck({
    id: 'CRYPTO003',
    category: 'crypto',
    name: 'Math.random() Used for Security',
    severity: 'high',
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    pattern: /Math\.random\s*\(\)/g,
    validate(_regexMatch, line) {
      // Only flag if the line also contains a security-relevant word
      return SECURITY_CONTEXT.test(line);
    },
    message:
      'Math.random() is predictable and must never be used for tokens, secrets, or IDs. Its output can be reconstructed from a few observed values.',
    fix: '1. Use crypto.randomUUID() for unique identifiers.\n2. Use crypto.randomBytes() or crypto.getRandomValues() for random tokens and secrets.',
    fixCode: `// Dangerous:
const token = Math.random().toString(36);

// Safe - use crypto:
import crypto from 'node:crypto';
const token = crypto.randomUUID();
const secret = crypto.randomBytes(32).toString('hex');`,
  }),

  // CRYPTO004 - Weak JWT Algorithm
  createLineCheck({
    id: 'CRYPTO004',
    category: 'crypto',
    name: 'Weak JWT Algorithm',
    severity: 'medium',
    appliesTo: ['js', 'ts', 'jsx', 'tsx'],
    pattern: /algorithms?\s*:\s*\[?\s*['"](?:HS256|none)['"]/gi,
    message:
      'Using a weak JWT algorithm. HS256 can be vulnerable to key confusion attacks when a public key is available, and "none" disables signature verification entirely.',
    fix: '1. Use RS256 or ES256 with proper key management for production JWTs.\n2. Never allow the "none" algorithm.\n3. Always validate the algorithm on the server side, do not trust the JWT header.',
    fixCode: `// Dangerous:
jwt.verify(token, secret, { algorithms: ['HS256'] });

// Safe - use asymmetric algorithms:
jwt.verify(token, publicKey, { algorithms: ['RS256'] });`,
  }),

  // CRYPTO005 - Deprecated crypto.createCipher
  createLineCheck({
    id: 'CRYPTO005',
    category: 'crypto',
    name: 'Deprecated crypto.createCipher',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /crypto\.createCipher\s*\(/g,
    validate(_regexMatch, line) {
      // Make sure we are not matching createCipheriv
      return !line.includes('createCipheriv');
    },
    message:
      'crypto.createCipher is deprecated and insecure. It derives the key without a salt and does not use an initialization vector, making the ciphertext deterministic and vulnerable to analysis.',
    fix: '1. Use crypto.createCipheriv with a random IV generated for each encryption.\n2. Use a well-tested encryption library like libsodium if you are unsure about the details.',
    fixCode: `// Dangerous:
const cipher = crypto.createCipher('aes-256-cbc', password);

// Safe - use createCipheriv with a random IV:
const iv = crypto.randomBytes(16);
const key = crypto.scryptSync(password, salt, 32);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);`,
  }),

  // CRYPTO006 - Hardcoded IV
  createLineCheck({
    id: 'CRYPTO006',
    category: 'crypto',
    name: 'Hardcoded Initialization Vector',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /createCipheriv\s*\([^)]*,\s*[^)]*,\s*(?:Buffer\.from\s*\(\s*['"]|['"])/g,
    message:
      'The encryption initialization vector (IV) is hardcoded. IVs must be randomly generated for each encryption operation. A static IV makes the ciphertext deterministic, allowing attackers to detect duplicate plaintexts.',
    fix: '1. Generate a random IV using crypto.randomBytes(16) for each encryption.\n2. Prepend the IV to the ciphertext so it can be used during decryption.',
    fixCode: `// Dangerous:
const iv = Buffer.from('1234567890123456');
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// Safe - generate a random IV each time:
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
// Prepend IV to ciphertext for decryption:
const encrypted = Buffer.concat([iv, cipher.update(data), cipher.final()]);`,
  }),

  // CRYPTO007 - Timing-Unsafe Secret Comparison
  createLineCheck({
    id: 'CRYPTO007',
    category: 'crypto',
    name: 'Timing-Unsafe Secret Comparison',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /(?:signature|token|secret|apiKey|api_key|webhook_secret|signing)\s*(?:===|!==|==)\s*/g,
    validate(_regexMatch, line) {
      // Skip if the line already uses timingSafeEqual
      if (line.includes('timingSafeEqual')) return false;
      return true;
    },
    message:
      'Secrets are compared with ===, which is vulnerable to timing attacks. Use crypto.timingSafeEqual() instead.',
    fix: '1. Use crypto.timingSafeEqual() for comparing secrets, tokens, and signatures.\n2. Convert both values to Buffers of the same length before comparing.',
    fixCode: `// Dangerous:
if (signature === expectedSignature) { ... }

// Safe - use timing-safe comparison:
import crypto from 'node:crypto';
const a = Buffer.from(signature);
const b = Buffer.from(expectedSignature);
if (a.length === b.length && crypto.timingSafeEqual(a, b)) { ... }`,
  }),

  // CRYPTO008 - Hardcoded Encryption Key
  createLineCheck({
    id: 'CRYPTO008',
    category: 'crypto',
    name: 'Hardcoded Encryption Key',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /(?:encryption_key|ENCRYPTION_KEY|aes_key|AES_KEY|cipher_key|CIPHER_KEY)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    message:
      'An encryption key is hardcoded in source code. Move it to an environment variable.',
    fix: '1. Remove the hardcoded key from source code.\n2. Store the key in an environment variable or a secrets manager.\n3. Rotate the key since it may already be exposed in version control history.',
    fixCode: `// Dangerous:
const ENCRYPTION_KEY = 'my-super-secret-key-12345';

// Safe - use an environment variable:
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY is required');`,
  }),

  // CRYPTO009 - Date.now for Token/Session ID
  createLineCheck({
    id: 'CRYPTO009',
    category: 'crypto',
    name: 'Date.now() Used for Token/Session ID',
    severity: 'medium',
    appliesTo: ['js', 'ts'],
    pattern: /(?:session|token|secret|nonce|csrf)\w*\s*=\s*(?:Date\.now|new Date)/gi,
    message:
      'Date.now() is predictable and must not be used for tokens or session IDs. Use crypto.randomUUID() instead.',
    fix: '1. Use crypto.randomUUID() or crypto.randomBytes() for generating tokens and session IDs.\n2. Date-based values can be guessed by an attacker who knows the approximate time.',
    fixCode: `// Dangerous:
const sessionId = Date.now().toString();
const token = new Date().getTime().toString(36);

// Safe:
import crypto from 'node:crypto';
const sessionId = crypto.randomUUID();
const token = crypto.randomBytes(32).toString('hex');`,
  }),

  // CRYPTO010 - ECB Mode Encryption
  createLineCheck({
    id: 'CRYPTO010',
    category: 'crypto',
    name: 'ECB Mode Encryption',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /createCipheriv\s*\(\s*['"]aes-\d+-ecb['"]/g,
    message:
      'ECB mode produces identical ciphertext for identical plaintext blocks. Use CBC or GCM mode instead.',
    fix: '1. Replace ECB mode with CBC (requires an IV) or GCM (provides authentication).\n2. GCM is preferred because it provides both confidentiality and integrity.',
    fixCode: `// Dangerous:
const cipher = crypto.createCipheriv('aes-256-ecb', key, null);

// Safe - use GCM:
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
  }),

  // CRYPTO011 - Weak Key Derivation
  createLineCheck({
    id: 'CRYPTO011',
    category: 'crypto',
    name: 'Weak Key Derivation',
    severity: 'high',
    appliesTo: ['js', 'ts'],
    pattern: /Buffer\.from\s*\(\s*(?:password|secret|key)\s*[,)]/g,
    validate(_regexMatch, line) {
      // Skip if the line also uses a proper KDF
      if (/scrypt/i.test(line)) return false;
      if (/pbkdf2/i.test(line)) return false;
      if (/argon2/i.test(line)) return false;
      return true;
    },
    message:
      'Password used directly as encryption key without proper derivation. Use crypto.scryptSync or PBKDF2.',
    fix: '1. Derive encryption keys from passwords using crypto.scryptSync() or PBKDF2.\n2. Always use a random salt stored alongside the ciphertext.',
    fixCode: `// Dangerous:
const key = Buffer.from(password);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// Safe - derive key with scrypt:
const salt = crypto.randomBytes(16);
const key = crypto.scryptSync(password, salt, 32);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);`,
  }),

  // CRYPTO012 - Insufficient Random Bytes
  createLineCheck({
    id: 'CRYPTO012',
    category: 'crypto',
    name: 'Insufficient Random Bytes',
    severity: 'medium',
    appliesTo: ['js', 'ts'],
    pattern: /randomBytes\s*\(\s*[1-7]\s*\)/g,
    message:
      'Random token uses less than 8 bytes (64 bits) of entropy. Use at least 16 bytes (128 bits) for tokens.',
    fix: '1. Use at least 16 bytes (128 bits) for tokens and secrets.\n2. Use 32 bytes (256 bits) for encryption keys.',
    fixCode: `// Dangerous:
const token = crypto.randomBytes(4).toString('hex'); // only 32 bits

// Safe:
const token = crypto.randomBytes(16).toString('hex'); // 128 bits
const key = crypto.randomBytes(32); // 256 bits for encryption`,
  }),
];
