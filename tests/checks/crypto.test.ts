import { describe, it, expect } from 'vitest';
import { cryptoChecks } from '../../src/checks/crypto/index.js';
import { testLine } from '../helpers.js';

describe('crypto checks', () => {
  describe('CRYPTO001 - MD5 Used for Password Hashing', () => {
    it('flags createHash(md5) with password context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO001', `createHash('md5').update(password)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO001');
      expect(result!.severity).toBe('critical');
      expect(result!.category).toBe('crypto');
      expect(result!.message).toContain('MD5');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag createHash(md5) without password context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO001', `createHash('md5').update(data)`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO003 - Math.random() Used for Security', () => {
    it('flags Math.random() in security context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO003', `const token = Math.random()`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO003');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
      expect(result!.message).toContain('Math.random');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag Math.random() without security context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO003', `const x = Math.random()`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO005 - Deprecated crypto.createCipher', () => {
    it('flags crypto.createCipher()', () => {
      const result = testLine(cryptoChecks, 'CRYPTO005', `crypto.createCipher('aes-256-cbc', key)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO005');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag crypto.createCipheriv()', () => {
      const result = testLine(cryptoChecks, 'CRYPTO005', `crypto.createCipheriv('aes-256-cbc', key, iv)`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO007 - Timing-Unsafe Secret Comparison', () => {
    it('flags === comparison on signature', () => {
      const result = testLine(cryptoChecks, 'CRYPTO007', `signature === req.headers['x-signature']`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO007');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag when timingSafeEqual is used', () => {
      const result = testLine(cryptoChecks, 'CRYPTO007', `crypto.timingSafeEqual(signature, expected)`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO002 - SHA Used for Password Hashing', () => {
    it('flags createHash(sha256) with password context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO002', `createHash('sha256').update(password).digest('hex')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO002');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag createHash(sha256) without password context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO002', `createHash('sha256').update(data).digest('hex')`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO004 - Weak JWT Algorithm', () => {
    it('flags algorithms: [HS256]', () => {
      const result = testLine(cryptoChecks, 'CRYPTO004', `algorithms: ['HS256']`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO004');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag algorithms: [RS256]', () => {
      const result = testLine(cryptoChecks, 'CRYPTO004', `algorithms: ['RS256']`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO006 - Hardcoded Initialization Vector', () => {
    it('flags createCipheriv with hardcoded IV string', () => {
      const result = testLine(cryptoChecks, 'CRYPTO006', `createCipheriv('aes-256-cbc', key, Buffer.from('fixediv123456'))`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO006');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag createCipheriv with variable IV', () => {
      const result = testLine(cryptoChecks, 'CRYPTO006', `createCipheriv('aes-256-cbc', key, randomIV)`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO008 - Hardcoded Encryption Key', () => {
    it('flags hardcoded ENCRYPTION_KEY string', () => {
      const result = testLine(cryptoChecks, 'CRYPTO008', `ENCRYPTION_KEY = "mysecretencryptionkey123"`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO008');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag ENCRYPTION_KEY from env', () => {
      const result = testLine(cryptoChecks, 'CRYPTO008', `ENCRYPTION_KEY = process.env.KEY`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO009 - Date.now() Used for Token/Session ID', () => {
    it('flags Date.now() assigned to token variable', () => {
      const result = testLine(cryptoChecks, 'CRYPTO009', `const token = Date.now().toString()`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO009');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('crypto');
    });

    it('does not flag Date.now() without security context', () => {
      const result = testLine(cryptoChecks, 'CRYPTO009', `const timestamp = Date.now()`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO010 - ECB Mode Encryption', () => {
    it('flags createCipheriv with aes-256-ecb', () => {
      const result = testLine(cryptoChecks, 'CRYPTO010', `createCipheriv('aes-256-ecb', key, null)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO010');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
      expect(result!.message).toContain('ECB');
    });

    it('does not flag createCipheriv with aes-256-cbc', () => {
      const result = testLine(cryptoChecks, 'CRYPTO010', `createCipheriv('aes-256-cbc', key, iv)`);
      expect(result).toBeNull();
    });

    it('does not flag createCipheriv with aes-256-gcm', () => {
      const result = testLine(cryptoChecks, 'CRYPTO010', `createCipheriv('aes-256-gcm', key, iv)`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO011 - Weak Key Derivation', () => {
    it('flags Buffer.from(password)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO011', `const key = Buffer.from(password)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO011');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('crypto');
      expect(result!.message).toContain('derivation');
    });

    it('flags Buffer.from(secret, "utf8")', () => {
      const result = testLine(cryptoChecks, 'CRYPTO011', `const key = Buffer.from(secret, "utf8")`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO011');
    });

    it('does not flag when scrypt is also used on the line', () => {
      const result = testLine(cryptoChecks, 'CRYPTO011', `const key = crypto.scryptSync(password, salt, 32) // not Buffer.from(password)`);
      expect(result).toBeNull();
    });

    it('does not flag Buffer.from with non-password arguments', () => {
      const result = testLine(cryptoChecks, 'CRYPTO011', `const buf = Buffer.from(data, 'hex')`);
      expect(result).toBeNull();
    });
  });

  describe('CRYPTO012 - Insufficient Random Bytes', () => {
    it('flags randomBytes(4)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO012', `const token = crypto.randomBytes(4).toString('hex')`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO012');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('crypto');
      expect(result!.message).toContain('entropy');
    });

    it('flags randomBytes(2)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO012', `crypto.randomBytes(2)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('CRYPTO012');
    });

    it('does not flag randomBytes(32)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO012', `crypto.randomBytes(32).toString('hex')`);
      expect(result).toBeNull();
    });

    it('does not flag randomBytes(16)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO012', `crypto.randomBytes(16)`);
      expect(result).toBeNull();
    });

    it('does not flag randomBytes(8)', () => {
      const result = testLine(cryptoChecks, 'CRYPTO012', `crypto.randomBytes(8)`);
      expect(result).toBeNull();
    });
  });
});
