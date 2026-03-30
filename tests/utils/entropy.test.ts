import { describe, it, expect } from 'vitest';
import { shannonEntropy, isPlaceholder } from '../../src/utils/entropy.js';

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for single character repeated', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('returns higher entropy for diverse characters', () => {
    const low = shannonEntropy('aaaa');
    const mid = shannonEntropy('aabb');
    const high = shannonEntropy('aBc1DefG2h');
    expect(mid).toBeGreaterThan(low);
    expect(high).toBeGreaterThan(mid);
  });

  it('returns ~1 bit for perfectly balanced binary', () => {
    const entropy = shannonEntropy('ab');
    expect(entropy).toBeCloseTo(1.0, 1);
  });
});

describe('isPlaceholder', () => {
  it('detects common placeholder words', () => {
    expect(isPlaceholder('your-api-key-here')).toBe(true);
    expect(isPlaceholder('CHANGE_ME')).toBe(true);
    expect(isPlaceholder('placeholder_value')).toBe(true);
    expect(isPlaceholder('example_key_123')).toBe(true);
    expect(isPlaceholder('INSERT_YOUR_KEY')).toBe(true);
    expect(isPlaceholder('fake-token')).toBe(true);
    expect(isPlaceholder('mock_secret')).toBe(true);
    expect(isPlaceholder('dummy_key')).toBe(true);
    expect(isPlaceholder('test_key_abc')).toBe(true);
    expect(isPlaceholder('sample_value')).toBe(true);
    expect(isPlaceholder('replace-me-now')).toBe(true);
    expect(isPlaceholder('put_your_key')).toBe(true);
  });

  it('does not flag real-looking secrets', () => {
    expect(isPlaceholder('sk_live_4eC39HqLyjWDarjtT1zdp7dc')).toBe(false);
    expect(isPlaceholder('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef')).toBe(false);
    expect(isPlaceholder('AKIAIOSFODNN7EXAMPLE')).toBe(true); // contains "example"
  });

  it('detects config template syntax', () => {
    expect(isPlaceholder('env(S3_SECRET_KEY)')).toBe(true);
    expect(isPlaceholder('secret_key = "env(S3_SECRET_KEY)"')).toBe(true);
    expect(isPlaceholder('${DATABASE_URL}')).toBe(true);
    expect(isPlaceholder('process.env.SECRET_KEY')).toBe(true);
  });

  it('does not flag strings without placeholder indicators', () => {
    expect(isPlaceholder('aB3kL9mNpQ2rStUvWxYz')).toBe(false);
    expect(isPlaceholder('1234567890abcdef')).toBe(false);
  });
});
