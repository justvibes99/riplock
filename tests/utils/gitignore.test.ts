import { describe, it, expect } from 'vitest';
import { compileGitignore, isPathGitignored } from '../../src/utils/gitignore.js';

describe('compileGitignore', () => {
  it('returns false for everything when content is null', () => {
    const matcher = compileGitignore(null);
    expect(matcher('.env')).toBe(false);
    expect(matcher('node_modules/foo.js')).toBe(false);
  });

  it('matches exact filenames', () => {
    const matcher = compileGitignore('.env\nnode_modules/');
    expect(matcher('.env')).toBe(true);
    expect(matcher('.env.local')).toBe(false);
    expect(matcher('src/app.js')).toBe(false);
  });

  it('matches wildcard patterns', () => {
    const matcher = compileGitignore('*.log\n*.env*');
    expect(matcher('error.log')).toBe(true);
    expect(matcher('debug.log')).toBe(true);
    expect(matcher('app.js')).toBe(false);
  });

  it('matches .env* glob pattern', () => {
    const matcher = compileGitignore('.env*');
    expect(matcher('.env')).toBe(true);
    expect(matcher('.env.local')).toBe(true);
    expect(matcher('.env.production')).toBe(true);
    expect(matcher('.env.staging')).toBe(true);
    expect(matcher('.envrc')).toBe(true);
  });

  it('handles negation patterns', () => {
    const matcher = compileGitignore('.env*\n!.env.example');
    expect(matcher('.env')).toBe(true);
    expect(matcher('.env.local')).toBe(true);
    expect(matcher('.env.example')).toBe(false);
  });

  it('matches patterns in subdirectories', () => {
    const matcher = compileGitignore('*.log');
    expect(matcher('logs/error.log')).toBe(true);
    expect(matcher('deep/nested/debug.log')).toBe(true);
  });

  it('matches directory patterns', () => {
    const matcher = compileGitignore('node_modules/');
    expect(matcher('node_modules/package/index.js')).toBe(true);
  });

  it('handles ** glob patterns', () => {
    const matcher = compileGitignore('**/*.test.js');
    expect(matcher('app.test.js')).toBe(true);
    expect(matcher('src/app.test.js')).toBe(true);
    expect(matcher('src/deep/app.test.js')).toBe(true);
    expect(matcher('app.js')).toBe(false);
  });

  it('ignores comments and blank lines', () => {
    const matcher = compileGitignore('# This is a comment\n\n.env\n  # Another comment');
    expect(matcher('.env')).toBe(true);
    expect(matcher('#')).toBe(false);
  });

  it('handles anchored patterns with /', () => {
    const matcher = compileGitignore('/build');
    expect(matcher('build')).toBe(true);
    expect(matcher('build/index.js')).toBe(true);
    expect(matcher('src/build')).toBe(false);
  });
});

describe('isPathGitignored (backward compat)', () => {
  it('works as a simple wrapper', () => {
    expect(isPathGitignored('.env', '.env*')).toBe(true);
    expect(isPathGitignored('app.js', '.env*')).toBe(false);
    expect(isPathGitignored('.env', null)).toBe(false);
  });
});
