import { describe, it, expect } from 'vitest';
import { extractSnippet } from '../../src/utils/snippet.js';

describe('extractSnippet', () => {
  const lines = ['line 1', 'line 2', 'line 3', 'line 4', 'line 5'];

  it('extracts snippet with context', () => {
    const result = extractSnippet(lines, 3, 2);
    expect(result.snippet).toBe('line 3');
    expect(result.contextBefore).toEqual(['line 1', 'line 2']);
    expect(result.contextAfter).toEqual(['line 4', 'line 5']);
  });

  it('handles first line', () => {
    const result = extractSnippet(lines, 1, 2);
    expect(result.snippet).toBe('line 1');
    expect(result.contextBefore).toEqual([]);
    expect(result.contextAfter).toEqual(['line 2', 'line 3']);
  });

  it('handles last line', () => {
    const result = extractSnippet(lines, 5, 2);
    expect(result.snippet).toBe('line 5');
    expect(result.contextBefore).toEqual(['line 3', 'line 4']);
    expect(result.contextAfter).toEqual([]);
  });

  it('handles empty lines array', () => {
    const result = extractSnippet([], 1, 2);
    expect(result.snippet).toBe('');
    expect(result.contextBefore).toEqual([]);
    expect(result.contextAfter).toEqual([]);
  });

  it('handles context larger than available lines', () => {
    const short = ['only line'];
    const result = extractSnippet(short, 1, 5);
    expect(result.snippet).toBe('only line');
    expect(result.contextBefore).toEqual([]);
    expect(result.contextAfter).toEqual([]);
  });
});
