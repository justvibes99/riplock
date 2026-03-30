export function extractSnippet(
  lines: readonly string[],
  lineNumber: number,
  contextLines = 2,
): { snippet: string; contextBefore: string[]; contextAfter: string[] } {
  const idx = lineNumber - 1;
  const start = Math.max(0, idx - contextLines);
  const end = Math.min(lines.length - 1, idx + contextLines);

  const contextBefore: string[] = [];
  const contextAfter: string[] = [];

  for (let i = start; i < idx; i++) {
    contextBefore.push(lines[i]);
  }
  for (let i = idx + 1; i <= end; i++) {
    contextAfter.push(lines[i]);
  }

  return {
    snippet: lines[idx] ?? '',
    contextBefore,
    contextAfter,
  };
}
