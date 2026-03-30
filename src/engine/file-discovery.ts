import fg from 'fast-glob';
import { readFile, stat } from 'node:fs/promises';
import { basename, extname, relative, resolve } from 'node:path';
import type { FileEntry, ResolvedConfig } from '../checks/types.js';

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.output/**',
  '**/.vercel/**',
  '**/.netlify/**',
  '**/coverage/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.tox/**',
  '**/.mypy_cache/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/*.lock',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/bun.lockb',
  '**/*.woff',
  '**/*.woff2',
  '**/*.ttf',
  '**/*.eot',
  '**/*.ico',
  '**/*.png',
  '**/*.jpg',
  '**/*.jpeg',
  '**/*.gif',
  '**/*.svg',
  '**/*.webp',
  '**/*.avif',
  '**/*.mp3',
  '**/*.mp4',
  '**/*.webm',
  '**/*.zip',
  '**/*.tar.gz',
  '**/*.tgz',
  '**/*.pdf',
];

const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.o', '.a',
  '.wasm', '.pyc', '.pyo', '.class', '.jar',
]);

export async function discoverFiles(
  projectRoot: string,
  config: ResolvedConfig,
): Promise<Map<string, FileEntry>> {
  const ignorePatterns = [...DEFAULT_IGNORE, ...config.ignorePatterns];

  const paths = await fg('**/*', {
    cwd: projectRoot,
    ignore: ignorePatterns,
    dot: true,
    absolute: false,
    onlyFiles: true,
    followSymbolicLinks: false,
  });

  const files = new Map<string, FileEntry>();

  await Promise.all(
    paths.map(async (relPath) => {
      const absPath = resolve(projectRoot, relPath);
      const base = basename(relPath);
      let ext = extname(relPath).toLowerCase().slice(1);

      // Fix: .env.local → extension should be 'env', not 'local'
      // Any file starting with .env should be treated as extension 'env'
      if (base.startsWith('.env')) {
        ext = 'env';
      }
      // Fix: dotfiles like .npmrc, .gitignore → use name without dot as extension
      // But .eslintrc.json → ext should be 'json', not 'eslintrc.json'
      if (!ext && base.startsWith('.')) {
        const withoutDot = base.slice(1);
        const innerExt = extname(withoutDot).toLowerCase().slice(1);
        ext = innerExt || withoutDot.toLowerCase();
      }
      // Fix: firestore.rules, storage.rules → treat as 'rules'
      if (base.endsWith('.rules')) {
        ext = 'rules';
      }

      if (BINARY_EXTENSIONS.has(`.${ext}`)) return;

      try {
        const st = await stat(absPath);
        if (st.size > config.maxFileSizeBytes) return;
        if (st.size === 0) return;

        const entry: FileEntry = {
          absolutePath: absPath,
          relativePath: relPath,
          sizeBytes: st.size,
          extension: ext,
          basename: basename(relPath),
        };

        files.set(relPath, entry);
      } catch {
        // skip unreadable files
      }
    }),
  );

  return files;
}

export async function loadFileContent(entry: FileEntry): Promise<string> {
  if (entry.content !== undefined) return entry.content;
  try {
    const content = await readFile(entry.absolutePath, 'utf-8');
    entry.content = content;
    entry.lines = content.split('\n');
    return content;
  } catch {
    // Non-UTF8 file — try latin1 as fallback
    try {
      const content = await readFile(entry.absolutePath, 'latin1');
      entry.content = content;
      entry.lines = content.split('\n');
      return content;
    } catch {
      entry.content = '';
      entry.lines = [];
      return '';
    }
  }
}

export async function loadFileLines(entry: FileEntry): Promise<readonly string[]> {
  if (entry.lines !== undefined) return entry.lines;
  await loadFileContent(entry);
  return entry.lines!;
}

export function groupByExtension(
  files: Map<string, FileEntry>,
): Map<string, FileEntry[]> {
  const grouped = new Map<string, FileEntry[]>();
  for (const entry of files.values()) {
    const list = grouped.get(entry.extension) ?? [];
    list.push(entry);
    grouped.set(entry.extension, list);
  }
  return grouped;
}
