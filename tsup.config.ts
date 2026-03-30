import { defineConfig } from 'tsup';
import { copyFileSync, mkdirSync } from 'node:fs';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  clean: true,
  banner: {
    js: '#!/usr/bin/env node',
  },
  sourcemap: false,
  splitting: false,
  treeshake: true,
  // Keep tree-sitter packages external — they need runtime WASM file resolution
  external: [
    'web-tree-sitter',
    'tree-sitter-javascript',
    'tree-sitter-typescript',
    'tree-sitter-python',
    'tree-sitter-go',
    'tree-sitter-ruby',
    'tree-sitter-php',
    '@ast-grep/napi',
  ],
  onSuccess: async () => {
    // Copy built-in rules JSON to dist so the rule loader can find it at runtime
    mkdirSync('dist/rules', { recursive: true });
    copyFileSync('src/rules/builtin.json', 'dist/rules/builtin.json');
  },
});
