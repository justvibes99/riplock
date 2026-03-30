import type { AstLanguage, FileEntry } from '../checks/types.js';
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';

export interface ParsedFile {
  tree: any;        // web-tree-sitter Tree
  rootNode: any;    // web-tree-sitter SyntaxNode
  language: AstLanguage;
}

// Extension → AstLanguage mapping
const extensionMap: Record<string, AstLanguage> = {
  js:  'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'tsx',
  ts:  'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'tsx',
  py:  'python',
  go:  'go',
  rb:  'ruby',
  php: 'php',
};

// AstLanguage → WASM file info
const wasmMap: Record<AstLanguage, { pkg: string; file: string }> = {
  javascript: { pkg: 'tree-sitter-javascript/package.json', file: 'tree-sitter-javascript.wasm' },
  typescript: { pkg: 'tree-sitter-typescript/package.json', file: 'tree-sitter-typescript.wasm' },
  tsx:        { pkg: 'tree-sitter-typescript/package.json', file: 'tree-sitter-tsx.wasm' },
  python:     { pkg: 'tree-sitter-python/package.json',     file: 'tree-sitter-python.wasm' },
  go:         { pkg: 'tree-sitter-go/package.json',         file: 'tree-sitter-go.wasm' },
  ruby:       { pkg: 'tree-sitter-ruby/package.json',       file: 'tree-sitter-ruby.wasm' },
  php:        { pkg: 'tree-sitter-php/package.json',        file: 'tree-sitter-php.wasm' },
};

// Lazy-init state
let Parser: any = null;
let LanguageClass: any = null;
let initPromise: Promise<void> | null = null;
const loadedLanguages = new Map<AstLanguage, any>();    // AstLanguage → Language instance
const parsers = new Map<AstLanguage, any>();             // AstLanguage → Parser instance
const treeCache = new Map<string, ParsedFile>();         // absolutePath → ParsedFile
const MAX_CACHE_SIZE = 500;

let verbose = false;

/** Set verbose logging mode (called externally before first use). */
export function setAstVerbose(v: boolean): void {
  verbose = v;
}

/** Check if a file extension is parseable by the AST engine. */
export function isAstParseable(extension: string): boolean {
  const ext = extension.startsWith('.') ? extension.slice(1) : extension;
  return ext in extensionMap;
}

/** Ensure the WASM runtime is initialized (idempotent). */
async function ensureInit(): Promise<void> {
  if (Parser) return;
  if (initPromise) {
    await initPromise;
    return;
  }
  initPromise = (async () => {
    try {
      const mod = await import('web-tree-sitter');
      // web-tree-sitter exports { Parser, Language, ... } as named exports
      const ParserClass = mod.Parser ?? mod.default?.Parser ?? mod.default;
      if (!ParserClass || typeof ParserClass.init !== 'function') {
        throw new Error('Could not find Parser class in web-tree-sitter module');
      }
      await ParserClass.init();
      Parser = ParserClass;
      LanguageClass = mod.Language ?? mod.default?.Language;
    } catch (err) {
      if (verbose) {
        console.error('[ast-parser] Failed to initialize web-tree-sitter:', err);
      }
      Parser = null;
      throw err;
    }
  })();
  await initPromise;
}

/** Load a language grammar, caching the result. */
async function loadLanguage(lang: AstLanguage): Promise<any> {
  const cached = loadedLanguages.get(lang);
  if (cached) return cached;

  const info = wasmMap[lang];
  const req = createRequire(import.meta.url);
  const wasmPath = join(dirname(req.resolve(info.pkg)), info.file);

  const LangLoader = LanguageClass ?? Parser.Language;
  const langInst = await LangLoader.load(wasmPath);
  loadedLanguages.set(lang, langInst);
  return langInst;
}

/** Get or create a parser for a given language. */
async function getParser(lang: AstLanguage): Promise<any> {
  const cached = parsers.get(lang);
  if (cached) return cached;

  const langInst = await loadLanguage(lang);
  const parser = new Parser();
  parser.setLanguage(langInst);
  parsers.set(lang, parser);
  return parser;
}

/**
 * Parse a file's content into a tree-sitter AST.
 * Returns null if the file is not parseable or parsing fails.
 */
export async function parseFile(file: FileEntry): Promise<ParsedFile | null> {
  const ext = file.extension.startsWith('.') ? file.extension.slice(1) : file.extension;
  const lang = extensionMap[ext];
  if (!lang) return null;

  // Check cache
  const cached = treeCache.get(file.absolutePath);
  if (cached) return cached;

  try {
    await ensureInit();

    const content = file.content;
    if (content == null) {
      if (verbose) {
        console.error(`[ast-parser] No content for file: ${file.relativePath}`);
      }
      return null;
    }

    const parser = await getParser(lang);
    const tree = parser.parse(content);
    if (!tree) {
      if (verbose) {
        console.error(`[ast-parser] Failed to parse: ${file.relativePath}`);
      }
      return null;
    }

    const result: ParsedFile = {
      tree,
      rootNode: tree.rootNode,
      language: lang,
    };

    treeCache.set(file.absolutePath, result);

    // LRU eviction: Maps maintain insertion order, so oldest entry is first
    if (treeCache.size > MAX_CACHE_SIZE) {
      const oldest = treeCache.keys().next().value;
      if (oldest) treeCache.delete(oldest);
    }

    return result;
  } catch (err) {
    if (verbose) {
      console.error(`[ast-parser] Error parsing ${file.relativePath}:`, err);
    }
    return null;
  }
}

/** Clear all cached parsed trees (call between scan runs). */
export function clearAstCache(): void {
  treeCache.clear();
}
