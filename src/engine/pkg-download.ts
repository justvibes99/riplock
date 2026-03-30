/**
 * Package download and extraction for pre-install scanning.
 * Downloads npm/pip packages to a temp directory without installing them,
 * extracts the source, and returns the path for scanning.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

export type PackageManager = 'npm' | 'pip';

export interface PackageSpec {
  manager: PackageManager;
  raw: string;       // original specifier: "express@4.18.2" or "requests==2.31.0"
  name: string;      // package name without version
  version?: string;  // version constraint if present
}

export interface DownloadResult {
  spec: PackageSpec;
  extractDir: string;
  success: boolean;
  error?: string;
}

/**
 * Parse a package specifier and detect the package manager.
 * - Contains == or >= or ~= → pip
 * - Contains @ followed by version → npm
 * - Explicit manager prefix "npm:" or "pip:" overrides detection
 */
export function parsePackageSpec(raw: string): PackageSpec {
  // Explicit prefix
  if (raw.startsWith('npm:')) {
    return parseNpmSpec(raw.slice(4));
  }
  if (raw.startsWith('pip:')) {
    return parsePipSpec(raw.slice(4));
  }

  // Heuristic: Python version operators
  if (/[><=!~]=/.test(raw) || raw.includes('==')) {
    return parsePipSpec(raw);
  }

  // Default to npm
  return parseNpmSpec(raw);
}

function parseNpmSpec(raw: string): PackageSpec {
  // Scoped: @scope/name@version or @scope/name
  // Unscoped: name@version or name
  let name: string;
  let version: string | undefined;

  if (raw.startsWith('@')) {
    // Scoped package: find the second @
    const secondAt = raw.indexOf('@', 1);
    if (secondAt > 0) {
      name = raw.slice(0, secondAt);
      version = raw.slice(secondAt + 1);
    } else {
      name = raw;
    }
  } else {
    const atIdx = raw.indexOf('@');
    if (atIdx > 0) {
      name = raw.slice(0, atIdx);
      version = raw.slice(atIdx + 1);
    } else {
      name = raw;
    }
  }

  return { manager: 'npm', raw, name, version };
}

function parsePipSpec(raw: string): PackageSpec {
  const match = raw.match(/^([a-zA-Z0-9_.-]+)\s*([><=!~]+.+)?$/);
  if (match) {
    return {
      manager: 'pip',
      raw,
      name: match[1],
      version: match[2]?.trim(),
    };
  }
  return { manager: 'pip', raw, name: raw };
}

/**
 * Download and extract a single package to a temp directory.
 */
export async function downloadPackage(
  spec: PackageSpec,
  baseDir: string,
): Promise<DownloadResult> {
  const pkgDir = join(baseDir, spec.name.replace(/[/@]/g, '_'));

  try {
    if (spec.manager === 'npm') {
      return await downloadNpmPackage(spec, pkgDir);
    } else {
      return await downloadPipPackage(spec, pkgDir);
    }
  } catch (err) {
    return {
      spec,
      extractDir: pkgDir,
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function downloadNpmPackage(
  spec: PackageSpec,
  pkgDir: string,
): Promise<DownloadResult> {
  const { mkdir, readdir, rename } = await import('node:fs/promises');
  await mkdir(pkgDir, { recursive: true });

  const packTarget = spec.version ? `${spec.name}@${spec.version}` : spec.raw;

  // npm pack downloads the tarball without installing
  await exec('npm', ['pack', packTarget, '--pack-destination', pkgDir], {
    timeout: 30_000,
  });

  // Extract all tarballs
  const files = await readdir(pkgDir);
  const tmpExtract = join(pkgDir, '_tmp');
  await mkdir(tmpExtract, { recursive: true });

  for (const f of files) {
    if (f.endsWith('.tgz') || f.endsWith('.tar.gz')) {
      await exec('tar', ['xzf', join(pkgDir, f), '-C', tmpExtract], {
        timeout: 15_000,
      });
    }
  }

  // npm pack extracts to a `package/` subdirectory. Move it into a
  // `node_modules/<name>/` structure so discoverDepFiles finds it.
  const extractDir = join(pkgDir, 'extracted');
  const nmDir = join(extractDir, 'node_modules', spec.name);
  await mkdir(join(extractDir, 'node_modules'), { recursive: true });

  // The tarball extracts to _tmp/package/
  const tmpPackage = join(tmpExtract, 'package');
  try {
    await rename(tmpPackage, nmDir);
  } catch {
    // Fallback: maybe the tarball structure is different
    await rename(tmpExtract, nmDir);
  }

  return { spec, extractDir, success: true };
}

async function downloadPipPackage(
  spec: PackageSpec,
  pkgDir: string,
): Promise<DownloadResult> {
  const { mkdir, readdir } = await import('node:fs/promises');
  await mkdir(pkgDir, { recursive: true });

  // pip download fetches without installing
  const pipSpec = spec.version ? `${spec.name}${spec.version}` : spec.name;
  await exec('pip3', ['download', '--no-deps', '-d', pkgDir, pipSpec], {
    timeout: 30_000,
  });

  // Extract into a site-packages/<name>/ structure so discoverDepFiles finds it
  const extractDir = join(pkgDir, 'extracted');
  const spDir = join(extractDir, 'site-packages', spec.name);
  await mkdir(spDir, { recursive: true });

  const files = await readdir(pkgDir);
  for (const f of files) {
    const filePath = join(pkgDir, f);
    if (f.endsWith('.whl') || f.endsWith('.zip')) {
      await exec('unzip', ['-q', '-o', filePath, '-d', spDir], {
        timeout: 15_000,
      });
    } else if (f.endsWith('.tar.gz') || f.endsWith('.tgz')) {
      await exec('tar', ['xzf', filePath, '-C', spDir], {
        timeout: 15_000,
      });
    }
  }

  return { spec, extractDir, success: true };
}

/**
 * Create a temp directory for package scanning. Caller must clean up.
 */
export async function createScanDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'riplock-scan-'));
}

/**
 * Clean up a scan directory.
 */
export async function cleanupScanDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}
