/**
 * `riplock scan-pkg` — download and scan packages for supply chain attacks
 * before installing them. Downloads to a temp directory, runs supply chain
 * checks, reports findings, and cleans up.
 */
import pc from 'picocolors';
import { defaultConfig } from '../config/defaults.js';
import { scan } from '../engine/scanner.js';
import { renderTerminal } from '../reporters/terminal.js';
import { renderJson } from '../reporters/json.js';
import {
  parsePackageSpec,
  downloadPackage,
  createScanDir,
  cleanupScanDir,
  type PackageSpec,
  type DownloadResult,
} from '../engine/pkg-download.js';

interface ScanPkgOptions {
  manager?: 'npm' | 'pip';
  json?: boolean;
  version: string;
}

/**
 * Download, scan, and report on one or more packages.
 * Returns exit code: 0 = clean, 1 = findings, 2 = error.
 */
export async function scanPackages(
  packages: string[],
  opts: ScanPkgOptions,
): Promise<number> {
  const scanDir = await createScanDir();

  try {
    // Parse specs
    const specs: PackageSpec[] = packages.map(raw => {
      const spec = parsePackageSpec(raw);
      // Override manager if explicitly set
      if (opts.manager) spec.manager = opts.manager;
      return spec;
    });

    if (!opts.json) {
      console.log('');
      console.log(pc.bold(`  riplock v${opts.version}`) + pc.dim(' — pre-install package scan'));
      console.log('');
    }

    // Download all packages
    const downloads: DownloadResult[] = [];
    for (const spec of specs) {
      if (!opts.json) {
        process.stdout.write(pc.dim(`  Downloading ${spec.raw}...`));
      }
      const result = await downloadPackage(spec, scanDir);
      downloads.push(result);
      if (!opts.json) {
        if (result.success) {
          console.log(pc.green(' ok'));
        } else {
          console.log(pc.red(` failed: ${result.error}`));
        }
      }
    }

    // Check for download failures
    const failed = downloads.filter(d => !d.success);
    if (failed.length === downloads.length) {
      if (!opts.json) {
        console.error(pc.red('\n  All package downloads failed.'));
      }
      return 2;
    }

    if (!opts.json) {
      console.log('');
    }

    // Scan each downloaded package
    let hasFindings = false;

    for (const dl of downloads) {
      if (!dl.success) continue;

      const config = defaultConfig({
        scanDeps: true,
        maxFileSizeBytes: 2_097_152,
        format: opts.json ? 'json' : 'terminal',
      });

      const result = await scan(dl.extractDir, config);

      if (result.findings.length > 0) {
        hasFindings = true;
      }

      if (opts.json) {
        console.log(JSON.stringify({
          package: dl.spec.raw,
          manager: dl.spec.manager,
          ...JSON.parse(renderJson(result, opts.version)),
        }));
      } else {
        if (result.findings.length > 0) {
          console.log(pc.red(pc.bold(`  ${dl.spec.raw}`)) + pc.dim(` (${dl.spec.manager})`));
          console.log(renderTerminal(result, opts.version));
        } else {
          console.log(
            pc.green(`  ✓ ${dl.spec.raw}`) +
            pc.dim(` — clean (${result.filesScanned} files scanned)`),
          );
        }
      }
    }

    // Print summary for failed downloads
    if (failed.length > 0 && !opts.json) {
      console.log('');
      for (const f of failed) {
        console.log(pc.yellow(`  ⚠ ${f.spec.raw} — download failed: ${f.error}`));
      }
    }

    if (!opts.json) {
      console.log('');
    }

    return hasFindings ? 1 : 0;
  } finally {
    await cleanupScanDir(scanDir);
  }
}
