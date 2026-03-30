import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);
import type {
  CheckDefinition,
  DependencyCheck,
  ProjectCheck,
  PackageJsonData,
  LockFileData,
  Finding,
  ScanContext,
  Severity,
} from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map npm audit severity strings to RipLock severity levels. */
function mapNpmSeverity(npmSeverity: string): Severity {
  switch (npmSeverity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Naive semver "less than" check. Handles common x.y.z versions.
 * Returns true when `version` is strictly less than `threshold`.
 * Strips leading ^ ~ >= etc. from the version string.
 */
function semverLessThan(raw: string, threshold: string): boolean {
  const clean = raw.replace(/^[\^~>=<\s]+/, '');
  const a = clean.split('.').map(Number);
  const b = threshold.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av < bv) return true;
    if (av > bv) return false;
  }
  return false; // equal
}

/**
 * Naive semver "greater than or equal" check.
 */
function semverGte(raw: string, threshold: string): boolean {
  return !semverLessThan(raw, threshold);
}

/** Get all dependency names + versions from both deps and devDeps. */
function allDeps(pkg: PackageJsonData): Map<string, string> {
  const map = new Map<string, string>();
  for (const [name, version] of Object.entries(pkg.dependencies)) {
    map.set(name, version);
  }
  for (const [name, version] of Object.entries(pkg.devDependencies)) {
    map.set(name, version);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

// DEP001 - npm audit
const dep001: DependencyCheck = {
  level: 'dependency',
  id: 'DEP001',
  name: 'Known Vulnerability (npm audit)',
  description:
    'Runs npm audit to detect packages with known security vulnerabilities.',
  category: 'dependencies',
  defaultSeverity: 'high',
  async analyze(
    _packageJson: PackageJsonData,
    lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    // Only run when a lock file exists - npm audit requires it
    if (!lockFile) return [];

    // Only run for npm lock files (npm audit won't work with yarn/pnpm/bun)
    if (lockFile.type !== 'package-lock') return [];

    let auditJson: string;
    try {
      const { stdout } = await execAsync('npm audit --json', {
        cwd: ctx.projectRoot,
        encoding: 'utf-8',
        timeout: 30_000,
      });
      auditJson = stdout;
    } catch (err: unknown) {
      // npm audit exits with non-zero when vulnerabilities are found,
      // but still outputs valid JSON to stdout.
      if (err && typeof err === 'object' && 'stdout' in err) {
        auditJson = (err as { stdout: string }).stdout;
      } else {
        // Genuine failure (npm not installed, network error, etc.) — skip silently
        return [];
      }
    }

    if (!auditJson) return [];

    const findings: Finding[] = [];

    try {
      const audit = JSON.parse(auditJson);

      // npm v7+ format: audit.vulnerabilities is an object keyed by package name
      const vulnerabilities = audit.vulnerabilities ?? {};

      for (const [pkgName, vuln] of Object.entries<Record<string, unknown>>(vulnerabilities)) {
        const severity = mapNpmSeverity(String(vuln.severity ?? 'moderate'));
        const title = String(vuln.title ?? 'Known vulnerability');
        const viaEntries = Array.isArray(vuln.via) ? vuln.via : [];
        const description = viaEntries
          .filter((v: unknown) => typeof v === 'object' && v !== null && 'title' in v)
          .map((v: Record<string, unknown>) => String(v.title))
          .join('; ') || title;

        const fixAvailable = vuln.fixAvailable;
        let fixText = 'Run "npm audit fix" to attempt an automatic fix, or update the package manually.';
        if (fixAvailable && typeof fixAvailable === 'object' && 'version' in fixAvailable) {
          fixText = `Update to ${String((fixAvailable as Record<string, unknown>).name ?? pkgName)} ${String((fixAvailable as Record<string, unknown>).version)}. Run "npm audit fix" to apply.`;
        }

        findings.push({
          checkId: 'DEP001',
          title: `Vulnerable package: ${pkgName}`,
          message: `Package "${pkgName}" has a known vulnerability: ${description}.`,
          severity,
          category: 'dependencies',
          location: { filePath: 'package.json', startLine: 1 },
          fix: fixText,
        });
      }
    } catch {
      // Malformed JSON output — skip
    }

    return findings;
  },
};

// DEP002 - Dangerous / compromised packages
interface DangerousPackage {
  name: string;
  reason: string;
  /** If set, only flag when the installed version matches this predicate. */
  versionCheck?: (version: string) => boolean;
}

const DANGEROUS_PACKAGES: DangerousPackage[] = [
  {
    name: 'event-stream',
    reason: 'This package was compromised in 2018 to steal cryptocurrency wallets.',
  },
  {
    name: 'flatmap-stream',
    reason: 'This package was the malicious payload injected into event-stream.',
  },
  {
    name: 'ua-parser-js',
    reason: 'Versions before 1.0.33 were compromised with cryptomining and password-stealing malware.',
    versionCheck: (v) => semverLessThan(v, '1.0.33'),
  },
  {
    name: 'colors',
    reason: 'Versions after 1.4.0 were sabotaged by the maintainer to print garbage output (protest-ware).',
    versionCheck: (v) => semverGte(v, '1.4.1'),
  },
  {
    name: 'faker',
    reason: 'Versions after 6.6.6 were sabotaged by the maintainer to print garbage output (protest-ware).',
    versionCheck: (v) => semverGte(v, '6.6.7'),
  },
  {
    name: 'node-ipc',
    reason: 'Versions after 10.1.0 contained protest-ware that could overwrite files on disk.',
    versionCheck: (v) => semverGte(v, '10.1.1'),
  },
];

const dep002: DependencyCheck = {
  level: 'dependency',
  id: 'DEP002',
  name: 'Compromised or Sabotaged Package',
  description:
    'Detects packages that have been compromised, hijacked, or intentionally sabotaged by their maintainers.',
  category: 'dependencies',
  defaultSeverity: 'critical',
  async analyze(
    packageJson: PackageJsonData,
    _lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    const deps = allDeps(packageJson);
    const findings: Finding[] = [];

    for (const dangerous of DANGEROUS_PACKAGES) {
      const version = deps.get(dangerous.name);
      if (!version) continue;

      // If there's a version check, only flag matching versions
      if (dangerous.versionCheck && !dangerous.versionCheck(version)) continue;

      const severity =
        ctx.config.severityOverrides.get('DEP002') ?? 'critical';

      findings.push({
        checkId: 'DEP002',
        title: `Compromised package: ${dangerous.name}`,
        message: `Package "${dangerous.name}" has been compromised or sabotaged. ${dangerous.reason}`,
        severity,
        category: 'dependencies',
        location: { filePath: 'package.json', startLine: 1 },
        fix: `Remove "${dangerous.name}" from your dependencies immediately. Find a maintained, trustworthy alternative.`,
      });
    }

    return findings;
  },
};

// DEP003 - No lock file
const dep003: ProjectCheck = {
  level: 'project',
  id: 'DEP003',
  name: 'No Package Lock File',
  description:
    'Checks that a package lock file exists to ensure deterministic installs.',
  category: 'dependencies',
  defaultSeverity: 'medium',
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    // Only relevant if there IS a package.json
    if (!ctx.packageJson) return [];

    if (ctx.lockFile) return [];

    const severity =
      ctx.config.severityOverrides.get('DEP003') ?? 'medium';

    return [
      {
        checkId: 'DEP003',
        title: 'No package lock file found',
        message:
          'No package lock file found (package-lock.json, yarn.lock, pnpm-lock.yaml, or bun.lockb). Without a lock file, you might install different and potentially malicious versions of your dependencies.',
        severity,
        category: 'dependencies',
        location: { filePath: 'package.json', startLine: 1 },
        fix: '1. Run "npm install" (or yarn/pnpm/bun install) to generate a lock file.\n2. Commit the lock file to version control.\n3. Always use "npm ci" in CI/CD pipelines for reproducible builds.',
      },
    ];
  },
};

// DEP004 - Prototype pollution packages
interface VulnerablePackage {
  name: string;
  fixedVersion: string;
  description: string;
}

const PROTOTYPE_POLLUTION_PACKAGES: VulnerablePackage[] = [
  {
    name: 'lodash',
    fixedVersion: '4.17.21',
    description: 'Lodash before 4.17.21 is vulnerable to prototype pollution via merge, set, and zipObjectDeep.',
  },
  {
    name: 'minimist',
    fixedVersion: '1.2.6',
    description: 'Minimist before 1.2.6 is vulnerable to prototype pollution via crafted command-line arguments.',
  },
  {
    name: 'qs',
    fixedVersion: '6.10.3',
    description: 'qs before 6.10.3 is vulnerable to prototype pollution via crafted query strings.',
  },
  {
    name: 'merge',
    fixedVersion: '2.1.1',
    description: 'merge before 2.1.1 is vulnerable to prototype pollution when recursively merging objects.',
  },
];

const dep004: DependencyCheck = {
  level: 'dependency',
  id: 'DEP004',
  name: 'Prototype Pollution Vulnerability',
  description:
    'Detects packages with known prototype pollution vulnerabilities.',
  category: 'dependencies',
  defaultSeverity: 'high',
  async analyze(
    packageJson: PackageJsonData,
    _lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    const deps = allDeps(packageJson);
    const findings: Finding[] = [];

    for (const vuln of PROTOTYPE_POLLUTION_PACKAGES) {
      const version = deps.get(vuln.name);
      if (!version) continue;

      if (semverLessThan(version, vuln.fixedVersion)) {
        const severity =
          ctx.config.severityOverrides.get('DEP004') ?? 'high';

        findings.push({
          checkId: 'DEP004',
          title: `Prototype pollution: ${vuln.name}`,
          message: `Package "${vuln.name}" has a known prototype pollution vulnerability. ${vuln.description}`,
          severity,
          category: 'dependencies',
          location: { filePath: 'package.json', startLine: 1 },
          fix: `Update "${vuln.name}" to version ${vuln.fixedVersion} or later: npm install ${vuln.name}@latest`,
        });
      }
    }

    return findings;
  },
};

// DEP005 - Vulnerable framework / library versions
interface VulnerableVersion {
  name: string;
  maxVersion: string;
  cve: string;
  impact: string;
}

/**
 * Check if a semver version falls within a range [minVersion, maxVersion).
 * Returns true if version >= minVersion AND version < maxVersion.
 */
function semverInRange(raw: string, minVersion: string, maxVersion: string): boolean {
  return semverGte(raw, minVersion) && semverLessThan(raw, maxVersion);
}

const VULNERABLE_VERSIONS: VulnerableVersion[] = [
  {
    name: 'next',
    maxVersion: '14.1.1',
    cve: 'CVE-2024-34350/CVE-2024-34351',
    impact: 'Server-Side Request Forgery (SSRF) allowing attackers to make requests to internal services through your Next.js server.',
  },
  {
    name: 'next',
    maxVersion: '15.2.3',
    cve: 'CVE-2025-29927',
    impact: 'Middleware authentication bypass allowing attackers to skip your auth checks and access protected routes.',
  },
  {
    name: 'express',
    maxVersion: '4.19.2',
    cve: 'CVE-2024-29041',
    impact: 'Open redirect vulnerability allowing attackers to redirect users to malicious sites through your Express app.',
  },
  {
    name: 'jsonwebtoken',
    maxVersion: '9.0.0',
    cve: 'CVE-2022-23529',
    impact: 'Remote Code Execution (RCE) through crafted JWT secret key objects, allowing full server takeover.',
  },
  {
    name: 'serialize-javascript',
    maxVersion: '3.1.0',
    cve: 'CVE-2020-7660',
    impact: 'Remote Code Execution (RCE) through crafted serialized payloads.',
  },
];

const dep005: DependencyCheck = {
  level: 'dependency',
  id: 'DEP005',
  name: 'Critically Vulnerable Package Version',
  description:
    'Detects packages at versions with known critical vulnerabilities (SSRF, RCE, auth bypass).',
  category: 'dependencies',
  defaultSeverity: 'critical',
  async analyze(
    packageJson: PackageJsonData,
    _lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    const deps = allDeps(packageJson);
    const findings: Finding[] = [];
    const severity = ctx.config.severityOverrides.get('DEP005') ?? 'critical';

    for (const vuln of VULNERABLE_VERSIONS) {
      const version = deps.get(vuln.name);
      if (!version) continue;

      if (semverLessThan(version, vuln.maxVersion)) {
        findings.push({
          checkId: 'DEP005',
          title: `Vulnerable version: ${vuln.name} (${vuln.cve})`,
          message: `Package "${vuln.name}" is at a version affected by ${vuln.cve}. ${vuln.impact}`,
          severity,
          category: 'dependencies',
          location: { filePath: 'package.json', startLine: 1 },
          fix: `Update to the latest version: npm install ${vuln.name}@latest`,
        });
      }
    }

    // Special case: react / react-dom 19.0.0 to 19.1.0 (CVE-2025-55182 React2Shell RCE)
    for (const pkg of ['react', 'react-dom']) {
      const version = deps.get(pkg);
      if (!version) continue;

      if (semverInRange(version, '19.0.0', '19.1.1')) {
        findings.push({
          checkId: 'DEP005',
          title: `Vulnerable version: ${pkg} (CVE-2025-55182)`,
          message: `Package "${pkg}" is at a version affected by CVE-2025-55182 (React2Shell). This allows Remote Code Execution through crafted React component trees.`,
          severity,
          category: 'dependencies',
          location: { filePath: 'package.json', startLine: 1 },
          fix: `Update to the latest version: npm install ${pkg}@latest`,
        });
      }
    }

    // Special case: node-serialize at any version (inherently unsafe)
    const nodeSerializeVersion = deps.get('node-serialize');
    if (nodeSerializeVersion) {
      findings.push({
        checkId: 'DEP005',
        title: 'Vulnerable package: node-serialize (CVE-2017-5941)',
        message: 'Package "node-serialize" is inherently unsafe at ANY version. It allows Remote Code Execution through crafted serialized objects (CVE-2017-5941).',
        severity,
        category: 'dependencies',
        location: { filePath: 'package.json', startLine: 1 },
        fix: 'Remove node-serialize entirely. Use JSON.stringify/JSON.parse for serialization.',
      });
    }

    return findings;
  },
};

// DEP006 - node-serialize usage (inherently unsafe)
const dep006: DependencyCheck = {
  level: 'dependency',
  id: 'DEP006',
  name: 'Inherently Unsafe Serialization Package',
  description:
    'Detects node-serialize, which is inherently unsafe and allows Remote Code Execution at any version.',
  category: 'dependencies',
  defaultSeverity: 'critical',
  async analyze(
    packageJson: PackageJsonData,
    _lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    const deps = allDeps(packageJson);
    const version = deps.get('node-serialize');
    if (!version) return [];

    const severity = ctx.config.severityOverrides.get('DEP006') ?? 'critical';

    return [
      {
        checkId: 'DEP006',
        title: 'Inherently unsafe package: node-serialize',
        message:
          'The node-serialize package is inherently unsafe and allows Remote Code Execution. It should never be used with untrusted data.',
        severity,
        category: 'dependencies',
        location: { filePath: 'package.json', startLine: 1 },
        fix: 'Remove node-serialize entirely. Use JSON.stringify/JSON.parse for serialization.',
      },
    ];
  },
};

// DEP007 - Permissive Version Range
const dep007: DependencyCheck = {
  level: 'dependency',
  id: 'DEP007',
  name: 'Permissive Version Range',
  description:
    'Detects dependencies using overly permissive version ranges (* , >= , >) that could pull in malicious updates.',
  category: 'dependencies',
  defaultSeverity: 'medium',
  async analyze(
    packageJson: PackageJsonData,
    _lockFile: LockFileData | null,
    ctx: ScanContext,
  ): Promise<Finding[]> {
    const findings: Finding[] = [];
    const severity = ctx.config.severityOverrides.get('DEP007') ?? 'medium';

    const PERMISSIVE_RE = /^(\*|>=\s*\d|>\s*\d)/;

    const deps = allDeps(packageJson);
    for (const [name, version] of deps) {
      if (!PERMISSIVE_RE.test(version.trim())) continue;

      findings.push({
        checkId: 'DEP007',
        title: `Permissive version range: ${name}`,
        message: `Dependency "${name}" uses an overly permissive version range ("${version}"). A malicious update could be installed automatically.`,
        severity,
        category: 'dependencies',
        location: { filePath: 'package.json', startLine: 1 },
        fix: `Pin "${name}" to a specific version or use a caret (^) / tilde (~) range instead of "${version}".`,
      });
    }

    return findings;
  },
};

// DEP008 - Python Requirements with Known Vulnerabilities
interface PythonVuln {
  name: string;
  fixedVersion: string;
  cve: string;
}

const PYTHON_VULNERABLE_PACKAGES: PythonVuln[] = [
  { name: 'django', fixedVersion: '4.2.8', cve: 'CVE-2023-46695' },
  { name: 'flask', fixedVersion: '2.3.3', cve: 'CVE-2023-30861' },
  { name: 'requests', fixedVersion: '2.31.0', cve: 'CVE-2023-32681' },
  { name: 'cryptography', fixedVersion: '41.0.4', cve: 'CVE-2023-38325' },
  { name: 'pyyaml', fixedVersion: '6.0.1', cve: 'Known vulnerability' },
  { name: 'pillow', fixedVersion: '10.0.1', cve: 'Known vulnerability' },
  { name: 'jinja2', fixedVersion: '3.1.3', cve: 'Known vulnerability' },
  { name: 'werkzeug', fixedVersion: '3.0.1', cve: 'Known vulnerability' },
  { name: 'urllib3', fixedVersion: '2.0.7', cve: 'Known vulnerability' },
  { name: 'certifi', fixedVersion: '2023.7.22', cve: 'Known vulnerability' },
];

/**
 * Parse a requirements.txt line into [package, version] or null.
 * Handles formats: package==version, package>=version, package~=version
 */
function parseRequirementsLine(line: string): [string, string] | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) return null;
  const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|~=|<=)\s*([^\s;#]+)/);
  if (!match) return null;
  return [match[1].toLowerCase(), match[2]];
}

const dep008: ProjectCheck = {
  level: 'project',
  id: 'DEP008',
  name: 'Python Requirements with Known Vulnerabilities',
  description:
    'Scans requirements.txt for Python packages with known security vulnerabilities.',
  category: 'dependencies',
  defaultSeverity: 'high',
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    // Look for requirements.txt
    let reqContent: string | null = null;
    for (const file of ctx.files.values()) {
      if (file.basename === 'requirements.txt') {
        reqContent = await ctx.readFile(file.absolutePath);
        break;
      }
    }
    if (!reqContent) return [];

    const findings: Finding[] = [];
    const severity = ctx.config.severityOverrides.get('DEP008') ?? 'high';
    const lines = reqContent.split('\n');

    for (const line of lines) {
      const parsed = parseRequirementsLine(line);
      if (!parsed) continue;
      const [pkgName, version] = parsed;

      for (const vuln of PYTHON_VULNERABLE_PACKAGES) {
        if (pkgName === vuln.name && semverLessThan(version, vuln.fixedVersion)) {
          findings.push({
            checkId: 'DEP008',
            title: `Vulnerable Python package: ${vuln.name} (${vuln.cve})`,
            message: `Python package "${vuln.name}" at version ${version} has a known vulnerability (${vuln.cve}). Update to ${vuln.fixedVersion} or later.`,
            severity,
            category: 'dependencies',
            location: { filePath: 'requirements.txt', startLine: 1 },
            fix: `Update "${vuln.name}" to version ${vuln.fixedVersion} or later in requirements.txt.`,
          });
        }
      }
    }

    return findings;
  },
};

// DEP009 - Gemfile Without Bundle Audit
const dep009: ProjectCheck = {
  level: 'project',
  id: 'DEP009',
  name: 'Gemfile Without Bundle Audit',
  description:
    'Checks if a Ruby project has bundler-audit for vulnerability scanning.',
  category: 'dependencies',
  defaultSeverity: 'medium',
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    // Check for Gemfile
    let hasGemfile = false;
    let gemfileContent = '';
    for (const file of ctx.files.values()) {
      if (file.basename === 'Gemfile') {
        hasGemfile = true;
        gemfileContent = await ctx.readFile(file.absolutePath);
        break;
      }
    }
    if (!hasGemfile) return [];

    // Check if bundler-audit is referenced in Gemfile
    if (/bundler-audit|bundle.audit/i.test(gemfileContent)) return [];

    const severity = ctx.config.severityOverrides.get('DEP009') ?? 'medium';

    return [
      {
        checkId: 'DEP009',
        title: 'Ruby project without bundle-audit',
        message:
          'Ruby project without bundle-audit. Run `bundle audit` to check for vulnerable gems.',
        severity,
        category: 'dependencies',
        location: { filePath: 'Gemfile', startLine: 1 },
        fix: 'Add bundler-audit to your Gemfile and run `bundle audit` regularly.\ngem "bundler-audit", group: :development',
      },
    ];
  },
};

// DEP010 - Python Without Safety/pip-audit
const dep010: ProjectCheck = {
  level: 'project',
  id: 'DEP010',
  name: 'Python Without pip-audit',
  description:
    'Detects Python projects without a vulnerability scanning tool configured.',
  category: 'dependencies',
  defaultSeverity: 'medium',
  async analyze(ctx: ScanContext): Promise<Finding[]> {
    let hasPythonProject = false;
    let detectedFile = '';
    for (const file of ctx.files.values()) {
      if (file.basename === 'requirements.txt' || file.basename === 'pyproject.toml') {
        hasPythonProject = true;
        detectedFile = file.basename;
        break;
      }
    }
    if (!hasPythonProject) return [];

    const severity = ctx.config.severityOverrides.get('DEP010') ?? 'medium';

    return [
      {
        checkId: 'DEP010',
        title: 'Python project without vulnerability scanning',
        message:
          'Python project detected. Run `pip-audit` or `safety check` to scan for vulnerable packages.',
        severity,
        category: 'dependencies',
        location: { filePath: detectedFile, startLine: 1 },
        fix: 'Install pip-audit (`pip install pip-audit`) and run it regularly, or add it to your CI pipeline.',
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const dependencyChecks: CheckDefinition[] = [
  dep001,
  dep002,
  dep003,
  dep004,
  dep005,
  dep006,
  dep007,
  dep008,
  dep009,
  dep010,
];
