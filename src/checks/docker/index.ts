import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  Finding,
  ScanContext,
} from '../types.js';
import { createLineCheck } from '../shared.js';
import { extractSnippet } from '../../utils/snippet.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isDockerfile(file: FileEntry): boolean {
  const base = file.basename.toLowerCase();
  return base === 'dockerfile' || base.startsWith('dockerfile.');
}

// ---------------------------------------------------------------------------
// DOCKER001 - Running as Root
// ---------------------------------------------------------------------------

const DOCKER001: FileCheck = {
  level: 'file',
  id: 'DOCKER001',
  name: 'Container Runs as Root',
  description:
    'Checks that Dockerfiles include a USER directive so the container does not run as root.',
  category: 'docker',
  defaultSeverity: 'high',
  fastFilter: 'FROM',

  async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
    if (!isDockerfile(file)) return [];

    const lines = file.lines ?? (await ctx.readLines(file.absolutePath));
    const content = lines.join('\n');

    // Must have a FROM directive to be a real Dockerfile
    if (!/^FROM\s/m.test(content)) return [];

    // If there is a USER directive, the image is (likely) not running as root
    if (/^USER\s/m.test(content)) return [];

    return [
      {
        checkId: 'DOCKER001',
        title: 'Container Runs as Root',
        message:
          'Container runs as root. If compromised, the attacker has full control of the container and potentially the host.',
        severity: ctx.config.severityOverrides.get('DOCKER001') ?? 'high',
        category: 'docker',
        location: { filePath: file.relativePath, startLine: 1 },
        fix: 'Add a USER directive to run the container as a non-root user.',
        fixCode: `# Add near the end of your Dockerfile, before CMD/ENTRYPOINT:
RUN addgroup --system app && adduser --system --ingroup app app
USER app`,
      },
    ];
  },
} satisfies FileCheck;

// ---------------------------------------------------------------------------
// DOCKER002 - Secrets in ENV
// ---------------------------------------------------------------------------

const DOCKER002: CheckDefinition = createLineCheck({
  id: 'DOCKER002',
  name: 'Secrets in Dockerfile ENV',
  category: 'docker',
  severity: 'high',
  pattern: /^ENV\s+(?:\w*(?:SECRET|PASSWORD|TOKEN|KEY|PRIVATE|CREDENTIAL)\w*)[=\s]/gim,
  message:
    'Secrets in Dockerfile ENV are visible in image layers. Use Docker secrets or runtime environment variables.',
  fix: 'Pass secrets at runtime with `docker run -e` or Docker secrets instead of baking them into the image.',
  fixCode: `# Dangerous:
ENV DATABASE_PASSWORD=hunter2

# Safe - pass at runtime:
# docker run -e DATABASE_PASSWORD=hunter2 myimage`,
  validate(_match, _line, file) {
    return isDockerfile(file);
  },
});

// ---------------------------------------------------------------------------
// DOCKER003 - COPY Sensitive Files
// ---------------------------------------------------------------------------

const DOCKER003: CheckDefinition = createLineCheck({
  id: 'DOCKER003',
  name: 'COPY Sensitive Files into Image',
  category: 'docker',
  severity: 'high',
  pattern: /^COPY\s+.*(?:\.env|\.pem|\.key|id_rsa|credentials|\.npmrc)/gim,
  message:
    'Sensitive files are copied into the Docker image. They persist in image layers even if deleted later.',
  fix: 'Use a .dockerignore file to exclude sensitive files, or use multi-stage builds and Docker secrets.',
  fixCode: `# Add to .dockerignore:
.env
*.pem
*.key
id_rsa
credentials.json
.npmrc`,
  validate(_match, _line, file) {
    return isDockerfile(file);
  },
});

// ---------------------------------------------------------------------------
// DOCKER004 - Using :latest Tag
// ---------------------------------------------------------------------------

const DOCKER004: CheckDefinition = createLineCheck({
  id: 'DOCKER004',
  name: 'Unpinned Base Image Tag',
  category: 'docker',
  severity: 'medium',
  pattern: /^FROM\s+\S+(?::latest\b|\s*$)/gim,
  message:
    'Using :latest or no tag means builds are not reproducible. Pin a specific version.',
  fix: 'Pin the base image to a specific version or digest.',
  fixCode: `# Dangerous:
FROM node:latest
FROM node

# Safe:
FROM node:20-alpine
FROM node@sha256:abc123...`,
  validate(_match, _line, file) {
    return isDockerfile(file);
  },
});

// ---------------------------------------------------------------------------
// DOCKER005 - ADD Instead of COPY for Remote URLs
// ---------------------------------------------------------------------------

const DOCKER005: CheckDefinition = createLineCheck({
  id: 'DOCKER005',
  name: 'ADD with Remote URL',
  category: 'docker',
  severity: 'low',
  pattern: /^ADD\s+https?:/gim,
  message:
    'ADD with a URL fetches remote content at build time. Use COPY with a separately downloaded file for reproducibility and security.',
  fix: 'Download the file in a RUN step with curl or wget, then COPY it.',
  fixCode: `# Dangerous:
ADD https://example.com/file.tar.gz /app/

# Safe:
RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz
COPY /tmp/file.tar.gz /app/`,
  validate(_match, _line, file) {
    return isDockerfile(file);
  },
});

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const dockerChecks: CheckDefinition[] = [
  DOCKER001,
  DOCKER002,
  DOCKER003,
  DOCKER004,
  DOCKER005,
];
