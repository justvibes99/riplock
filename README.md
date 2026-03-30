![RipLock — we lock it down so you can let it rip](banner.jpg)

# RipLock

**Security scanner — we lock it down so you can let it rip.**

RipLock scans your codebase for security vulnerabilities using AST taint tracking, structural pattern matching, and 537 security checks across 7 languages and 10+ infrastructure platforms. It also scans packages *before* you install them to catch supply chain attacks. Every finding comes with a plain-English explanation and copy-paste fix.

## Quick Start

```bash
npx riplock-cli-cli                            # Scan your code
npx riplock-cli-cli scan-pkg express axios     # Scan packages before installing
```

## How It Works

RipLock uses five detection engines:

1. **AST Taint Tracking** — Parses code with tree-sitter, traces user input through variables, object properties, promise callbacks, and function calls to dangerous sinks. Cross-file analysis follows imports 3 levels deep.
2. **ast-grep Structural Matching** — Semgrep-style pattern-as-code matching with metavariables (`$DB.query($SQL)`) and compound operators (`inside`, `has`, `not`).
3. **268 Hardcoded Checks** — Battle-tested TypeScript checks with custom validation logic, iteratively calibrated against 18 real-world projects.
4. **269 Rule Engine Rules** — JSON-defined patterns (regex and ast-grep) loaded at runtime. User-extensible via `.riplock-rules.json`.
5. **Cross-File Taint** — Resolves imports between project files, builds function taint signatures, detects data flow across module boundaries.

```javascript
// RipLock traces this across variables and files:
// file: routes/users.ts
import { findUser } from './db';
app.get('/users', async (req, res) => {
  const id = req.params.id;           // ← source
  const user = await findUser(id);     // ← cross-file call
  res.json(user);
});

// file: db.ts
export function findUser(id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);  // ← sink
}
```

Output:
```
CRITICAL  SQL Injection (Taint-Tracked)                AST-INJ001
  Data flow:
  └ req.params.id (line 3)
  ├ id (line 4)
  └ db.query(...) (line 9, db.ts)
```

## Supported Languages

| Language | Regex Checks | AST Taint Tracking | ast-grep Patterns |
|---|---|---|---|
| JavaScript / TypeScript / TSX | Yes | Yes | Yes (metavariables) |
| Python | Yes | Yes | Yes (kind-based) |
| Go | Yes | Yes | Yes (kind-based) |
| Ruby | Yes | Yes | Yes (kind-based) |
| PHP | Yes | — | — |

## Supported Infrastructure

Terraform, Kubernetes, Helm, CloudFormation, Docker, Nginx, Apache, Ansible, Serverless Framework, GitHub Actions — plus 12 generic config checks for any YAML/JSON/TOML/INI file.

## Usage

### Scan your code

```bash
npx riplock-cli                           # Scan current directory
npx riplock-cli ./my-project              # Scan a specific path
npx riplock-cli --severity high           # Only critical + high findings
npx riplock-cli --json                    # JSON output for CI
npx riplock-cli --sarif                   # SARIF 2.1.0 for GitHub Code Scanning
npx riplock-cli --ignore SEC007 GIT010    # Skip specific checks
npx riplock-cli --exclude 'tests/**'      # Exclude files by glob pattern
npx riplock-cli --no-deps                 # Skip npm audit (faster)
npx riplock-cli --scan-deps               # Scan installed dependencies (node_modules etc.)
npx riplock-cli --list-checks             # Show all checks
npx riplock-cli --verbose                 # Show timing and debug info
```

### Scan packages before installing

```bash
npx riplock-cli scan-pkg express@4.21.2           # Scan an npm package
npx riplock-cli scan-pkg requests==2.31.0 --pip   # Scan a pip package
npx riplock-cli scan-pkg lodash moment axios      # Scan multiple packages
npx riplock-cli scan-pkg express --json           # JSON output for automation
```

Downloads the package tarball without installing, extracts it to a temp directory, runs 12 supply chain checks (credential exfiltration, reverse shells, install script attacks, obfuscated code, cryptominers, etc.), and cleans up. Use this to vet packages before adding them to your project.

## What It Catches

537 checks across 18 categories:

| Category | Checks | What It Finds |
|---|---|---|
| **Secrets** | 33 | API keys (30+ providers), passwords, private keys, database URLs, base64-encoded secrets |
| **Injection** | 27+ | SQL injection, NoSQL, command injection, XSS, eval, SSRF, path traversal, prototype pollution, mass assignment, prompt injection, zip slip |
| **Auth** | 23 | Weak JWTs, missing auth, insecure cookies, plaintext passwords, IDOR, webhooks, CSRF, OAuth, session fixation, account lockout |
| **IaC** | 47+ | Terraform, K8s, Helm, CloudFormation, Nginx, Apache, Ansible, Serverless + 12 generic config patterns |
| **Framework** | 16 | Next.js server actions, NEXT_PUBLIC_ leaks, Firebase/Supabase misconfigs, Express hardening |
| **Config** | 12 | Debug mode, default credentials, CSP, admin panels, error monitoring |
| **Git** | 11 | .gitignore, .env, sensitive files, secrets in .env.example |
| **Crypto** | 12 | MD5/SHA, Math.random, ECB mode, weak key derivation, timing attacks, DES/RC4 |
| **Dependencies** | 10 | npm audit, Python/Ruby dep scanning, compromised packages, CVEs, permissive ranges |
| **Network** | 7 | CORS, security headers, SSRF, HTTP URLs, origin reflection |
| **DoS** | 7 | ReDoS, timeouts, unbounded queries, body limits, connection pools |
| **Uploads** | 5 | File type/size validation, path traversal, public directories, content-type |
| **Python** | 12 | Django/Flask security, pickle, yaml.load, f-string injection |
| **Go** | 9 | SQL injection, command injection, TLS config, unhandled errors |
| **Ruby** | 8 | Rails mass assignment, Marshal.load, YAML deserialization |
| **PHP** | 9 | SQL injection, file inclusion, register_globals, XSS |
| **Docker** | 5 | Root containers, secrets in layers, unpinned tags |
| **CI/CD** | 6 | Script injection, unpinned actions, pull_request_target, permissions |

| **Supply Chain** | 12 | Credential exfiltration, reverse shells, install script attacks, obfuscated code, cryptominers, .pth code execution, DNS exfiltration, system persistence |

Run `npx riplock-cli --list-checks` for the full catalog.

## Custom Rules

Create `.riplock-rules.json` in your project:

```json
{
  "rules": [
    {
      "id": "CUSTOM-001",
      "message": "Direct database access outside repository layer",
      "severity": "high",
      "category": "injection",
      "languages": ["typescript"],
      "pattern": "prisma.$TABLE.$METHOD",
      "pattern-mode": "ast",
      "paths": { "exclude": ["src/repositories/**"] },
      "fix": "Use the repository pattern for all database access"
    }
  ]
}
```

Supports regex patterns, ast-grep structural patterns with `$METAVAR` metavariables, and compound operators (`inside`, `has`, `not`, `follows`, `precedes`).

## Configuration

Create `.riplock.json` in your project root:

```json
{
  "disable": ["CONFIG011", "CICD002"],
  "severity": "medium",
  "exclude": ["tests/**", "scripts/**"],
  "skipDeps": true
}
```

## CI Integration

### GitHub Actions

```yaml
- name: Security scan
  run: npx riplock-cli --severity high

# With SARIF upload to GitHub Code Scanning:
- name: Security scan (SARIF)
  run: npx riplock-cli --sarif > results.sarif
  continue-on-error: true
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  script: npx riplock-cli --severity high --json > riplock.json
  artifacts:
    reports:
      security: riplock.json
```

## Using with AI Coding Assistants

RipLock scans every file systematically in milliseconds — something that would cost an AI assistant 200K+ tokens to do by reading files one at a time. Run RipLock first, then let your AI focus on the findings that need judgment.

### Option 1: Manual

Run it yourself and share findings with your AI:

```bash
riplock . --severity high
# Copy interesting findings into your AI conversation

# Or pipe JSON directly:
riplock . --json | pbcopy
# Then: "Here are the security findings — fix them"
```

### Option 2: AI instructions (recommended)

Add to your project's `CLAUDE.md`, `.cursorrules`, or equivalent instructions file:

```markdown
## Security

Before committing or creating a PR, run a security scan:
  riplock . --no-deps --severity high

Fix any critical or high findings before proceeding.
```

Your AI assistant will run the scan as part of its workflow, read the findings, and fix them with full context of what the code is supposed to do. This is the best balance of coverage and simplicity.

### Option 3: Pre-install hook (Claude Code)

RipLock ships ready-made Claude Code hooks in the `hooks/` directory. The pre-install hook scans packages with `riplock scan-pkg` before allowing `npm install`, `pip install`, `npx -y`, or `uvx` commands. It also hard-blocks ephemeral package runners (`npx -y`, `uvx`) without version pins, since those have no lockfile.

Copy the hooks and add to your `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "/path/to/hooks/check-install-safety.sh",
        "timeout": 60,
        "statusMessage": "Scanning packages for malware..."
      }]
    }],
    "PostToolUse": [{
      "matcher": "Write|Edit",
      "hooks": [{
        "type": "command",
        "command": "/path/to/hooks/check-supply-chain.sh",
        "timeout": 10,
        "statusMessage": "Checking for supply chain risks..."
      }]
    }]
  }
}
```

The pre-install hook downloads and scans packages before installation. The post-write hook catches supply chain risks in config files (unpinned MCP servers, `*`/`latest` dependencies, install scripts).

### Option 4: Post-edit scan hook

Surface findings as warnings after every code change:

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "Write|Edit",
      "hooks": [{
        "type": "command",
        "command": "riplock . --no-deps --severity critical --json 2>/dev/null | node -e \"const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')); if(d.stats.critical>0) console.log('⚠️ RipLock: '+d.stats.critical+' critical findings')\""
      }]
    }]
  }
}
```

### Option 5: Claude Code skill (most powerful)

Create `~/.claude/skills/security-review.md` to get a `/security-review` slash command that combines RipLock's systematic scan with Claude's contextual review:

```markdown
---
name: security-review
description: Combined static + contextual security review
user-invocable: true
---

# Security Review

## Phase 1: RipLock Static Analysis

Run RipLock against the current project:

\`\`\`bash
npx riplock-cli . --no-deps --json
\`\`\`

Parse the JSON output. Summarize findings by severity with the top 5 most
important issues, their taint flow paths, and fix suggestions.

## Phase 2: Contextual Review

After RipLock completes, review the codebase for issues static analysis misses:

1. **Business Logic** — payment flows, authorization bypasses, workflow ordering
2. **Auth Architecture** — middleware ordering, inconsistent auth, privilege escalation
3. **Data Exposure** — over-fetched API responses, server data leaking to client
4. **Architectural Risks** — secrets management, missing rate limiting, error handling

Read the key files and report contextual issues with specific fix suggestions.
End with a prioritized action list.
```

Then run `/security-review` in any project. RipLock handles the O(n) file scanning, Claude handles the contextual judgment.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at medium+ severity |
| `1` | Findings at medium or higher severity |
| `2` | Tool error |

## Scoring

| Grade | Score | Meaning |
|---|---|---|
| A+ | 100 | No issues found |
| A | 90-99 | Minor issues only |
| B | 75-89 | Some issues to address |
| C | 60-74 | Significant issues |
| D | 40-59 | Serious problems |
| F | 0-39 | Critical vulnerabilities |

Findings with 4+ occurrences are automatically grouped with the top 3 examples shown. Each grouped finding includes a suppress hint.

## Limitations

RipLock is a first line of defense, not a guarantee. It catches known vulnerability patterns and common supply chain attack techniques, but:

- **It is not a substitute for professional security review.** Static analysis finds what it's been taught to look for. Business logic flaws, novel attack techniques, and subtle backdoors require human judgment.
- **A clean `scan-pkg` result does not mean a package is safe.** It means the package didn't match any of the 12 supply chain patterns RipLock checks. Sophisticated attackers can craft payloads that evade pattern matching.
- **Cross-file taint tracking has depth limits** — call chains beyond 3 import levels are not followed.
- **Typosquatting is not detected** — telling `lod-ash` from `lodash` requires registry metadata, not code analysis.
- **Runtime behavior is not analyzed** — memory leaks, race conditions, and timing attacks require dynamic testing.
- **Calibration is ongoing.** The check thresholds have been tuned against ~20 real-world projects but have not yet been battle-tested across a wide range of production codebases. If you hit false positives, [open an issue](https://github.com/justvibes99/riplock/issues) or suppress individual checks in `.riplock.json`.

Use RipLock alongside — not instead of — dependency auditing (`npm audit`, Dependabot/Renovate), lockfile enforcement, code review, and periodic professional penetration testing.

## License

MIT
