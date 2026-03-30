import { describe, it, expect } from 'vitest';
import { iacChecks } from '../../src/checks/iac/index.js';
import { testLine, testFileCheck } from '../helpers.js';
import type { LineCheck, FileEntry, Finding, ScanContext } from '../../src/checks/types.js';
import { defaultConfig } from '../../src/config/defaults.js';

// ---------------------------------------------------------------------------
// Helper: test a K8S line check with file content containing 'kind:'
// ---------------------------------------------------------------------------

function testK8sLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const fullContent = `kind: Deployment\n${line}`;
  const lines = fullContent.split('\n');

  const file: FileEntry = {
    absolutePath: '/test/deployment.yml',
    relativePath: 'deployment.yml',
    sizeBytes: fullContent.length,
    extension: 'yml',
    basename: 'deployment.yml',
    content: fullContent,
    lines,
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 2, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

// ---------------------------------------------------------------------------
// TF001 - S3 Bucket Public Access
// ---------------------------------------------------------------------------

describe('TF001 - S3 Bucket Public Access', () => {
  it('detects public-read ACL', () => {
    const finding = testLine(
      iacChecks,
      'TF001',
      'acl = "public-read"',
      'tf',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag private ACL', () => {
    const finding = testLine(
      iacChecks,
      'TF001',
      'acl = "private"',
      'tf',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF002 - Security Group Open to World
// ---------------------------------------------------------------------------

describe('TF002 - Security Group Open to World', () => {
  it('detects inbound 0.0.0.0/0', () => {
    const finding = testLine(
      iacChecks,
      'TF002',
      'cidr_blocks = ["0.0.0.0/0"]',
      'tf',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });

  it('skips when line contains egress', () => {
    const finding = testLine(
      iacChecks,
      'TF002',
      'cidr_blocks = ["0.0.0.0/0"] # egress rule',
      'tf',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF003 - RDS Publicly Accessible
// ---------------------------------------------------------------------------

describe('TF003 - RDS Publicly Accessible', () => {
  it('detects publicly_accessible = true', () => {
    const finding = testLine(
      iacChecks,
      'TF003',
      'publicly_accessible = true',
      'tf',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag publicly_accessible = false', () => {
    const finding = testLine(
      iacChecks,
      'TF003',
      'publicly_accessible = false',
      'tf',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF005 - IAM Wildcard Policy
// ---------------------------------------------------------------------------

describe('TF005 - IAM Wildcard Policy', () => {
  it('detects actions = ["*"]', () => {
    const finding = testLine(
      iacChecks,
      'TF005',
      'actions = ["*"]',
      'tf',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag specific actions', () => {
    const finding = testLine(
      iacChecks,
      'TF005',
      'actions = ["s3:GetObject"]',
      'tf',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF006 - Hardcoded Credentials in Terraform
// ---------------------------------------------------------------------------

describe('TF006 - Hardcoded Credentials in Terraform', () => {
  it('detects hardcoded password in Terraform', () => {
    const finding = testLine(
      iacChecks,
      'TF006',
      'password = "hardcoded123"',
      'tf',
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF006');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });

  it('skips when using a variable reference', () => {
    const finding = testLine(
      iacChecks,
      'TF006',
      'password = var.db_password',
      'tf',
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// K8S001 - Running as Root
// ---------------------------------------------------------------------------

describe('K8S001 - Running as Root', () => {
  it('detects runAsNonRoot: false in K8S manifest', () => {
    const finding = testK8sLine('K8S001', 'runAsNonRoot: false');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('K8S001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag runAsNonRoot: true', () => {
    const finding = testK8sLine('K8S001', 'runAsNonRoot: true');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// K8S002 - Privileged Container
// ---------------------------------------------------------------------------

describe('K8S002 - Privileged Container', () => {
  it('detects privileged: true in K8S manifest', () => {
    const finding = testK8sLine('K8S002', 'privileged: true');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('K8S002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag privileged: false', () => {
    const finding = testK8sLine('K8S002', 'privileged: false');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// K8S005 - hostNetwork Enabled
// ---------------------------------------------------------------------------

describe('K8S005 - hostNetwork Enabled', () => {
  it('detects hostNetwork: true in K8S manifest', () => {
    const finding = testK8sLine('K8S005', 'hostNetwork: true');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('K8S005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag hostNetwork: false', () => {
    const finding = testK8sLine('K8S005', 'hostNetwork: false');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// K8S006 - Using Latest Tag
// ---------------------------------------------------------------------------

describe('K8S006 - Using Latest Tag', () => {
  it('detects image: nginx:latest in K8S manifest', () => {
    const finding = testK8sLine('K8S006', 'image: nginx:latest');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('K8S006');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag pinned image version', () => {
    const finding = testK8sLine('K8S006', 'image: nginx:1.25');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Custom helpers for checks that validate file paths or basenames
// ---------------------------------------------------------------------------

function testNginxLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const file: FileEntry = {
    absolutePath: '/test/nginx.conf',
    relativePath: 'nginx.conf',
    sizeBytes: line.length,
    extension: 'conf',
    basename: 'nginx.conf',
    content: line,
    lines: [line],
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 1, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

function testConfLine(
  checkId: string,
  line: string,
  basename = 'nginx.conf',
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const ext = basename.split('.').pop() ?? 'conf';

  const file: FileEntry = {
    absolutePath: `/test/${basename}`,
    relativePath: basename,
    sizeBytes: line.length,
    extension: ext,
    basename,
    content: line,
    lines: [line],
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 1, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

function testAnsibleLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const fullContent = line;
  const file: FileEntry = {
    absolutePath: '/test/ansible/playbooks/main.yml',
    relativePath: 'ansible/playbooks/main.yml',
    sizeBytes: fullContent.length,
    extension: 'yml',
    basename: 'main.yml',
    content: fullContent,
    lines: fullContent.split('\n'),
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 1, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

function testServerlessLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const fullContent = `provider:\n  name: aws\n${line}`;
  const lines = fullContent.split('\n');

  const file: FileEntry = {
    absolutePath: '/test/serverless.yml',
    relativePath: 'serverless.yml',
    sizeBytes: fullContent.length,
    extension: 'yml',
    basename: 'serverless.yml',
    content: fullContent,
    lines,
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  const lineNumber = lines.indexOf(line) + 1;

  return check.analyze(
    { line, lineNumber, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

function testHelmLine(
  checkId: string,
  line: string,
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const file: FileEntry = {
    absolutePath: '/test/chart/values.yaml',
    relativePath: 'chart/values.yaml',
    sizeBytes: line.length,
    extension: 'yaml',
    basename: 'values.yaml',
    content: line,
    lines: [line],
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  return check.analyze(
    { line, lineNumber: 1, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

/**
 * Helper for CloudFormation checks: wraps a line in a file that looks like
 * a CloudFormation template (has AWSTemplateFormatVersion in content).
 */
function testCfLine(
  checkId: string,
  line: string,
  extraLines: string[] = [],
): Finding | null {
  const check = iacChecks.find((c) => c.id === checkId) as LineCheck;
  if (!check) throw new Error(`Check ${checkId} not found`);

  const allLines = ['AWSTemplateFormatVersion: "2010-09-09"', 'Resources:', ...extraLines, line];
  const fullContent = allLines.join('\n');

  const file: FileEntry = {
    absolutePath: '/test/template.yaml',
    relativePath: 'template.yaml',
    sizeBytes: fullContent.length,
    extension: 'yaml',
    basename: 'template.yaml',
    content: fullContent,
    lines: allLines,
  };

  check.pattern.lastIndex = 0;
  const match = check.pattern.exec(line);
  if (!match) return null;

  const lineNumber = allLines.indexOf(line) + 1;

  return check.analyze(
    { line, lineNumber, regexMatch: match, file },
    { config: defaultConfig() } as ScanContext,
  );
}

// ---------------------------------------------------------------------------
// CF001 - Security Group Open to World (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF001 - Security Group Open to World (CloudFormation)', () => {
  it('detects CidrIp: 0.0.0.0/0 in a CloudFormation template', () => {
    const finding = testCfLine('CF001', 'CidrIp: 0.0.0.0/0');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF001');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });

  it('skips when line contains egress', () => {
    const finding = testCfLine('CF001', 'CidrIp: 0.0.0.0/0 # egress');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CF002 - S3 Bucket Public Access (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF002 - S3 Bucket Public Access (CloudFormation)', () => {
  it('detects AccessControl: PublicRead', () => {
    const finding = testCfLine('CF002', 'AccessControl: PublicRead');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF002');
    expect(finding!.severity).toBe('critical');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// CF003 - RDS Publicly Accessible (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF003 - RDS Publicly Accessible (CloudFormation)', () => {
  it('detects PubliclyAccessible: true', () => {
    const finding = testCfLine('CF003', 'PubliclyAccessible: true');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// CF005 - IAM Wildcard Action (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF005 - IAM Wildcard Action (CloudFormation)', () => {
  it("detects Action: '*'", () => {
    const finding = testCfLine('CF005', "Action: '*'");
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// CF006 - Hardcoded Secrets in Parameters (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF006 - Hardcoded Secrets in Parameters (CloudFormation)', () => {
  it('detects hardcoded default near a password parameter', () => {
    const finding = testCfLine(
      'CF006',
      "Default: 'realSecretValue123456'",
      ['  DatabasePassword:'],
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF006');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// NGINX001 - Server Tokens Exposed
// ---------------------------------------------------------------------------

describe('NGINX001 - Server Tokens Exposed', () => {
  it('detects server_tokens on', () => {
    const finding = testNginxLine('NGINX001', 'server_tokens on;');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('NGINX001');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// NGINX003 - Autoindex Enabled
// ---------------------------------------------------------------------------

describe('NGINX003 - Autoindex Enabled', () => {
  it('detects autoindex on', () => {
    const finding = testNginxLine('NGINX003', 'autoindex on;');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('NGINX003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// NGINX005 - Permissive CORS
// ---------------------------------------------------------------------------

describe('NGINX005 - Permissive CORS', () => {
  it('detects add_header Access-Control-Allow-Origin *', () => {
    const finding = testNginxLine('NGINX005', 'add_header Access-Control-Allow-Origin *;');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('NGINX005');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// APACHE001 - Directory Listing Enabled
// ---------------------------------------------------------------------------

describe('APACHE001 - Directory Listing Enabled', () => {
  it('detects Options +Indexes', () => {
    const finding = testConfLine('APACHE001', 'Options +Indexes +FollowSymLinks', 'httpd.conf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('APACHE001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag Options -Indexes', () => {
    const finding = testConfLine('APACHE001', 'Options -Indexes +FollowSymLinks', 'httpd.conf');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// APACHE002 - Server Signature Exposed
// ---------------------------------------------------------------------------

describe('APACHE002 - Server Signature Exposed', () => {
  it('detects ServerSignature On', () => {
    const finding = testConfLine('APACHE002', 'ServerSignature On', 'httpd.conf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('APACHE002');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// ANSIBLE001 - Hardcoded Password in Ansible
// ---------------------------------------------------------------------------

describe('ANSIBLE001 - Hardcoded Password in Ansible', () => {
  it('detects hardcoded password in ansible playbook', () => {
    const finding = testAnsibleLine('ANSIBLE001', 'password: "hardcoded123secret"');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('ANSIBLE001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('skips Jinja2 vault variable reference', () => {
    const finding = testAnsibleLine('ANSIBLE001', 'password: "{{ vault_password }}"');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ANSIBLE003 - Certificate Validation Disabled
// ---------------------------------------------------------------------------

describe('ANSIBLE003 - Certificate Validation Disabled', () => {
  it('detects validate_certs: no in ansible path', () => {
    const finding = testAnsibleLine('ANSIBLE003', 'validate_certs: no');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('ANSIBLE003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// SLS001 - Serverless Wildcard IAM Permissions
// ---------------------------------------------------------------------------

describe('SLS001 - Serverless Wildcard IAM Permissions', () => {
  it("detects Action: '*' in serverless file", () => {
    const finding = testServerlessLine('SLS001', "Action: '*'");
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SLS001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });
});

// ---------------------------------------------------------------------------
// HELM001 - Default Secret in Helm values.yaml
// ---------------------------------------------------------------------------

describe('HELM001 - Default Secret in Helm values.yaml', () => {
  it('detects real secret value in values.yaml', () => {
    const finding = testHelmLine('HELM001', 'password: realSecretValue');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('HELM001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('skips changeme placeholder values', () => {
    const finding = testHelmLine('HELM001', 'password: changeme');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// K8S003 - No Resource Limits (FileCheck)
// ---------------------------------------------------------------------------

describe('K8S003 - No Resource Limits', () => {
  it('flags deployment without resource limits', async () => {
    const content = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0.0`;
    const findings = await testFileCheck(iacChecks, 'K8S003', content, {
      relativePath: 'deployment.yml',
      extension: 'yml',
      basename: 'deployment.yml',
    });
    expect(findings.length).toBe(1);
    expect(findings[0].checkId).toBe('K8S003');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].category).toBe('iac');
  });

  it('does not flag deployment with resource limits', async () => {
    const content = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0.0
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"`;
    const findings = await testFileCheck(iacChecks, 'K8S003', content, {
      relativePath: 'deployment.yml',
      extension: 'yml',
      basename: 'deployment.yml',
    });
    expect(findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// K8S004 - Secrets in Plain YAML
// ---------------------------------------------------------------------------

describe('K8S004 - Secrets in Plain YAML', () => {
  it('detects stringData in a Secret manifest', () => {
    const check = iacChecks.find((c) => c.id === 'K8S004') as LineCheck;

    const fullContent = `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-creds\nstringData:\n  password: "supersecret"`;
    const lines = fullContent.split('\n');
    const targetLine = 'stringData:';

    const file: FileEntry = {
      absolutePath: '/test/secret.yml',
      relativePath: 'secret.yml',
      sizeBytes: fullContent.length,
      extension: 'yml',
      basename: 'secret.yml',
      content: fullContent,
      lines,
    };

    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(targetLine);
    expect(match).not.toBeNull();

    const finding = check.analyze(
      { line: targetLine, lineNumber: 5, regexMatch: match!, file },
      { config: defaultConfig() } as ScanContext,
    );
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('K8S004');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag stringData when kind is not Secret', () => {
    const check = iacChecks.find((c) => c.id === 'K8S004') as LineCheck;

    const fullContent = `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config\nstringData:\n  key: value`;
    const lines = fullContent.split('\n');
    const targetLine = 'stringData:';

    const file: FileEntry = {
      absolutePath: '/test/configmap.yml',
      relativePath: 'configmap.yml',
      sizeBytes: fullContent.length,
      extension: 'yml',
      basename: 'configmap.yml',
      content: fullContent,
      lines,
    };

    check.pattern.lastIndex = 0;
    const match = check.pattern.exec(targetLine);
    expect(match).not.toBeNull();

    const finding = check.analyze(
      { line: targetLine, lineNumber: 5, regexMatch: match!, file },
      { config: defaultConfig() } as ScanContext,
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA001 - Hardcoded Password in Config
// ---------------------------------------------------------------------------

describe('INFRA001 - Hardcoded Password in Config', () => {
  it('detects hardcoded password in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA001', 'password: "hardcoded123secret"', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA001');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('skips environment variable reference', () => {
    const finding = testLine(iacChecks, 'INFRA001', 'password: "${DB_PASSWORD}"', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA003 - TLS/SSL Disabled
// ---------------------------------------------------------------------------

describe('INFRA003 - TLS/SSL Disabled', () => {
  it('detects verify_ssl set to false', () => {
    const finding = testLine(iacChecks, 'INFRA003', 'verify_ssl: false', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag verify_ssl set to true', () => {
    const finding = testLine(iacChecks, 'INFRA003', 'verify_ssl: true', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA005 - Wildcard Bind Address
// ---------------------------------------------------------------------------

describe('INFRA005 - Wildcard Bind Address', () => {
  it('detects bind to 0.0.0.0', () => {
    const finding = testLine(iacChecks, 'INFRA005', 'bind: 0.0.0.0', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA005');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag bind to 127.0.0.1', () => {
    const finding = testLine(iacChecks, 'INFRA005', 'bind: 127.0.0.1', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA008 - CORS Wildcard in Config
// ---------------------------------------------------------------------------

describe('INFRA008 - CORS Wildcard in Config', () => {
  it('detects CORS wildcard', () => {
    const finding = testLine(iacChecks, 'INFRA008', 'cors: "*"', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA008');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
    expect(finding!.message).toContain('CORS');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag specific origin', () => {
    const finding = testLine(iacChecks, 'INFRA008', 'cors: "https://myapp.com"', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA010 - Plaintext Connection String
// ---------------------------------------------------------------------------

describe('INFRA010 - Plaintext Connection String', () => {
  it('detects plaintext connection string with credentials', () => {
    const finding = testLine(iacChecks, 'INFRA010', 'database_url: "postgres://user:pass@host/db"', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA010');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
    expect(finding!.message).toContain('connection string');
    expect(finding!.fix).toBeTruthy();
  });

  it('skips environment variable reference', () => {
    const finding = testLine(iacChecks, 'INFRA010', 'database_url: "${DATABASE_URL}"', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA009 - Admin/Root User Enabled
// ---------------------------------------------------------------------------

describe('INFRA009 - Admin/Root User Enabled', () => {
  it('detects admin_enabled: true in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA009', 'admin_enabled: true', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA009');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
    expect(finding!.message).toContain('Admin');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag admin_enabled: false', () => {
    const finding = testLine(iacChecks, 'INFRA009', 'admin_enabled: false', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA011 - SSH Keys / Private Key Paths
// ---------------------------------------------------------------------------

describe('INFRA011 - SSH Keys / Private Key Paths', () => {
  it('detects ssh_key with a file path in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA011', 'ssh_key: /path/to/key', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA011');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
    expect(finding!.message).toContain('key');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag ssh_key without a file path', () => {
    const finding = testLine(iacChecks, 'INFRA011', 'ssh_key: vault:secret/key', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA012 - Rate Limit Disabled
// ---------------------------------------------------------------------------

describe('INFRA012 - Rate Limit Disabled', () => {
  it('detects rate_limit set to 0 in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA012', 'rate_limit: 0', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA012');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
    expect(finding!.message).toContain('Rate limiting');
    expect(finding!.fix).toBeTruthy();
  });

  it('does not flag rate_limit set to a positive number', () => {
    const finding = testLine(iacChecks, 'INFRA012', 'rate_limit: 100', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ANSIBLE002 - Ansible Privilege Escalation
// ---------------------------------------------------------------------------

describe('ANSIBLE002 - Ansible Privilege Escalation', () => {
  it('detects become: yes in an ansible playbook', () => {
    const finding = testAnsibleLine('ANSIBLE002', 'become: yes');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('ANSIBLE002');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('detects become: true in an ansible playbook', () => {
    const finding = testAnsibleLine('ANSIBLE002', 'become: true');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('ANSIBLE002');
  });

  it('does not flag become: yes outside of ansible paths', () => {
    const finding = testLine(iacChecks, 'ANSIBLE002', 'become: yes', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// APACHE003 - CGI Execution Enabled
// ---------------------------------------------------------------------------

describe('APACHE003 - CGI Execution Enabled', () => {
  it('detects Options ExecCGI in Apache config', () => {
    const finding = testConfLine('APACHE003', 'Options +ExecCGI', 'httpd.conf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('APACHE003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag a line without ExecCGI', () => {
    const finding = testConfLine('APACHE003', 'Options +FollowSymLinks', 'httpd.conf');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// CF004 - No Encryption on EBS/RDS (CloudFormation)
// ---------------------------------------------------------------------------

describe('CF004 - No Encryption on EBS/RDS (CloudFormation)', () => {
  it('detects StorageEncrypted: false in CloudFormation template', () => {
    const finding = testCfLine('CF004', 'StorageEncrypted: false');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF004');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('detects Encrypted: false in CloudFormation template', () => {
    const finding = testCfLine('CF004', 'Encrypted: false');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('CF004');
  });

  it('does not flag Encrypted: true', () => {
    const finding = testCfLine('CF004', 'Encrypted: true');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF004 - No Encryption at Rest (Terraform)
// ---------------------------------------------------------------------------

describe('TF004 - No Encryption at Rest', () => {
  it('detects encrypted = false in Terraform', () => {
    const finding = testLine(iacChecks, 'TF004', 'encrypted = false', 'tf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF004');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag encrypted = true', () => {
    const finding = testLine(iacChecks, 'TF004', 'encrypted = true', 'tf');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TF007 - Sensitive Output Not Marked
// ---------------------------------------------------------------------------

describe('TF007 - Sensitive Output Not Marked', () => {
  it('detects output with secret in name', () => {
    const finding = testLine(iacChecks, 'TF007', 'output "db_secret_key" {', 'tf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF007');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('detects output with password in name', () => {
    const finding = testLine(iacChecks, 'TF007', 'output "db_password" {', 'tf');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('TF007');
  });

  it('does not flag output without sensitive keyword', () => {
    const finding = testLine(iacChecks, 'TF007', 'output "instance_id" {', 'tf');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// NGINX002 - Missing HTTPS Redirect
// ---------------------------------------------------------------------------

describe('NGINX002 - Missing HTTPS Redirect', () => {
  it('detects listen 80 without HTTPS redirect', () => {
    const finding = testNginxLine('NGINX002', 'listen 80;');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('NGINX002');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag listen 80 when file has HTTPS redirect', () => {
    const check = iacChecks.find((c) => c.id === 'NGINX002') as LineCheck;
    const fullContent = 'listen 80;\nreturn 301 https://$host$request_uri;';
    const lines = fullContent.split('\n');
    const file: FileEntry = {
      absolutePath: '/test/nginx.conf',
      relativePath: 'nginx.conf',
      sizeBytes: fullContent.length,
      extension: 'conf',
      basename: 'nginx.conf',
      content: fullContent,
      lines,
    };

    check.pattern.lastIndex = 0;
    const match = check.pattern.exec('listen 80;');
    expect(match).not.toBeNull();

    const finding = check.analyze(
      { line: 'listen 80;', lineNumber: 1, regexMatch: match!, file },
      { config: defaultConfig() } as ScanContext,
    );
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// NGINX004 - Missing Security Headers (FileCheck)
// ---------------------------------------------------------------------------

describe('NGINX004 - Missing Security Headers', () => {
  it('flags nginx config missing security headers', async () => {
    const content = `server {
    listen 443 ssl;
    server_name example.com;
}`;
    const findings = await testFileCheck(iacChecks, 'NGINX004', content, {
      relativePath: 'nginx.conf',
      extension: 'conf',
      basename: 'nginx.conf',
    });
    expect(findings.length).toBe(1);
    expect(findings[0].checkId).toBe('NGINX004');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].category).toBe('iac');
  });

  it('does not flag nginx config with security headers', async () => {
    const content = `server {
    listen 443 ssl;
    server_name example.com;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
}`;
    const findings = await testFileCheck(iacChecks, 'NGINX004', content, {
      relativePath: 'nginx.conf',
      extension: 'conf',
      basename: 'nginx.conf',
    });
    expect(findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// HELM002 - Helm Template Missing Security Context (FileCheck)
// ---------------------------------------------------------------------------

describe('HELM002 - Helm Template Missing Security Context', () => {
  it('flags Helm deployment template without securityContext', async () => {
    const content = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0.0`;
    const findings = await testFileCheck(iacChecks, 'HELM002', content, {
      relativePath: 'chart/templates/deployment.yml',
      extension: 'yml',
      basename: 'deployment.yml',
    });
    expect(findings.length).toBe(1);
    expect(findings[0].checkId).toBe('HELM002');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].category).toBe('iac');
  });

  it('does not flag Helm template with securityContext', async () => {
    const content = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: myapp:1.0.0`;
    const findings = await testFileCheck(iacChecks, 'HELM002', content, {
      relativePath: 'chart/templates/deployment.yml',
      extension: 'yml',
      basename: 'deployment.yml',
    });
    expect(findings.length).toBe(0);
  });

  it('does not flag files outside templates/ directory', async () => {
    const content = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0.0`;
    const findings = await testFileCheck(iacChecks, 'HELM002', content, {
      relativePath: 'chart/deployment.yml',
      extension: 'yml',
      basename: 'deployment.yml',
    });
    expect(findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// SLS002 - Serverless Public API Endpoint
// ---------------------------------------------------------------------------

describe('SLS002 - Serverless Public API Endpoint', () => {
  it('detects private: false in serverless file', () => {
    const finding = testServerlessLine('SLS002', 'private: false');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SLS002');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag private: true in serverless file', () => {
    const finding = testServerlessLine('SLS002', 'private: true');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SLS003 - Serverless Hardcoded Secret
// ---------------------------------------------------------------------------

describe('SLS003 - Serverless Hardcoded Secret', () => {
  it('detects hardcoded secret in serverless env vars', () => {
    const finding = testServerlessLine('SLS003', 'SECRET_KEY: "abcdef1234567890"');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('SLS003');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('skips SSM variable reference', () => {
    const finding = testServerlessLine('SLS003', 'SECRET_KEY: "${ssm:/myapp/secret}"');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA002 - Hardcoded API Key/Token in Config
// ---------------------------------------------------------------------------

describe('INFRA002 - Hardcoded API Key/Token in Config', () => {
  it('detects hardcoded API token in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA002', 'api_token: "abc123longkeyvalue1234567890"', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA002');
    expect(finding!.severity).toBe('high');
    expect(finding!.category).toBe('iac');
  });

  it('skips environment variable reference', () => {
    const finding = testLine(iacChecks, 'INFRA002', 'api_token: "${API_TOKEN}"', 'yml');
    expect(finding).toBeNull();
  });

  it('skips placeholder values', () => {
    const finding = testLine(iacChecks, 'INFRA002', 'api_key: "your_api_key_changeme_here"', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA004 - Insecure Protocol in Config
// ---------------------------------------------------------------------------

describe('INFRA004 - Insecure Protocol in Config', () => {
  it('detects HTTP URL to external host in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA004', 'url: "http://external.example.com/api"', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA004');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('does not flag http://localhost', () => {
    const finding = testLine(iacChecks, 'INFRA004', 'url: "http://localhost:3000"', 'yml');
    expect(finding).toBeNull();
  });

  it('does not flag HTTPS URLs', () => {
    const finding = testLine(iacChecks, 'INFRA004', 'url: "https://external.example.com"', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA006 - Debug/Verbose Mode in Config
// ---------------------------------------------------------------------------

describe('INFRA006 - Debug/Verbose Mode in Config', () => {
  it('detects debug: true in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA006', 'debug: true', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA006');
    expect(finding!.severity).toBe('medium');
    expect(finding!.category).toBe('iac');
  });

  it('detects log_level: debug in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA006', 'log_level: debug', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA006');
  });

  it('does not flag debug: false', () => {
    const finding = testLine(iacChecks, 'INFRA006', 'debug: false', 'yml');
    expect(finding).toBeNull();
  });

  it('skips when line references production context', () => {
    const finding = testLine(iacChecks, 'INFRA006', 'debug: true # production override', 'yml');
    expect(finding).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// INFRA007 - Default/Weak Port Exposure
// ---------------------------------------------------------------------------

describe('INFRA007 - Default/Weak Port Exposure', () => {
  it('detects MySQL default port 3306 in YAML config', () => {
    const finding = testLine(iacChecks, 'INFRA007', 'port: 3306', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA007');
    expect(finding!.severity).toBe('low');
    expect(finding!.category).toBe('iac');
  });

  it('detects Redis default port 6379', () => {
    const finding = testLine(iacChecks, 'INFRA007', 'port: 6379', 'yml');
    expect(finding).not.toBeNull();
    expect(finding!.checkId).toBe('INFRA007');
  });

  it('does not flag non-risky port numbers', () => {
    const finding = testLine(iacChecks, 'INFRA007', 'port: 8080', 'yml');
    expect(finding).toBeNull();
  });
});
