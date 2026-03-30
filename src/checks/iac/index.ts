import type {
  CheckDefinition,
  FileCheck,
  FileEntry,
  Finding,
  ScanContext,
} from '../types.js';
import { extractSnippet } from '../../utils/snippet.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Infrastructure-as-Code security checks
// Terraform (.tf, .hcl), Kubernetes (.yml, .yaml), CloudFormation (.yml, .yaml)
// ---------------------------------------------------------------------------

export const iacChecks: CheckDefinition[] = [
  // =========================================================================
  // Terraform
  // =========================================================================

  // TF001 - S3 Bucket Public Access
  createLineCheck({
    id: 'TF001',
    name: 'S3 Bucket Public Access',
    category: 'iac',
    severity: 'critical',
    pattern: /acl\s*=\s*['"]public-read(?:-write)?['"]/g,
    appliesTo: ['tf', 'hcl'],
    message:
      'S3 bucket is publicly accessible. Anyone on the internet can read (or write) your data.',
    fix: 'Set the ACL to "private" and use bucket policies with specific principal access.',
    fixCode: `# Dangerous:
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}

# Safe:
resource "aws_s3_bucket" "data" {
  acl = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
  }),

  // TF002 - Security Group Open to World
  createLineCheck({
    id: 'TF002',
    name: 'Security Group Open to World',
    category: 'iac',
    severity: 'critical',
    pattern: /cidr_blocks\s*=\s*\[['"]0\.0\.0\.0\/0['"]\]/g,
    appliesTo: ['tf', 'hcl'],
    validate(_match, line, file) {
      const lower = line.toLowerCase();
      // Outbound 0.0.0.0/0 is common and acceptable
      if (lower.includes('outbound') || lower.includes('egress')) return false;

      // Check surrounding context in the file for egress block
      const lines = file.lines ?? [];
      const idx = lines.indexOf(line);
      if (idx >= 0) {
        // Look back up to 10 lines for egress/outbound indicators
        for (let i = Math.max(0, idx - 10); i < idx; i++) {
          const ctx = lines[i].toLowerCase();
          if (ctx.includes('egress') || ctx.includes('outbound') || ctx.includes('type') && ctx.includes('"egress"')) {
            return false;
          }
        }
      }
      return true;
    },
    message:
      'Security group allows inbound traffic from any IP address. Restrict to known IP ranges.',
    fix: 'Replace 0.0.0.0/0 with specific CIDR ranges for the services that need access.',
    fixCode: `# Dangerous:
ingress {
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
  to_port     = 22
}

# Safe - restrict to your IP or VPN range:
ingress {
  cidr_blocks = ["10.0.0.0/8"]
  from_port   = 22
  to_port     = 22
}`,
  }),

  // TF003 - RDS Publicly Accessible
  createLineCheck({
    id: 'TF003',
    name: 'RDS Publicly Accessible',
    category: 'iac',
    severity: 'high',
    pattern: /publicly_accessible\s*=\s*true/g,
    appliesTo: ['tf', 'hcl'],
    message:
      'Database is publicly accessible from the internet. Keep databases in private subnets.',
    fix: 'Set publicly_accessible = false and access the database through a VPN or bastion host.',
    fixCode: `# Dangerous:
resource "aws_db_instance" "main" {
  publicly_accessible = true
}

# Safe:
resource "aws_db_instance" "main" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}`,
  }),

  // TF004 - No Encryption at Rest
  createLineCheck({
    id: 'TF004',
    name: 'No Encryption at Rest',
    category: 'iac',
    severity: 'high',
    pattern: /encrypted\s*=\s*false/g,
    appliesTo: ['tf', 'hcl'],
    message:
      'Encryption at rest is disabled. Enable it to protect data if storage is compromised.',
    fix: 'Set encrypted = true and specify a KMS key for encryption.',
    fixCode: `# Dangerous:
resource "aws_ebs_volume" "data" {
  encrypted = false
}

# Safe:
resource "aws_ebs_volume" "data" {
  encrypted  = true
  kms_key_id = aws_kms_key.ebs.arn
}`,
  }),

  // TF005 - IAM Wildcard Policy
  createLineCheck({
    id: 'TF005',
    name: 'IAM Wildcard Policy',
    category: 'iac',
    severity: 'high',
    pattern: /["']Effect["']\s*:\s*["']Allow["'][\s\S]*?["']Action["']\s*:\s*["']\*["']|actions\s*=\s*\[['"]?\*['"]?\]/g,
    appliesTo: ['tf', 'hcl'],
    message:
      'IAM policy grants wildcard permissions. Follow the principle of least privilege.',
    fix: 'Replace the wildcard with only the specific actions needed by the resource.',
    fixCode: `# Dangerous:
data "aws_iam_policy_document" "admin" {
  statement {
    effect  = "Allow"
    actions = ["*"]
    resources = ["*"]
  }
}

# Safe - least privilege:
data "aws_iam_policy_document" "app" {
  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject"]
    resources = ["\${aws_s3_bucket.app.arn}/*"]
  }
}`,
  }),

  // TF006 - Hardcoded Credentials in Terraform
  createLineCheck({
    id: 'TF006',
    name: 'Hardcoded Credentials in Terraform',
    category: 'iac',
    severity: 'critical',
    pattern: /(?:access_key|secret_key|password|api_key)\s*=\s*['"][^'"]{8,}['"]/gi,
    appliesTo: ['tf', 'hcl'],
    validate(_match, line) {
      const lower = line.toLowerCase();
      // Skip references to variables, locals, data sources, and modules
      if (lower.includes('var.')) return false;
      if (lower.includes('local.')) return false;
      if (lower.includes('data.')) return false;
      if (lower.includes('module.')) return false;
      return true;
    },
    message:
      'Credentials hardcoded in Terraform. Use variables or a secrets manager.',
    fix: 'Move credentials to Terraform variables, environment variables, or a secrets manager like Vault.',
    fixCode: `# Dangerous:
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Safe - use variables:
variable "aws_access_key" {
  type      = string
  sensitive = true
}

provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# Best - use IAM roles or environment variables instead of keys`,
  }),

  // TF007 - Sensitive Output Not Marked
  createLineCheck({
    id: 'TF007',
    name: 'Sensitive Output Not Marked',
    category: 'iac',
    severity: 'medium',
    pattern: /output\s+['"][^'"]*(?:secret|password|key|token)[^'"]*['"]/gi,
    appliesTo: ['tf', 'hcl'],
    message:
      'Terraform output may contain sensitive data. Mark it with sensitive = true to prevent it from showing in logs.',
    fix: 'Add sensitive = true to outputs that expose secrets, keys, passwords, or tokens.',
    fixCode: `# Dangerous - value shows in terraform output and logs:
output "db_password" {
  value = aws_db_instance.main.password
}

# Safe:
output "db_password" {
  value     = aws_db_instance.main.password
  sensitive = true
}`,
  }),

  // =========================================================================
  // Kubernetes
  // =========================================================================

  // K8S001 - Running as Root
  createLineCheck({
    id: 'K8S001',
    name: 'Running as Root',
    category: 'iac',
    severity: 'high',
    pattern: /runAsNonRoot:\s*false|runAsUser:\s*0\b/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /kind:/i.test(content);
    },
    message:
      'Container runs as root. A compromise gives the attacker full container access.',
    fix: 'Set runAsNonRoot: true and runAsUser to a non-zero UID in the securityContext.',
    fixCode: `# Dangerous:
securityContext:
  runAsNonRoot: false
  runAsUser: 0

# Safe:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000`,
  }),

  // K8S002 - Privileged Container
  createLineCheck({
    id: 'K8S002',
    name: 'Privileged Container',
    category: 'iac',
    severity: 'critical',
    pattern: /privileged:\s*true/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /kind:/i.test(content);
    },
    message:
      'Container runs in privileged mode with full host access. This is almost never necessary.',
    fix: 'Remove privileged: true. If the container needs specific capabilities, grant only those with securityContext.capabilities.add.',
    fixCode: `# Dangerous:
securityContext:
  privileged: true

# Safe - grant only needed capabilities:
securityContext:
  privileged: false
  capabilities:
    add: ["NET_BIND_SERVICE"]
    drop: ["ALL"]`,
  }),

  // K8S003 - No Resource Limits (FileCheck)
  {
    level: 'file',
    id: 'K8S003',
    name: 'No Resource Limits',
    description:
      'Kubernetes manifest defines containers without resource limits.',
    category: 'iac',
    defaultSeverity: 'medium',
    appliesTo: ['yml', 'yaml'],
    fastFilter: 'kind:',

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Only flag Kubernetes manifests
      if (!/kind:/i.test(content)) return [];

      // Must have containers defined
      if (!/containers:/i.test(content)) return [];

      // Check if limits are defined
      if (/limits:/i.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with containers:
      let containerLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/containers:/i.test(lines[i])) {
          containerLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        containerLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'K8S003',
          title: 'No Resource Limits',
          message:
            'Container has no resource limits. It can consume all node resources and crash other pods.',
          severity: ctx.config.severityOverrides.get('K8S003') ?? 'medium',
          category: 'iac',
          location: {
            filePath: file.relativePath,
            startLine: containerLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Add resources.limits to every container to cap CPU and memory usage.',
          fixCode: `# Add resource limits to each container:
containers:
  - name: app
    image: myapp:1.0.0
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "500m"
        memory: "512Mi"`,
        },
      ];
    },
  } satisfies FileCheck,

  // K8S004 - Secrets in Plain YAML
  createLineCheck({
    id: 'K8S004',
    name: 'Secrets in Plain YAML',
    category: 'iac',
    severity: 'high',
    pattern: /stringData:/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /kind:\s*Secret/i.test(content);
    },
    message:
      'Kubernetes Secret defined with plaintext stringData. Use sealed-secrets or external secret managers in production.',
    fix: 'Use sealed-secrets, External Secrets Operator, or Vault to inject secrets instead of committing them in YAML.',
    fixCode: `# Dangerous - plaintext secret in YAML:
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
stringData:
  password: "super-secret-password"

# Safe - use SealedSecret (Bitnami):
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
spec:
  encryptedData:
    password: "AgBy3i4OJSWK+PiTySYZZA9rO..."

# Safe - use External Secrets Operator:
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: db-credentials
  data:
    - secretKey: password
      remoteRef:
        key: secret/db
        property: password`,
  }),

  // K8S005 - hostNetwork Enabled
  createLineCheck({
    id: 'K8S005',
    name: 'hostNetwork Enabled',
    category: 'iac',
    severity: 'high',
    pattern: /hostNetwork:\s*true/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /kind:/i.test(content);
    },
    message:
      'Container shares the host network namespace. It can intercept traffic from other containers.',
    fix: 'Remove hostNetwork: true. Use Kubernetes Services and NetworkPolicies for inter-pod communication.',
    fixCode: `# Dangerous:
spec:
  hostNetwork: true

# Safe - remove hostNetwork and use a Service:
spec:
  hostNetwork: false  # or simply omit it
  containers:
    - name: app
      ports:
        - containerPort: 8080`,
  }),

  // K8S006 - Using Latest Tag
  createLineCheck({
    id: 'K8S006',
    name: 'Using Latest Tag',
    category: 'iac',
    severity: 'medium',
    pattern: /image:\s*\S+:latest\b/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /kind:/i.test(content);
    },
    message:
      'Container image uses :latest tag. Pin a specific version for reproducibility and security.',
    fix: 'Replace :latest with a specific image tag or digest.',
    fixCode: `# Dangerous - unpredictable deploys:
containers:
  - name: app
    image: nginx:latest

# Safe - pinned version:
containers:
  - name: app
    image: nginx:1.25.3

# Best - pinned by digest:
containers:
  - name: app
    image: nginx@sha256:abc123...`,
  }),

  // =========================================================================
  // Ansible
  // =========================================================================

  // ANSIBLE001 - Hardcoded Password
  createLineCheck({
    id: 'ANSIBLE001',
    name: 'Hardcoded Password in Ansible',
    category: 'iac',
    severity: 'high',
    pattern: /(?:password|secret|token|api_key)\s*:\s*['"][^'"]{8,}['"]/gi,
    appliesTo: ['yml', 'yaml'],
    validate(_match, line, file) {
      const path = file.relativePath.toLowerCase();
      const isAnsible =
        path.includes('ansible') ||
        path.includes('playbook') ||
        path.includes('roles/') ||
        path.includes('tasks/');
      if (!isAnsible) return false;

      // Skip Jinja2 variable references and Ansible Vault values
      const value = line.match(/:\s*['"]([^'"]+)['"]/)?.[1] ?? '';
      if (value.startsWith('{{') || value.toLowerCase().startsWith('vault')) return false;

      return true;
    },
    message:
      'Hardcoded secret in Ansible playbook. Use Ansible Vault or environment variables.',
    fix: 'Encrypt secrets with Ansible Vault or reference them from environment variables.',
    fixCode: `# Dangerous:
- name: Configure database
  mysql_user:
    password: "SuperSecret123"

# Safe - use Ansible Vault:
- name: Configure database
  mysql_user:
    password: "{{ vault_db_password }}"

# Safe - use environment variable:
- name: Configure database
  mysql_user:
    password: "{{ lookup('env', 'DB_PASSWORD') }}"`,
  }),

  // ANSIBLE002 - No Become Password
  createLineCheck({
    id: 'ANSIBLE002',
    name: 'Ansible Privilege Escalation',
    category: 'iac',
    severity: 'medium',
    pattern: /become:\s*(?:yes|true)/gi,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const path = file.relativePath.toLowerCase();
      return (
        path.includes('ansible') ||
        path.includes('playbook') ||
        path.includes('roles/') ||
        path.includes('tasks/')
      );
    },
    message:
      'Ansible escalates privileges with \'become\'. Ensure become_password is not hardcoded.',
    fix: 'Use --ask-become-pass at runtime or store the become password in Ansible Vault.',
    fixCode: `# Flagged:
- hosts: webservers
  become: yes
  tasks:
    - name: Install nginx
      apt: name=nginx

# Safe - prompt at runtime:
# ansible-playbook site.yml --ask-become-pass

# Safe - vault-encrypted variable:
- hosts: webservers
  become: yes
  vars:
    ansible_become_password: "{{ vault_become_pass }}"`,
  }),

  // ANSIBLE003 - Certificate Validation Disabled
  createLineCheck({
    id: 'ANSIBLE003',
    name: 'Ansible Certificate Validation Disabled',
    category: 'iac',
    severity: 'high',
    pattern: /validate_certs\s*:\s*(?:no|false|False)/gi,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const path = file.relativePath.toLowerCase();
      return (
        path.includes('ansible') ||
        path.includes('playbook') ||
        path.includes('roles/') ||
        path.includes('tasks/')
      );
    },
    message:
      'Certificate validation disabled in Ansible. This allows man-in-the-middle attacks.',
    fix: 'Remove validate_certs: no and ensure proper CA certificates are installed on managed hosts.',
    fixCode: `# Dangerous:
- name: Download package
  get_url:
    url: https://example.com/package.tar.gz
    validate_certs: no

# Safe - enable certificate validation:
- name: Download package
  get_url:
    url: https://example.com/package.tar.gz
    validate_certs: yes`,
  }),

  // =========================================================================
  // Serverless Framework
  // =========================================================================

  // SLS001 - Overly Permissive IAM
  createLineCheck({
    id: 'SLS001',
    name: 'Serverless Wildcard IAM Permissions',
    category: 'iac',
    severity: 'high',
    pattern: /Action:\s*['"]?\*['"]?/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return (
        file.relativePath.toLowerCase().includes('serverless') ||
        (/provider\s*:/i.test(content) && /aws/i.test(content))
      );
    },
    message:
      'Serverless function has wildcard IAM permissions. Grant only the permissions the function needs.',
    fix: 'Replace the wildcard Action with specific service actions following least privilege.',
    fixCode: `# Dangerous:
provider:
  iam:
    role:
      statements:
        - Effect: Allow
          Action: '*'
          Resource: '*'

# Safe - least privilege:
provider:
  iam:
    role:
      statements:
        - Effect: Allow
          Action:
            - dynamodb:GetItem
            - dynamodb:PutItem
          Resource: !GetAtt MyTable.Arn`,
  }),

  // SLS002 - No API Key Required
  createLineCheck({
    id: 'SLS002',
    name: 'Serverless Public API Endpoint',
    category: 'iac',
    severity: 'medium',
    pattern: /private:\s*false/g,
    appliesTo: ['yml', 'yaml'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return (
        file.relativePath.toLowerCase().includes('serverless') ||
        (/provider\s*:/i.test(content) && /aws/i.test(content))
      );
    },
    message:
      'Serverless API endpoint is public without authentication.',
    fix: 'Set private: true and configure an API key, or add an authorizer to the endpoint.',
    fixCode: `# Flagged:
functions:
  hello:
    handler: handler.hello
    events:
      - http:
          path: /hello
          method: get
          private: false

# Safe - require API key:
functions:
  hello:
    handler: handler.hello
    events:
      - http:
          path: /hello
          method: get
          private: true

# Safe - use authorizer:
functions:
  hello:
    handler: handler.hello
    events:
      - http:
          path: /hello
          method: get
          authorizer: myAuthorizer`,
  }),

  // SLS003 - Secrets in Environment
  createLineCheck({
    id: 'SLS003',
    name: 'Serverless Hardcoded Secret',
    category: 'iac',
    severity: 'high',
    pattern: /(?:SECRET|PASSWORD|TOKEN|KEY)\w*\s*:\s*['"][^'"]{8,}['"]/gi,
    appliesTo: ['yml', 'yaml'],
    validate(_match, line, file) {
      const content = file.content ?? '';
      const isServerless =
        file.relativePath.toLowerCase().includes('serverless') ||
        (/provider\s*:/i.test(content) && /aws/i.test(content));
      if (!isServerless) return false;

      // Skip variable references (${ssm:...}, ${env:...}, etc.)
      const value = line.match(/:\s*['"]([^'"]+)['"]/)?.[1] ?? '';
      if (value.startsWith('${')) return false;

      return true;
    },
    message:
      'Secret hardcoded in serverless environment variables. Use SSM Parameter Store or Secrets Manager.',
    fix: 'Reference secrets from SSM Parameter Store, Secrets Manager, or environment variables.',
    fixCode: `# Dangerous:
provider:
  environment:
    DB_PASSWORD: "SuperSecret123"

# Safe - use SSM Parameter Store:
provider:
  environment:
    DB_PASSWORD: \${ssm:/myapp/db-password}

# Safe - use Secrets Manager:
provider:
  environment:
    DB_PASSWORD: \${ssm:/aws/reference/secretsmanager/myapp/db-password}`,
  }),

  // =========================================================================
  // Helm Charts
  // =========================================================================

  // HELM001 - Default Secrets in values.yaml
  createLineCheck({
    id: 'HELM001',
    name: 'Default Secret in Helm values.yaml',
    category: 'iac',
    severity: 'high',
    pattern: /(?:password|secret|token|apiKey)\s*:\s*['"]?[^'"{\s]{8,}['"]?/gi,
    appliesTo: ['yml', 'yaml'],
    validate(_match, line, file) {
      const basename = file.basename.toLowerCase();
      if (basename !== 'values.yaml' && basename !== 'values.yml') return false;

      // Skip empty, placeholder, or override-me values
      const value = line.match(/:\s*['"]?([^'"{\s]+)['"]?/)?.[1] ?? '';
      const lowerVal = value.toLowerCase();
      if (
        lowerVal === '""' ||
        lowerVal === "''" ||
        lowerVal.includes('changeme') ||
        lowerVal.includes('override') ||
        lowerVal.includes('replace')
      ) {
        return false;
      }

      return true;
    },
    message:
      'Default secret value in Helm values.yaml. These are often committed to git.',
    fix: 'Use empty defaults and require values at install time, or use Helm secrets plugins.',
    fixCode: `# Dangerous - real secret committed:
# values.yaml
database:
  password: "production-db-pass"

# Safe - empty default, require at install:
# values.yaml
database:
  password: ""

# Then install with:
# helm install myapp ./chart --set database.password=$DB_PASSWORD`,
  }),

  // HELM002 - No Security Context (FileCheck)
  {
    level: 'file',
    id: 'HELM002',
    name: 'Helm Template Missing Security Context',
    description:
      'Helm template deploys containers without a securityContext.',
    category: 'iac',
    defaultSeverity: 'medium',
    appliesTo: ['yml', 'yaml'],
    fastFilter: 'kind:',

    async analyze(file: FileEntry, ctx: ScanContext): Promise<Finding[]> {
      // Only check files under a templates/ directory
      if (!file.relativePath.includes('templates/')) return [];

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Must be a Deployment or StatefulSet
      if (!/kind:\s*(?:Deployment|StatefulSet)/i.test(content)) return [];

      // Check if securityContext is defined anywhere
      if (/securityContext/i.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with kind:
      let kindLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/kind:\s*(?:Deployment|StatefulSet)/i.test(lines[i])) {
          kindLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        kindLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'HELM002',
          title: 'Helm Template Missing Security Context',
          message:
            'Helm template deploys containers without a securityContext. Set runAsNonRoot: true and drop capabilities.',
          severity: ctx.config.severityOverrides.get('HELM002') ?? 'medium',
          category: 'iac',
          location: {
            filePath: file.relativePath,
            startLine: kindLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Add a securityContext to the pod spec and/or container spec in the Helm template.',
          fixCode: `# Add securityContext to deployment template:
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: {{ .Chart.Name }}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL`,
        },
      ];
    },
  } satisfies FileCheck,

  // =========================================================================
  // CloudFormation
  // =========================================================================

  // CF001 - Security Group Open to World
  createLineCheck({
    id: 'CF001',
    name: 'Security Group Open to World',
    category: 'iac',
    severity: 'critical',
    pattern: /CidrIp\s*:\s*['"]?0\.0\.0\.0\/0/g,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, line, file) {
      const content = file.content ?? '';
      // Must be a CloudFormation template
      if (!/AWSTemplateFormatVersion/i.test(content) && !/Resources\s*:/i.test(content)) {
        return false;
      }
      // Skip egress / outbound rules
      const lower = line.toLowerCase();
      if (lower.includes('egress') || lower.includes('outbound')) return false;
      // Check surrounding lines for egress context
      const lines = file.lines ?? [];
      const idx = lines.indexOf(line);
      if (idx >= 0) {
        for (let i = Math.max(0, idx - 10); i < idx; i++) {
          const ctx = lines[i].toLowerCase();
          if (ctx.includes('egress') || ctx.includes('outbound')) return false;
        }
      }
      return true;
    },
    message:
      'CloudFormation security group allows inbound traffic from any IP.',
    fix: 'Restrict CidrIp to specific IP ranges instead of 0.0.0.0/0.',
    fixCode: `# Dangerous:
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 0.0.0.0/0

# Safe:
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/8`,
  }),

  // CF002 - S3 Bucket Public Access
  createLineCheck({
    id: 'CF002',
    name: 'S3 Bucket Public Access',
    category: 'iac',
    severity: 'critical',
    pattern: /AccessControl\s*:\s*['"]?(?:PublicRead|PublicReadWrite)/g,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /AWSTemplateFormatVersion/i.test(content) || /Resources\s*:/i.test(content);
    },
    message: 'S3 bucket is publicly accessible via CloudFormation.',
    fix: 'Set AccessControl to Private and use a bucket policy with specific principal access.',
    fixCode: `# Dangerous:
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    AccessControl: PublicRead

# Safe:
MyBucket:
  Type: AWS::S3::Bucket
  Properties:
    AccessControl: Private
    PublicAccessBlockConfiguration:
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true`,
  }),

  // CF003 - RDS Publicly Accessible
  createLineCheck({
    id: 'CF003',
    name: 'RDS Publicly Accessible',
    category: 'iac',
    severity: 'high',
    pattern: /PubliclyAccessible\s*:\s*['"]?true/gi,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /AWSTemplateFormatVersion/i.test(content) || /Type.*AWS::RDS/i.test(content);
    },
    message: 'RDS database is publicly accessible from the internet.',
    fix: 'Set PubliclyAccessible to false and place the database in a private subnet.',
    fixCode: `# Dangerous:
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    PubliclyAccessible: true

# Safe:
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    PubliclyAccessible: false
    DBSubnetGroupName: !Ref PrivateSubnetGroup`,
  }),

  // CF004 - No Encryption on EBS/RDS
  createLineCheck({
    id: 'CF004',
    name: 'No Encryption on EBS/RDS',
    category: 'iac',
    severity: 'high',
    pattern: /(?:StorageEncrypted|Encrypted)\s*:\s*['"]?false/gi,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /AWSTemplateFormatVersion/i.test(content) || /Resources\s*:/i.test(content);
    },
    message: 'Encryption is disabled on storage. Enable encryption at rest.',
    fix: 'Set StorageEncrypted or Encrypted to true and specify a KMS key.',
    fixCode: `# Dangerous:
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    StorageEncrypted: false

# Safe:
MyDB:
  Type: AWS::RDS::DBInstance
  Properties:
    StorageEncrypted: true
    KmsKeyId: !Ref MyKmsKey`,
  }),

  // CF005 - IAM Wildcard Action
  createLineCheck({
    id: 'CF005',
    name: 'IAM Wildcard Action',
    category: 'iac',
    severity: 'high',
    pattern: /Action\s*:.*['"]\*['"]/g,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, _line, file) {
      const content = file.content ?? '';
      return /AWSTemplateFormatVersion/i.test(content) || /Resources\s*:/i.test(content);
    },
    message:
      'IAM policy grants wildcard permissions. Follow the principle of least privilege.',
    fix: 'Replace the wildcard action with only the specific actions the resource needs.',
    fixCode: `# Dangerous:
PolicyDocument:
  Statement:
    - Effect: Allow
      Action: '*'
      Resource: '*'

# Safe:
PolicyDocument:
  Statement:
    - Effect: Allow
      Action:
        - 's3:GetObject'
        - 's3:PutObject'
      Resource: !Sub 'arn:aws:s3:::\${MyBucket}/*'`,
  }),

  // CF006 - Hardcoded Secrets in Parameters
  createLineCheck({
    id: 'CF006',
    name: 'Hardcoded Secrets in Parameters',
    category: 'iac',
    severity: 'high',
    pattern: /Default\s*:\s*['"][^'"]{16,}['"]/g,
    appliesTo: ['yml', 'yaml', 'json', 'template'],
    validate(_match, line, file) {
      const content = file.content ?? '';
      if (!/AWSTemplateFormatVersion/i.test(content) && !/Resources\s*:/i.test(content)) {
        return false;
      }
      // Only flag near parameter names that look like secrets
      const lines = file.lines ?? [];
      const idx = lines.indexOf(line);
      if (idx >= 0) {
        for (let i = Math.max(0, idx - 5); i < idx; i++) {
          if (/password|secret|key|token/i.test(lines[i])) return true;
        }
      }
      return false;
    },
    message:
      'CloudFormation parameter has a hardcoded default that looks like a secret.',
    fix: 'Remove the Default value and use NoEcho: true. Provide secrets via parameter overrides or AWS Secrets Manager.',
    fixCode: `# Dangerous:
Parameters:
  DatabasePassword:
    Type: String
    Default: 'MyS3cretP@ssword!'

# Safe:
Parameters:
  DatabasePassword:
    Type: String
    NoEcho: true
    # No Default - require it at deploy time

# Best - use Secrets Manager:
DatabasePassword:
  Type: AWS::SecretsManager::Secret
  Properties:
    GenerateSecretString:
      PasswordLength: 32`,
  }),

  // =========================================================================
  // Nginx
  // =========================================================================

  // NGINX001 - Server Tokens Exposed
  createLineCheck({
    id: 'NGINX001',
    name: 'Server Tokens Exposed',
    category: 'iac',
    severity: 'medium',
    pattern: /server_tokens\s+on/g,
    appliesTo: ['conf'],
    validate(_match, _line, file) {
      return file.basename.includes('nginx') || file.extension === 'conf';
    },
    message: 'Nginx exposes version information. Set server_tokens off.',
    fix: 'Change server_tokens on to server_tokens off.',
    fixCode: `# Dangerous:
server_tokens on;

# Safe:
server_tokens off;`,
  }),

  // NGINX002 - Missing HTTPS Redirect
  createLineCheck({
    id: 'NGINX002',
    name: 'Missing HTTPS Redirect',
    category: 'iac',
    severity: 'high',
    pattern: /listen\s+80\b/g,
    appliesTo: ['conf'],
    validate(_match, _line, file) {
      if (!file.basename.includes('nginx') && file.extension !== 'conf') return false;
      const content = file.content ?? '';
      // Skip if the file already has an HTTPS redirect
      if (/return\s+301\s+https/i.test(content)) return false;
      if (/return\s+302\s+https/i.test(content)) return false;
      return true;
    },
    message: 'Nginx listens on HTTP port 80 without HTTPS redirect.',
    fix: 'Add a return 301 https://$host$request_uri; directive to redirect HTTP to HTTPS.',
    fixCode: `# Dangerous - serving HTTP without redirect:
server {
    listen 80;
    server_name example.com;
}

# Safe - redirect to HTTPS:
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}`,
  }),

  // NGINX003 - Autoindex Enabled
  createLineCheck({
    id: 'NGINX003',
    name: 'Autoindex Enabled',
    category: 'iac',
    severity: 'high',
    pattern: /autoindex\s+on/g,
    appliesTo: ['conf'],
    validate(_match, _line, file) {
      return file.basename.includes('nginx') || file.extension === 'conf';
    },
    message: 'Directory listing is enabled. Attackers can browse your file structure.',
    fix: 'Set autoindex off or remove the directive.',
    fixCode: `# Dangerous:
location /files {
    autoindex on;
}

# Safe:
location /files {
    autoindex off;
}`,
  }),

  // NGINX004 - Missing Security Headers (FileCheck)
  {
    level: 'file',
    id: 'NGINX004',
    name: 'Missing Security Headers',
    description:
      'Nginx config is missing security headers (X-Frame-Options, X-Content-Type-Options).',
    category: 'iac',
    defaultSeverity: 'medium',
    appliesTo: ['conf'],
    fastFilter: 'server',

    async analyze(file, ctx): Promise<Finding[]> {
      if (!file.basename.includes('nginx') && file.extension !== 'conf') return [];

      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Must be an nginx config with a server block
      if (!/server\s*\{/i.test(content)) return [];

      const hasXFrame = /add_header\s+X-Frame-Options/i.test(content);
      const hasXContentType = /add_header\s+X-Content-Type-Options/i.test(content);

      if (hasXFrame && hasXContentType) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the first server block line
      let serverLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/server\s*\{/.test(lines[i])) {
          serverLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        serverLine,
        ctx.config.contextLines,
      );

      const missing: string[] = [];
      if (!hasXFrame) missing.push('X-Frame-Options');
      if (!hasXContentType) missing.push('X-Content-Type-Options');

      return [
        {
          checkId: 'NGINX004',
          title: 'Missing Security Headers',
          message: `Nginx config is missing security headers (${missing.join(', ')}).`,
          severity: ctx.config.severityOverrides.get('NGINX004') ?? 'medium',
          category: 'iac',
          location: {
            filePath: file.relativePath,
            startLine: serverLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Add security headers to your server or http block.',
          fixCode: `# Add these headers to your server block:
server {
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}`,
        },
      ];
    },
  } satisfies FileCheck,

  // NGINX005 - Permissive CORS
  createLineCheck({
    id: 'NGINX005',
    name: 'Permissive CORS',
    category: 'iac',
    severity: 'high',
    pattern: /add_header\s+['"]?Access-Control-Allow-Origin['"]?\s+['"]?\*['"]?/g,
    appliesTo: ['conf'],
    validate(_match, _line, file) {
      return file.basename.includes('nginx') || file.extension === 'conf';
    },
    message: 'Nginx CORS allows all origins.',
    fix: 'Restrict Access-Control-Allow-Origin to specific trusted origins.',
    fixCode: `# Dangerous:
add_header Access-Control-Allow-Origin *;

# Safe:
add_header Access-Control-Allow-Origin "https://example.com";`,
  }),

  // =========================================================================
  // Apache
  // =========================================================================

  // APACHE001 - Directory Listing Enabled
  createLineCheck({
    id: 'APACHE001',
    name: 'Directory Listing Enabled',
    category: 'iac',
    severity: 'high',
    pattern: /Options\s+.*Indexes/g,
    appliesTo: ['htaccess', 'conf'],
    validate(_match, line, file) {
      // Must be an Apache config file
      const isApache =
        file.basename === '.htaccess' ||
        file.basename === 'httpd.conf' ||
        file.basename === 'apache2.conf' ||
        file.relativePath.includes('apache');
      if (!isApache && file.extension !== 'conf') return false;
      // Skip if the line disables Indexes with -Indexes
      if (/-Indexes/.test(line)) return false;
      return true;
    },
    message: 'Apache directory listing is enabled. Attackers can browse your files.',
    fix: 'Replace +Indexes or Indexes with -Indexes to disable directory listing.',
    fixCode: `# Dangerous:
Options +Indexes +FollowSymLinks

# Safe:
Options -Indexes +FollowSymLinks`,
  }),

  // APACHE002 - Server Signature Exposed
  createLineCheck({
    id: 'APACHE002',
    name: 'Server Signature Exposed',
    category: 'iac',
    severity: 'medium',
    pattern: /ServerSignature\s+On/gi,
    appliesTo: ['htaccess', 'conf'],
    validate(_match, _line, file) {
      return (
        file.basename === '.htaccess' ||
        file.basename === 'httpd.conf' ||
        file.basename === 'apache2.conf' ||
        file.relativePath.includes('apache') ||
        file.extension === 'conf'
      );
    },
    message: 'Apache exposes version information. Set ServerSignature Off.',
    fix: 'Set ServerSignature Off and ServerTokens Prod.',
    fixCode: `# Dangerous:
ServerSignature On

# Safe:
ServerSignature Off
ServerTokens Prod`,
  }),

  // APACHE003 - CGI Execution Enabled
  createLineCheck({
    id: 'APACHE003',
    name: 'CGI Execution Enabled',
    category: 'iac',
    severity: 'high',
    pattern: /Options\s+.*ExecCGI/g,
    appliesTo: ['htaccess', 'conf'],
    validate(_match, _line, file) {
      return (
        file.basename === '.htaccess' ||
        file.basename === 'httpd.conf' ||
        file.basename === 'apache2.conf' ||
        file.relativePath.includes('apache') ||
        file.extension === 'conf'
      );
    },
    message:
      'CGI execution is enabled. This allows running arbitrary scripts if an attacker can upload files.',
    fix: 'Remove ExecCGI from Options unless CGI is explicitly required. Use modern alternatives like WSGI or FastCGI.',
    fixCode: `# Dangerous:
Options +ExecCGI
AddHandler cgi-script .cgi .pl

# Safe - remove ExecCGI:
Options -ExecCGI

# If CGI is needed, restrict to a specific directory:
<Directory /var/www/cgi-bin>
    Options +ExecCGI
    Require ip 10.0.0.0/8
</Directory>`,
  }),

  // =========================================================================
  // Generic Infrastructure Configuration Checks
  // =========================================================================

  // INFRA001 - Hardcoded Password in Config
  createLineCheck({
    id: 'INFRA001',
    name: 'Hardcoded Password in Config',
    category: 'iac',
    severity: 'high',
    pattern: /(?:password|passwd|pwd|pass)\s*[=:]\s*['"](?!['"${\s])[^'"]{8,}['"]/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties', 'env'],
    validate(_match, line) {
      const value = line.match(/[=:]\s*['"]([^'"]+)['"]/)?.[1] ?? '';
      if (
        value.startsWith('$') ||
        value.startsWith('{{') ||
        value.startsWith('env(') ||
        value.startsWith('vault:') ||
        value.startsWith('ssm:') ||
        value.startsWith('arn:') ||
        value.startsWith('<') ||
        value.startsWith('%') ||
        value.startsWith('!Ref') ||
        value.startsWith('!Sub')
      ) return false;
      return true;
    },
    message: 'Hardcoded password in configuration file. Use environment variables or a secrets manager.',
    fix: 'Replace the hardcoded password with an environment variable reference or secrets manager lookup.',
  }),

  // INFRA002 - Hardcoded API Key/Token in Config
  createLineCheck({
    id: 'INFRA002',
    name: 'Hardcoded API Key/Token in Config',
    category: 'iac',
    severity: 'high',
    pattern: /(?:api[_-]?key|api[_-]?token|auth[_-]?token|secret[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*['"]?[A-Za-z0-9_\-/.+]{20,}['"]?/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    validate(_match, line) {
      const value = line.match(/[=:]\s*['"]?([^\s'"]+)/)?.[1] ?? '';
      if (
        value.startsWith('$') ||
        value.startsWith('{{') ||
        value.startsWith('env(') ||
        value.startsWith('vault:') ||
        value.startsWith('ssm:') ||
        value.startsWith('<') ||
        value.startsWith('%') ||
        value.startsWith('!Ref')
      ) return false;
      // Skip placeholder words
      const lower = value.toLowerCase();
      if (
        lower.includes('changeme') ||
        lower.includes('placeholder') ||
        lower.includes('your_') ||
        lower.includes('replace') ||
        lower.includes('xxx')
      ) return false;
      return true;
    },
    message: 'API key or token hardcoded in configuration. Use environment variables or a secrets manager.',
    fix: 'Replace the hardcoded API key or token with an environment variable or secrets manager reference.',
  }),

  // INFRA003 - TLS/SSL Disabled
  createLineCheck({
    id: 'INFRA003',
    name: 'TLS/SSL Disabled',
    category: 'iac',
    severity: 'high',
    pattern: /(?:ssl|tls|https|verify_ssl|ssl_verify|tls_verify|verify_certificates|insecure_skip_verify|check_hostname)\s*[=:]\s*(?:false|no|off|0|disabled|none)/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'TLS/SSL verification is disabled. This allows man-in-the-middle attacks.',
    fix: 'Enable TLS/SSL verification. Set the value to true/yes/on.',
  }),

  // INFRA004 - Insecure Protocol in Config
  createLineCheck({
    id: 'INFRA004',
    name: 'Insecure Protocol in Config',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:url|uri|endpoint|host|server|address|href|target)\s*[=:]\s*['"]?(?:http|ftp|telnet|ldap):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    validate(_match, line) {
      // Skip XML namespaces and schema URIs
      if (/xmlns|w3\.org|schema\.org/i.test(line)) return false;
      return true;
    },
    message: 'Configuration uses an insecure protocol (HTTP/FTP/telnet). Use HTTPS/SFTP/SSH instead.',
    fix: 'Replace insecure protocol URLs with their secure equivalents (HTTPS, SFTP, SSH, LDAPS).',
  }),

  // INFRA005 - Wildcard Bind Address
  createLineCheck({
    id: 'INFRA005',
    name: 'Wildcard Bind Address',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:bind|listen|host|address)\s*[=:]\s*['"]?(?:0\.0\.0\.0|::)['":]?/g,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'Service binds to all interfaces (0.0.0.0). This exposes it to any network. Bind to 127.0.0.1 for internal services.',
    fix: 'Bind to 127.0.0.1 or a specific interface for internal services instead of 0.0.0.0.',
  }),

  // INFRA006 - Debug/Verbose Mode in Config
  createLineCheck({
    id: 'INFRA006',
    name: 'Debug/Verbose Mode in Config',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:debug|verbose|log_level|loglevel|logging)\s*[=:]\s*['"]?(?:true|on|yes|debug|trace|verbose|all)['"]?/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    validate(_match, line) {
      // Skip if line references production context
      if (/production|prod|NODE_ENV/i.test(line)) return false;
      return true;
    },
    message: 'Debug or verbose logging enabled in configuration. This may expose sensitive information in production logs.',
    fix: 'Set logging level to "info" or "warn" for production environments.',
  }),

  // INFRA007 - Default/Weak Port Exposure
  createLineCheck({
    id: 'INFRA007',
    name: 'Default/Weak Port Exposure',
    category: 'iac',
    severity: 'low',
    pattern: /(?:port)\s*[=:]\s*['"]?(?:21|23|25|110|143|445|1433|3306|5432|6379|27017|11211)['"]?/g,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties', 'tf', 'hcl'],
    message: 'Well-known service port exposed in configuration. Ensure this service is not directly accessible from the internet.',
    fix: 'Use a firewall or VPN to restrict access. Common risky ports: 21 (FTP), 23 (Telnet), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB).',
  }),

  // INFRA008 - CORS Wildcard in Config
  createLineCheck({
    id: 'INFRA008',
    name: 'CORS Wildcard in Config',
    category: 'iac',
    severity: 'high',
    pattern: /(?:cors|allowed[_-]?origins?|access[_-]?control)\s*[=:]\s*['"]?\*['"]?/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'CORS is configured to allow all origins (*). Restrict to specific trusted domains.',
    fix: 'Replace the wildcard (*) with specific trusted domain origins.',
  }),

  // INFRA009 - Admin/Root User Enabled
  createLineCheck({
    id: 'INFRA009',
    name: 'Admin/Root User Enabled',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:admin[_-]?enabled|root[_-]?login|allow[_-]?root|permit[_-]?root|superuser)\s*[=:]\s*['"]?(?:true|yes|on|enabled|1)['"]?/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'Admin or root access is enabled in configuration. Disable root login and use named admin accounts.',
    fix: 'Disable root login and create named admin accounts with appropriate permissions.',
  }),

  // INFRA010 - Plaintext Connection String
  createLineCheck({
    id: 'INFRA010',
    name: 'Plaintext Connection String',
    category: 'iac',
    severity: 'high',
    pattern: /(?:connection[_-]?string|dsn|database[_-]?url|db[_-]?url|jdbc)\s*[=:]\s*['"]?(?:postgres|mysql|mongodb|mssql|redis|amqp):\/\/[^:]+:[^@]+@/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    validate(_match, line) {
      const value = line.match(/[=:]\s*['"]?([^\s'"]+)/)?.[1] ?? '';
      if (
        value.startsWith('$') ||
        value.startsWith('{{') ||
        value.startsWith('env(') ||
        value.startsWith('vault:') ||
        value.startsWith('ssm:')
      ) return false;
      return true;
    },
    message: 'Database connection string with embedded credentials in configuration file. Use environment variables.',
    fix: 'Move connection strings with credentials to environment variables or a secrets manager.',
  }),

  // INFRA011 - SSH Keys / Private Key Paths
  createLineCheck({
    id: 'INFRA011',
    name: 'SSH Keys / Private Key Paths',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:ssh[_-]?key|private[_-]?key|key[_-]?file|identity[_-]?file|ssl[_-]?key)\s*[=:]\s*['"]?(?:\/|~\/|\.\/)[^\s'"]+['"]?/g,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'Private key file path in configuration. Ensure the key file has restrictive permissions (600) and is not committed to git.',
    fix: 'Ensure the key file has permissions set to 600 and is listed in .gitignore.',
  }),

  // INFRA012 - Rate Limit Disabled
  createLineCheck({
    id: 'INFRA012',
    name: 'Rate Limit Disabled',
    category: 'iac',
    severity: 'medium',
    pattern: /(?:rate[_-]?limit|throttle|max[_-]?requests)\s*[=:]\s*['"]?(?:0|false|off|disabled|none|unlimited|-1)['"]?/gi,
    appliesTo: ['yml', 'yaml', 'json', 'toml', 'ini', 'conf', 'cfg', 'properties'],
    message: 'Rate limiting is disabled. This allows attackers to make unlimited requests.',
    fix: 'Enable rate limiting with appropriate thresholds for your service.',
  }),
];
