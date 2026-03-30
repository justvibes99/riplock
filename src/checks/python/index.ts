import type { CheckDefinition } from '../types.js';
import { createLineCheck } from '../shared.js';

// ---- Python Security Checks ----

export const pythonChecks: CheckDefinition[] = [
  // PY001 - SQL Injection (f-string)
  createLineCheck({
    id: 'PY001',
    category: 'python',
    name: 'SQL Injection (f-string)',
    severity: 'critical',
    pattern: /(?:execute|executemany|cursor\.execute)\s*\(\s*f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
    appliesTo: ['py'],
    message:
      'Python f-string used in SQL query. An attacker can modify the query.',
    fix: 'Use parameterized queries with placeholders instead of f-strings.',
    fixCode: `# Dangerous:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Safe - use parameterized queries:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
  }),

  // PY002 - SQL Injection (.format)
  createLineCheck({
    id: 'PY002',
    category: 'python',
    name: 'SQL Injection (.format)',
    severity: 'critical',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE).*['"]\.format/gi,
    appliesTo: ['py'],
    message: 'str.format() used in SQL query.',
    fix: 'Use parameterized queries with placeholders instead of str.format().',
    fixCode: `# Dangerous:
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

# Safe - use parameterized queries:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
  }),

  // PY003 - Command Injection
  createLineCheck({
    id: 'PY003',
    category: 'python',
    name: 'Command Injection',
    severity: 'critical',
    pattern: /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*(?:f['"]|.*\.format|.*%\s)/g,
    appliesTo: ['py'],
    message:
      'User input in shell command. Use subprocess.run() with a list and shell=False.',
    fix: 'Use subprocess.run() with a list of arguments and shell=False instead of building shell command strings.',
    fixCode: `# Dangerous:
subprocess.run(f"ls {user_input}", shell=True)
os.system("rm %s" % filename)

# Safe - use a list of arguments:
subprocess.run(["ls", user_input], shell=False)`,
  }),

  // PY004 - Pickle Deserialization
  createLineCheck({
    id: 'PY004',
    category: 'python',
    name: 'Pickle Deserialization',
    severity: 'critical',
    pattern: /pickle\.(?:loads?|Unpickler)\s*\(/g,
    appliesTo: ['py'],
    message:
      'pickle deserializes arbitrary Python objects. An attacker can execute any code via a crafted pickle payload.',
    fix: 'Use JSON for untrusted data. If you must use pickle, only unpickle data from trusted sources.',
    fixCode: `# Dangerous:
data = pickle.loads(user_input)

# Safe - use JSON for untrusted data:
import json
data = json.loads(user_input)`,
  }),

  // PY005 - Django DEBUG True
  createLineCheck({
    id: 'PY005',
    category: 'python',
    name: 'Django DEBUG True',
    severity: 'high',
    pattern: /DEBUG\s*=\s*True/g,
    appliesTo: ['py'],
    validate(_match, line) {
      // Skip if the value comes from an environment variable or env() call
      if (/os\.environ/.test(line)) return false;
      if (/env\(/.test(line)) return false;
      return true;
    },
    message:
      'Django DEBUG mode is enabled. This exposes detailed error pages, SQL queries, and settings to anyone.',
    fix: 'Set DEBUG from an environment variable and ensure it is False in production.',
    fixCode: `# Dangerous:
DEBUG = True

# Safe - read from environment:
import os
DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"`,
  }),

  // PY006 - Django SECRET_KEY Hardcoded
  createLineCheck({
    id: 'PY006',
    category: 'python',
    name: 'Django SECRET_KEY Hardcoded',
    severity: 'critical',
    pattern: /SECRET_KEY\s*=\s*['"][^'"]{8,}['"]/g,
    appliesTo: ['py'],
    validate(_match, line) {
      // Skip if the value comes from an environment variable, env(), or config()
      if (/os\.environ/.test(line)) return false;
      if (/env\(/.test(line)) return false;
      if (/config\(/.test(line)) return false;
      return true;
    },
    message:
      'Django SECRET_KEY is hardcoded. Anyone with access to this code can forge sessions and CSRF tokens.',
    fix: 'Load SECRET_KEY from an environment variable or a secrets manager.',
    fixCode: `# Dangerous:
SECRET_KEY = "my-super-secret-key-12345"

# Safe - read from environment:
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`,
  }),

  // PY007 - Flask Debug Mode
  createLineCheck({
    id: 'PY007',
    category: 'python',
    name: 'Flask Debug Mode',
    severity: 'high',
    pattern: /app\.run\s*\([^)]*debug\s*=\s*True/g,
    appliesTo: ['py'],
    message:
      'Flask debug mode enables an interactive debugger. An attacker can execute code on your server.',
    fix: 'Disable debug mode in production. Use environment variables to control debug settings.',
    fixCode: `# Dangerous:
app.run(debug=True)

# Safe - control via environment:
import os
app.run(debug=os.environ.get("FLASK_DEBUG", "false") == "true")`,
  }),

  // PY008 - eval() Usage
  createLineCheck({
    id: 'PY008',
    category: 'python',
    name: 'eval() with User Input',
    severity: 'critical',
    pattern: /\beval\s*\(\s*(?:request\.|input\(|sys\.argv)/g,
    appliesTo: ['py'],
    message: 'eval() with user input executes arbitrary Python code.',
    fix: 'Never pass user input to eval(). Use ast.literal_eval() for safe literal parsing, or a dedicated parser for expressions.',
    fixCode: `# Dangerous:
result = eval(input("Enter expression: "))
result = eval(request.form["expr"])

# Safe - use ast.literal_eval for literals:
import ast
result = ast.literal_eval(user_input)`,
  }),

  // PY009 - Hardcoded Password (Python)
  createLineCheck({
    id: 'PY009',
    category: 'python',
    name: 'Hardcoded Password (Python)',
    severity: 'high',
    pattern: /(?:password|passwd|pwd)\s*=\s*['"][^'"]{8,}['"]/gi,
    appliesTo: ['py'],
    validate(_match, line) {
      // Skip if the value comes from environment, getenv, or config
      if (/os\.environ/.test(line)) return false;
      if (/getenv/.test(line)) return false;
      if (/config/.test(line)) return false;
      // Skip placeholder/example values
      if (/(?:example|placeholder|changeme|CHANGEME|your[_-]?password|xxx)/i.test(line)) return false;
      return true;
    },
    message:
      'A password is hardcoded in source code. Anyone with access to the repository can see it.',
    fix: 'Load passwords from environment variables or a secrets manager. Never commit passwords to source control.',
    fixCode: `# Dangerous:
password = "my_secret_password_123"

# Safe - read from environment:
import os
password = os.environ["DB_PASSWORD"]`,
  }),

  // PY010 - No CSRF Middleware (Django)
  createLineCheck({
    id: 'PY010',
    category: 'python',
    name: 'No CSRF Middleware (Django)',
    severity: 'high',
    pattern: /MIDDLEWARE\s*=\s*\[/g,
    appliesTo: ['py'],
    validate(_match, line) {
      // Skip if csrf appears on the same line (inline middleware list)
      if (/[Cc]srf/.test(line)) return false;
      return true;
    },
    message:
      'Django MIDDLEWARE is defined without CSRF protection on the same line. Ensure CsrfViewMiddleware is included in your MIDDLEWARE list.',
    fix: "Add 'django.middleware.csrf.CsrfViewMiddleware' to your MIDDLEWARE list.",
    fixCode: `# Ensure CSRF middleware is included:
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # ... other middleware
]`,
  }),

  // PY011 - Insecure Password Hash
  createLineCheck({
    id: 'PY011',
    category: 'python',
    name: 'Insecure Password Hash',
    severity: 'high',
    pattern: /(?:hashlib\.(?:md5|sha1|sha256))\s*\(.*(?:password|passwd)/gi,
    appliesTo: ['py'],
    message:
      "Using hashlib for password hashing. Use bcrypt, argon2, or Django's make_password().",
    fix: 'Use a purpose-built password hashing library like bcrypt or argon2-cffi. These include salting and are designed to be slow to resist brute-force attacks.',
    fixCode: `# Dangerous:
hashed = hashlib.sha256(password.encode()).hexdigest()

# Safe - use bcrypt:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Safe - Django:
from django.contrib.auth.hashers import make_password
hashed = make_password(password)`,
  }),

  // PY012 - Path Traversal
  createLineCheck({
    id: 'PY012',
    category: 'python',
    name: 'Path Traversal',
    severity: 'high',
    pattern: /open\s*\(\s*(?:request\.|input\(|sys\.argv|f['"])/g,
    appliesTo: ['py'],
    message:
      'File opened with user-controlled path. Validate the path stays within allowed directories.',
    fix: 'Resolve the path and verify it stays within the intended directory. Reject paths containing ".." or absolute paths from user input.',
    fixCode: `# Dangerous:
with open(request.args["filename"]) as f:
    data = f.read()

# Safe - validate path:
import os
base_dir = "/app/uploads"
requested = os.path.realpath(os.path.join(base_dir, filename))
if not requested.startswith(os.path.realpath(base_dir) + os.sep):
    raise ValueError("Path traversal detected")
with open(requested) as f:
    data = f.read()`,
  }),
];
