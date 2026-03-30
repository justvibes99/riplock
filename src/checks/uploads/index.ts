import type {
  CheckDefinition,
  FileCheck,
  Finding,
  ScanContext,
} from '../types.js';
import { extractSnippet } from '../../utils/snippet.js';
import { createLineCheck } from '../shared.js';

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

export const uploadChecks: CheckDefinition[] = [
  // UPLOAD001 - No File Type Validation (FileCheck)
  {
    level: 'file',
    id: 'UPLOAD001',
    name: 'No File Type Validation',
    description: 'File uploads have no type validation, allowing any file type to be uploaded.',
    category: 'uploads',
    defaultSeverity: 'high',
    appliesTo: ['js', 'ts'],
    fastFilter: /multer|formidable|busboy/i,

    async analyze(file, ctx): Promise<Finding[]> {
      const content = await ctx.readFile(file.absolutePath);
      if (!content) return [];

      // Confirm there is an upload handler in this file
      const uploadPattern = /(?:multer|formidable|busboy)\s*\(/i;
      if (!uploadPattern.test(content)) return [];

      // Check for file type validation references
      const typeValidation =
        /(?:fileFilter|allowedMimeTypes|mimetype|\.endsWith|accept|allowedTypes|allowedExtensions|fileTypes|mimeTypes)/i;
      if (typeValidation.test(content)) return [];

      const lines = await ctx.readLines(file.absolutePath);

      // Find the line with the upload handler for better location
      let uploadLine = 1;
      for (let i = 0; i < lines.length; i++) {
        if (/(?:multer|formidable|busboy)\s*\(/i.test(lines[i])) {
          uploadLine = i + 1;
          break;
        }
      }

      const { snippet, contextBefore, contextAfter } = extractSnippet(
        lines,
        uploadLine,
        ctx.config.contextLines,
      );

      return [
        {
          checkId: 'UPLOAD001',
          title: 'No File Type Validation',
          message:
            'File uploads have no type validation. An attacker can upload executable files or scripts.',
          severity: ctx.config.severityOverrides.get('UPLOAD001') ?? 'high',
          category: 'uploads',
          location: {
            filePath: file.relativePath,
            startLine: uploadLine,
          },
          snippet,
          contextBefore,
          contextAfter,
          fix: 'Add file type checking. Only allow the specific types you need (e.g., images, PDFs).',
          fixCode: `// Add a fileFilter to your multer config:
const upload = multer({
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'));
    }
  },
});`,
        },
      ];
    },
  } satisfies FileCheck,

  // UPLOAD002 - No File Size Limit
  createLineCheck({
    id: 'UPLOAD002',
    category: 'uploads',
    name: 'No File Size Limit',
    severity: 'high',
    pattern: /multer\s*\(\s*\{/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Not a problem if the same line references limits
      if (/limits/i.test(line)) return false;
      if (/maxFileSize/i.test(line)) return false;
      if (/fileSize/i.test(line)) return false;
      return true;
    },
    message:
      'No file size limit on uploads. An attacker can upload huge files to fill your storage or crash your server.',
    fix: 'Add a file size limit to your multer configuration.',
    fixCode: `// Add a limits option:
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 },  // 5MB max
});`,
  }),

  // UPLOAD003 - Uploads in Public Dir
  createLineCheck({
    id: 'UPLOAD003',
    category: 'uploads',
    name: 'Uploads Stored in Public Directory',
    severity: 'medium',
    pattern: /(?:destination|dest)\s*:\s*['"](?:public|static|www|htdocs)/g,
    appliesTo: ['js', 'ts'],
    message:
      'Uploaded files are stored in a publicly accessible directory. Malicious uploads could be served directly to users.',
    fix: '1. Store uploads outside the public directory.\n2. Serve files through a route handler that validates access and sets proper Content-Type headers.\n3. Generate random filenames to prevent direct URL guessing.',
    fixCode: `// Dangerous:
const upload = multer({ dest: 'public/uploads' });

// Safe - store outside public directory:
const upload = multer({ dest: 'private/uploads' });

// Serve through a controlled route:
app.get('/files/:id', authenticate, (req, res) => {
  const filePath = path.join('private/uploads', sanitize(req.params.id));
  res.sendFile(filePath);
});`,
  }),

  // UPLOAD004 - Path Traversal in Filename
  createLineCheck({
    id: 'UPLOAD004',
    category: 'uploads',
    name: 'Path Traversal in Upload Filename',
    severity: 'high',
    pattern: /(?:path\.join|writeFile|writeFileSync)\s*\([^)]*(?:originalname|file\.name)/g,
    appliesTo: ['js', 'ts'],
    message:
      'Upload filenames from users are not sanitized. An attacker can use "../" in the filename to write files outside the upload directory.',
    fix: 'Always use path.basename() on user-provided filenames to strip directory components.',
    fixCode: `// Dangerous:
const dest = path.join(uploadDir, file.originalname);
fs.writeFileSync(dest, file.buffer);

// Safe - strip directory components:
const safeName = path.basename(file.originalname);
const dest = path.join(uploadDir, safeName);
fs.writeFileSync(dest, file.buffer);`,
  }),

  // UPLOAD005 - Missing Content-Type Header on Response
  createLineCheck({
    id: 'UPLOAD005',
    category: 'uploads',
    name: 'Missing Content-Type Header on Response',
    severity: 'medium',
    pattern: /res\.(?:send|end)\s*\(\s*(?:file|buffer|data|stream)/g,
    appliesTo: ['js', 'ts'],
    validate(_match, line) {
      // Not a problem if the line or nearby code sets Content-Type
      if (/Content-Type/i.test(line)) return false;
      if (/contentType/i.test(line)) return false;
      if (/setHeader/i.test(line)) return false;
      if (/\.type\s*\(/i.test(line)) return false;
      return true;
    },
    message:
      'File served without Content-Type header. Browsers may MIME-sniff the content, potentially executing uploaded scripts.',
    fix: 'Set the Content-Type header before sending file data to prevent MIME-sniffing attacks.',
    fixCode: `// Dangerous - no Content-Type:
res.send(fileBuffer);

// Safe - set Content-Type explicitly:
res.setHeader('Content-Type', 'application/octet-stream');
res.send(fileBuffer);

// Or use res.type():
res.type('application/pdf');
res.send(fileBuffer);`,
  }),
];
