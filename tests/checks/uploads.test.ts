import { describe, it, expect } from 'vitest';
import { uploadChecks } from '../../src/checks/uploads/index.js';
import { testLine, testFileCheck } from '../helpers.js';

describe('upload checks', () => {
  describe('UPLOAD002 - No File Size Limit', () => {
    it('flags multer config without limits', () => {
      const result = testLine(uploadChecks, 'UPLOAD002', `multer({ storage: diskStorage })`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('UPLOAD002');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('uploads');
      expect(result!.message).toContain('size');
      expect(result!.fix).toBeTruthy();
    });

    it('does not flag multer config with limits', () => {
      const result = testLine(uploadChecks, 'UPLOAD002', `multer({ limits: { fileSize: 5000000 } })`);
      expect(result).toBeNull();
    });
  });

  describe('UPLOAD003 - Uploads Stored in Public Directory', () => {
    it('flags dest pointing to public directory', () => {
      const result = testLine(uploadChecks, 'UPLOAD003', `dest: 'public/uploads'`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('UPLOAD003');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('uploads');
      expect(result!.message).toContain('public');
      expect(result!.fix).toBeTruthy();
    });
  });

  describe('UPLOAD004 - Path Traversal in Upload Filename', () => {
    it('flags path.join with originalname', () => {
      const result = testLine(uploadChecks, 'UPLOAD004', `path.join(dir, file.originalname)`);
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('UPLOAD004');
      expect(result!.severity).toBe('high');
      expect(result!.category).toBe('uploads');
    });
  });

  // ---------------------------------------------------------------------------
  // UPLOAD001 - No File Type Validation (FileCheck)
  // ---------------------------------------------------------------------------

  describe('UPLOAD001 - No File Type Validation', () => {
    it('flags multer without fileFilter or mimetype check', async () => {
      const content = `const upload = multer({ dest: 'uploads/' });\napp.post('/upload', upload.single('file'), handler);`;
      const findings = await testFileCheck(uploadChecks, 'UPLOAD001', content);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe('UPLOAD001');
      expect(findings[0].severity).toBe('high');
      expect(findings[0].category).toBe('uploads');
    });

    it('does not flag multer with fileFilter', async () => {
      const content = `const upload = multer({\n  fileFilter: (req, file, cb) => {\n    if (file.mimetype === 'image/png') cb(null, true);\n  },\n});`;
      const findings = await testFileCheck(uploadChecks, 'UPLOAD001', content);
      expect(findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // UPLOAD005 - Missing Content-Type Header on Response
  // ---------------------------------------------------------------------------

  describe('UPLOAD005 - Missing Content-Type Header on Response', () => {
    it('flags res.send(buffer) without Content-Type', () => {
      const result = testLine(uploadChecks, 'UPLOAD005', 'res.send(buffer)');
      expect(result).not.toBeNull();
      expect(result!.checkId).toBe('UPLOAD005');
      expect(result!.severity).toBe('medium');
      expect(result!.category).toBe('uploads');
    });

    it('does not flag when Content-Type is set on same line', () => {
      const result = testLine(uploadChecks, 'UPLOAD005', `res.setHeader('Content-Type', 'image/png'); res.send(buffer)`);
      expect(result).toBeNull();
    });
  });
});
