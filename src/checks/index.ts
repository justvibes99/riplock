import type { CheckDefinition } from './types.js';

// Secrets
import { secretChecks } from './secrets/index.js';
// Git
import { gitChecks } from './git/index.js';
// Injection
import { injectionChecks } from './injection/index.js';
// Auth
import { authChecks } from './auth/index.js';
// Network
import { networkChecks } from './network/index.js';
// Data Exposure
import { dataExposureChecks } from './data-exposure/index.js';
// Crypto
import { cryptoChecks } from './crypto/index.js';
// Dependencies
import { dependencyChecks } from './dependencies/index.js';
// Framework
import { frameworkChecks } from './framework/index.js';
// Uploads
import { uploadChecks } from './uploads/index.js';
// DoS
import { dosChecks } from './dos/index.js';
// Config
import { configChecks } from './config/index.js';
// Python
import { pythonChecks } from './python/index.js';
// Go
import { goChecks } from './go/index.js';
// Ruby
import { rubyChecks } from './ruby/index.js';
// PHP
import { phpChecks } from './php/index.js';
// Docker
import { dockerChecks } from './docker/index.js';
// CI/CD
import { cicdChecks } from './cicd/index.js';
// IaC
import { iacChecks } from './iac/index.js';
// AST (taint-tracked)
import { astChecks } from './ast/index.js';

export const allChecks: CheckDefinition[] = [
  ...secretChecks,
  ...gitChecks,
  ...injectionChecks,
  ...authChecks,
  ...networkChecks,
  ...dataExposureChecks,
  ...cryptoChecks,
  ...dependencyChecks,
  ...frameworkChecks,
  ...uploadChecks,
  ...dosChecks,
  ...configChecks,
  ...pythonChecks,
  ...goChecks,
  ...rubyChecks,
  ...phpChecks,
  ...dockerChecks,
  ...cicdChecks,
  ...iacChecks,
  ...astChecks,
];
