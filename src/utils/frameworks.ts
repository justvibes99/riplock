import type { PackageJsonData } from '../checks/types.js';

const FRAMEWORK_DEPS: Record<string, string> = {
  next: 'nextjs',
  express: 'express',
  fastify: 'fastify',
  koa: 'koa',
  hono: 'hono',
  react: 'react',
  'react-dom': 'react',
  vue: 'vue',
  svelte: 'svelte',
  '@sveltejs/kit': 'sveltekit',
  nuxt: 'nuxt',
  '@angular/core': 'angular',
  'socket.io': 'socketio',
  prisma: 'prisma',
  '@prisma/client': 'prisma',
  mongoose: 'mongoose',
  sequelize: 'sequelize',
  drizzle: 'drizzle',
  'drizzle-orm': 'drizzle',
};

export function detectFrameworks(pkg: PackageJsonData | null): string[] {
  if (!pkg) return [];

  const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
  const detected = new Set<string>();

  for (const [dep, framework] of Object.entries(FRAMEWORK_DEPS)) {
    if (dep in allDeps) {
      detected.add(framework);
    }
  }

  return [...detected];
}
