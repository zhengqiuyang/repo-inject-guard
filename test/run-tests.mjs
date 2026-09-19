#!/usr/bin/env node
/**
 * Portable test launcher (house pattern).
 *
 * Enumerates dist/test/*.test.js and execs `node --test <file> <file> ...`
 * with an EXPLICIT file list — no glob arguments, which need Node 21+.
 * Works on Node 20+ and on Windows.
 */
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const distTestDir = join(here, '..', 'dist', 'test');

let files;
try {
  files = readdirSync(distTestDir)
    .filter((f) => f.endsWith('.test.js'))
    .sort()
    .map((f) => join(distTestDir, f));
} catch {
  console.error('repo-inject-guard: dist/test not found — run `npm run build` first.');
  process.exit(2);
}

if (files.length === 0) {
  console.error('repo-inject-guard: no *.test.js files in dist/test — run `npm run build` first.');
  process.exit(2);
}

console.log(`repo-inject-guard: running ${files.length} test file(s) via node --test`);
const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(result.status === null ? 2 : result.status);
