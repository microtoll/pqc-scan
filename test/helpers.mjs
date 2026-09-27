// Shared by the tests: fixture paths, and a scan with a fixed clock. Every
// scan goes through the public API (src/index.js).
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index.js';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const FIXTURES = join(ROOT, 'test', 'fixtures');
export const FIXED_NOW = new Date('2026-09-27T12:00:00Z');

export function scanFixture(name, options = {}) {
  return scan(join(FIXTURES, name), { now: FIXED_NOW, ...options });
}

/** One line per finding: `file:line algorithm [operation] priority`, for readable assertions. */
export function lines(report, file) {
  return report.findings
    .filter((f) => !file || f.file === file)
    .map((f) => `${f.file}:${f.line} ${f.algorithm} [${f.operation}]${f.priority ? ` ${f.priority}` : ''}`);
}

export function only(report, file) {
  return report.findings.filter((f) => f.file === file);
}
