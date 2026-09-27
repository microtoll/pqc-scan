// Invariants of the package itself: the publish gate, zero runtime
// dependencies, Node 20, and a test script that names every test file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

test('the publish gate is open (engine DECISIONS.md, 2026-09-27): the package is publishable under its scope', () => {
  assert.equal(pkg.private, undefined);
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.name, '@microtoll/pqc-scan');
  assert.equal(pkg.license, 'Apache-2.0');
});

test('zero runtime dependencies, and no dev dependencies', () => {
  assert.deepEqual(pkg.dependencies ?? {}, {});
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.peerDependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
});

test('Node 20 or later, an ES module, with the pqc-scan binary', () => {
  assert.equal(pkg.engines.node, '>=20');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.bin['pqc-scan'], 'bin/pqc-scan.mjs'); // no leading './': npm 11 drops such a bin entry at publish, silently losing npx
});

// Node 20's test runner does not expand globs, and its default discovery
// would treat every .js file under test/fixtures/ as a test and execute it.
// The fixtures are code to be scanned, never run, so the script lists each
// test file by name; this test keeps that list complete.
test('the test script names every test file, and nothing under fixtures', () => {
  const files = readdirSync(join(root, 'test')).filter((f) => f.endsWith('.test.mjs')).sort();
  const listed = pkg.scripts.test.split(/\s+/).filter((w) => w.startsWith('test/')).map((w) => w.slice(5)).sort();
  assert.deepEqual(listed, files);
  assert.ok(!pkg.scripts.test.includes('fixtures'));
});
