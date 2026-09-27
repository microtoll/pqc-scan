// The report (DESIGN.md §4, §8.7): the JSON against its published schema,
// the same report on every machine, what is walked and what is skipped, and
// Markdown that a scanned repository cannot write into.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { scan, toJson, toMarkdown, NOTICE, SCHEMA_VERSION } from '../src/index.js';
import { ROOT, FIXTURES, FIXED_NOW, scanFixture, lines } from './helpers.mjs';
import { check } from './schema-check.mjs';

const SCHEMA = JSON.parse(readFileSync(join(ROOT, 'schema', 'pqc-scan.schema.json'), 'utf8'));
const FIXTURE_SETS = ['webcrypto', 'node-crypto', 'traps', 'libraries', 'lockfiles', 'tls', 'cli', '.'];

/** A throwaway tree: { 'a/b.js': 'text' } → its directory. */
function tree(files) {
  const dir = mkdtempSync(join(tmpdir(), 'pqc-scan-test-'));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(join(dir, ...rel.split('/').slice(0, -1)), { recursive: true });
    writeFileSync(join(dir, ...rel.split('/')), text);
  }
  return dir;
}

test('every fixture report matches schema/pqc-scan.schema.json, version 1', () => {
  assert.equal(SCHEMA.properties.schema.const, SCHEMA_VERSION);
  assert.equal(SCHEMA.properties.notice.const, NOTICE);
  for (const set of FIXTURE_SETS) {
    const report = JSON.parse(toJson(scanFixture(set)));
    assert.deepEqual(check(SCHEMA, report), [], set);
  }
  // The checker is not a rubber stamp.
  const bad = JSON.parse(toJson(scanFixture('cli')));
  bad.findings[0].class = 'quantum';
  bad.findings[0].surprise = true;
  delete bad.summary.verdict;
  assert.equal(check(SCHEMA, bad).length, 3);
});

test('the summary counts agree with the lists they summarise', () => {
  const r = scanFixture('.');
  const s = r.summary;
  assert.equal(s.findings, r.findings.length);
  assert.equal(s.filesWithFindings, new Set(r.findings.map((f) => f.file)).size);
  assert.equal(s.quantumVulnerable.uses, r.findings.filter((f) => f.class === 'public-key').length);
  assert.equal(s.dynamic, r.findings.filter((f) => f.dynamic).length);
  assert.equal(s.libraries, r.dependencies.length);
  assert.equal(s.tls.configurations, r.tls.length);
  assert.equal(Object.values(s.byClass).reduce((a, b) => a + b, 0), r.findings.length);
  for (const p of ['high', 'medium', 'low']) {
    assert.equal(s.byPriority[p], r.findings.filter((f) => f.priority === p).length + r.tls.filter((t) => t.priority === p).length);
  }
  for (const f of r.findings) assert.equal(f.quantumVulnerable, f.class === 'public-key');
  assert.match(s.verdict, /^\d+ quantum-vulnerable public-key uses? in \d+ files?; \d+ librar(y|ies); /);
});

test('two scans of the same tree differ only in scannedAt; paths are relative with forward slashes; root is a name only (§8.7)', () => {
  const a = scan(FIXTURES, { now: FIXED_NOW });
  const b = scan(FIXTURES, { now: new Date('2030-01-01T00:00:00Z') });
  assert.notEqual(a.scannedAt, b.scannedAt);
  assert.deepEqual({ ...a, scannedAt: null }, { ...b, scannedAt: null });
  assert.equal(a.root, 'fixtures');
  const text = toJson(a);
  assert.ok(!text.includes(FIXTURES), 'no absolute path');
  assert.ok(!text.includes(FIXTURES.replace(/\\/g, '/')), 'no absolute path, in either spelling');
  const paths = [...a.findings.map((f) => f.file), ...a.tls.map((t) => t.file), ...a.dependencies.flatMap((d) => [...d.declaredIn, ...d.lockfiles, ...d.importedAt])];
  for (const p of paths) {
    assert.ok(!p.includes('\\') && !p.startsWith('/') && !/^[A-Za-z]:/.test(p), p);
  }
  // Sorted by file, then line, then column (DESIGN.md §8.7).
  const keys = a.findings.map((f) => [f.file, f.line, f.column]);
  const sorted = [...keys].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] - y[1] || x[2] - y[2]));
  assert.deepEqual(keys, sorted);
  assert.deepEqual(a.dependencies.map((d) => d.name), [...a.dependencies.map((d) => d.name)].sort());
});

test('test code is scanned and marked, not hidden; node_modules and .git are never walked; --exclude skips (§8.7)', () => {
  const call = "export const h = () => crypto.subtle.digest('SHA-256', new Uint8Array(1));\n";
  const dir = tree({
    'src/app.js': call,
    'src/app.test.js': call,
    'test/tooling/compose.mjs': call,
    '__tests__/x.js': call,
    'node_modules/pkg/index.js': call,
    '.git/hooks/pre-commit.js': call,
    'vendor/lib.js': call,
    'src/generated/out.js': call,
  });
  try {
    const r = scan(dir, { now: FIXED_NOW, exclude: ['vendor', 'src/generated/'] });
    assert.deepEqual(r.findings.map((f) => `${f.file} ${f.inTest}`), [
      '__tests__/x.js true',
      'src/app.js false',
      'src/app.test.js true',
      'test/tooling/compose.mjs true',
    ]);
    assert.equal(r.summary.findingsInTests, 3);
    assert.deepEqual(r.skipped, [], 'never walked is not the same as skipped');
    assert.equal(r.root, basename(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('files over 2 MB, binary files and symbolic links are skipped and listed (§8.7)', (t) => {
  const dir = tree({
    'big.js': `// ${'x'.repeat(2 * 1024 * 1024)}\n`,
    'blob.js': 'crypto.subtle.digest("SHA-1", d)\u0000\u0001',
    'ok.js': "crypto.subtle.digest('SHA-256', d);\n",
    'outside/secret.js': "crypto.subtle.digest('MD5', d);\n",
  });
  try {
    let linked = true;
    // A directory junction needs no special rights on Windows; elsewhere, a symbolic link.
    try { symlinkSync(join(dir, 'outside'), join(dir, 'link'), process.platform === 'win32' ? 'junction' : 'dir'); } catch { linked = false; }
    const r = scan(dir, { now: FIXED_NOW, exclude: ['outside'] });
    const expected = [
      { path: 'big.js', reason: 'larger than 2 MB' },
      { path: 'blob.js', reason: 'binary' },
    ];
    if (linked) expected.push({ path: 'link', reason: 'symbolic link, not followed' });
    else t.diagnostic('could not make a symbolic link here; that case was not checked');
    assert.deepEqual(r.skipped, expected);
    assert.deepEqual(lines(r), ['ok.js:1 SHA-256 [digest]']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('evidence is the trimmed source line, cut at 200 characters (§8.7)', () => {
  const dir = tree({ 'long.js': `    const h = crypto.subtle.digest('SHA-256', d); // ${'y'.repeat(400)}\n` });
  try {
    const [f] = scan(dir, { now: FIXED_NOW }).findings;
    assert.equal(f.evidence.length, 200);
    assert.ok(f.evidence.startsWith("const h = crypto.subtle.digest('SHA-256'"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the Markdown has the eight sections in order, the notice, and every priority entry (§4)', () => {
  const r = scanFixture('.');
  const md = toMarkdown(r);
  const headings = md.split('\n').filter((l) => l.startsWith('## '));
  assert.deepEqual(headings, [
    '## 1. Summary',
    '## 2. What you use, where',
    '## 3. Quantum-vulnerable public-key uses, with a priority',
    '## 4. Symmetric, hash and other notes',
    '## 5. Dependencies',
    '## 6. TLS',
    '## 7. Next steps',
    '## 8. What this report cannot see',
  ]);
  assert.ok(md.includes(`**${NOTICE}**`));
  assert.ok(md.trimEnd().endsWith(`*${NOTICE}*`));
  assert.ok(md.includes(`${r.summary.verdict}.`));
  assert.ok(md.includes('Grover'), 'the AES-128 note');
  assert.ok(md.includes('OpenSSL 3.5'), 'the unstated-groups note');
  // Every priority entry appears in section 3 with its file:line.
  const section3 = md.slice(md.indexOf('## 3.'), md.indexOf('## 4.'));
  for (const f of r.findings.filter((x) => x.priority)) assert.ok(section3.includes(`\`${f.file}:${f.line}\``), `${f.file}:${f.line}`);
  for (const t of r.tls.filter((x) => x.priority)) assert.ok(section3.includes(`\`${t.file}:${t.line}\``), `${t.file}:${t.line}`);
  // Every table row has as many cells as its header.
  for (const table of md.split('\n\n').filter((b) => b.startsWith('| '))) {
    const rows = table.split('\n');
    const width = cells(rows[0]).length;
    for (const row of rows) assert.equal(cells(row).length, width, row);
  }
});

test('the Markdown of an empty directory says so, and still carries the notice and the limits', () => {
  const dir = tree({ 'README.txt': 'nothing to scan' });
  try {
    const md = toMarkdown(scan(dir, { now: FIXED_NOW }));
    assert.ok(md.includes('No cryptographic calls were found'));
    assert.ok(md.includes('No catalogued cryptographic library'));
    assert.ok(md.includes('No TLS configuration was found'));
    assert.equal((md.match(/None found\./g) ?? []).length, 3);
    assert.ok(md.includes('It runs nothing it scans'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a scanned repository cannot write links, HTML or table cells into the Markdown', () => {
  const hostile = [
    "export const s = (k, d) => crypto.subtle.sign('Ed25519', k, d); // | [click](https://evil.example) <img src=x onerror=alert(1)> ``` `tick` **bold** |",
    '',
  ].join('\n');
  // Brackets and parentheses are legal in a file name on every platform; a pipe is not on Windows.
  const dir = tree({ 'src/[x](evil).js': hostile });
  try {
    const md = toMarkdown(scan(dir, { now: FIXED_NOW }));
    const section3 = md.slice(md.indexOf('## 3.'), md.indexOf('## 4.'));
    const row = section3.split('\n').find((l) => l.startsWith('| Ed25519'));
    assert.ok(row, 'the Medium entry is there');
    assert.equal(cells(row).length, 5, 'no extra table cells');
    // The evidence is one code span whose fence is longer than any backtick run inside it.
    const evidence = cells(row)[4];
    assert.match(evidence, /^````.*````$/);
    // Outside code spans, nothing is left that would render as a link or HTML.
    // A code span: a backtick run, then content, then a run of the same length (CommonMark §6.1).
    const outsideCode = md.replace(/(`+)([\s\S]*?[^`])\1(?!`)/g, '');
    assert.ok(!/(^|[^\\])\[[^\]]*\]\(/.test(outsideCode), 'no link');
    assert.ok(!/(^|[^\\])<img/i.test(outsideCode), 'no HTML');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** The cells of a table row, split at pipes that are not escaped. */
function cells(row) {
  return row.trim().replace(/^\|/, '').replace(/\|$/, '').split(/(?<!\\)\|/).map((c) => c.trim());
}
