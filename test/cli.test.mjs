// The command line (DESIGN.md §7, §8.7): its outputs, its thresholds and
// its exit codes — 0 done, 1 the --fail-on threshold was met, 2 a usage or
// read error. Each case runs the real binary in a child process.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, FIXTURES } from './helpers.mjs';
import { check } from './schema-check.mjs';

const BIN = join(ROOT, 'bin', 'pqc-scan.mjs');
const SCHEMA = JSON.parse(readFileSync(join(ROOT, 'schema', 'pqc-scan.schema.json'), 'utf8'));
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

function run(args, cwd = ROOT) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function inTemp(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'pqc-scan-cli-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('with neither --json nor --md: the Markdown on standard output, nothing written to disk', () => {
  inTemp((cwd) => {
    const r = run([join(FIXTURES, 'cli')], cwd);
    assert.equal(r.code, 0);
    assert.match(r.out, /^# Post-quantum cryptography inventory: cli\n/);
    assert.ok(r.out.includes('## 8. What this report cannot see'));
    assert.equal(r.err, '');
    assert.deepEqual(readdirSync(cwd), []);
  });
});

test('--json and --md write both reports; the JSON matches the schema; standard output carries the verdict', () => {
  inTemp((dir) => {
    const json = join(dir, 'pqc-scan.json');
    const md = join(dir, 'pqc-scan.md');
    const r = run([join(FIXTURES, 'cli'), '--json', json, '--md', md]);
    assert.equal(r.code, 0);
    const report = JSON.parse(readFileSync(json, 'utf8'));
    assert.deepEqual(check(SCHEMA, report), []);
    // The four-line summary (§8.13): the verdict, the counts, and where the two files are.
    assert.equal(r.out.split('\n')[0], `pqc-scan: ${report.summary.verdict}.`);
    assert.ok(r.out.includes(`  Report: ${md}`) && r.out.includes(`  JSON:   ${json}`));
    assert.match(readFileSync(md, 'utf8'), /^# Post-quantum cryptography inventory: cli\n/);
    // Either alone writes only that one.
    const onlyJson = join(dir, 'only.json');
    assert.equal(run([join(FIXTURES, 'cli'), '--json', onlyJson]).code, 0);
    assert.deepEqual(readdirSync(dir).sort(), ['only.json', 'pqc-scan.json', 'pqc-scan.md']);
  });
});

test('--fail-on: high fails on a High only; medium fails on a High or a Medium; the reports are still written', () => {
  const cases = [
    ['high', 'high', 1], ['medium', 'high', 0], ['clean', 'high', 0],
    ['high', 'medium', 1], ['medium', 'medium', 1], ['clean', 'medium', 0],
  ];
  for (const [dir, threshold, code] of cases) {
    const r = run([join(FIXTURES, 'cli', dir), '--fail-on', threshold]);
    assert.equal(r.code, code, `${dir} --fail-on ${threshold}`);
    assert.match(r.out, /^# Post-quantum cryptography inventory/, 'the report is written either way');
    if (code === 1) assert.match(r.err, new RegExp(`--fail-on ${threshold}: \\d+ entr(y is|ies are) at that priority or above`));
  }
  inTemp((dir) => {
    const json = join(dir, 'r.json');
    assert.equal(run([join(FIXTURES, 'cli'), '--json', json, '--fail-on', 'high']).code, 1);
    assert.equal(JSON.parse(readFileSync(json, 'utf8')).summary.byPriority.high, 2);
  });
});

test('--write (what a terminal gets by default) puts pqc-scan.md and pqc-scan.json in the current folder and prints a summary (§8.13)', () => {
  inTemp((cwd) => {
    const r = run([join(FIXTURES, 'cli'), '--write'], cwd);
    assert.equal(r.code, 0);
    assert.deepEqual(readdirSync(cwd).sort(), ['pqc-scan.json', 'pqc-scan.md']);
    const report = JSON.parse(readFileSync(join(cwd, 'pqc-scan.json'), 'utf8'));
    const lines = r.out.trimEnd().split('\n');
    assert.equal(lines.length, 4);
    assert.equal(lines[0], `pqc-scan: ${report.summary.verdict}.`);
    assert.match(lines[1], /^  \d+ files read; 2 High, 1 Medium, 0 Low; 0 to check by hand\.$/);
    assert.equal(lines[2], `  Report: ${join(cwd, 'pqc-scan.md')}  (open it; read sections 1 and 3 first)`);
    assert.equal(lines[3], `  JSON:   ${join(cwd, 'pqc-scan.json')}`);
    assert.equal(r.err, '');
    // Piped with nothing named (as these tests run it), the Markdown still goes to standard output and nothing is written.
  });
});

test('--test-files marks files whose path contains the text as test code (§8.13)', () => {
  inTemp((cwd) => {
    const plain = JSON.parse(run([join(FIXTURES, 'cli'), '--json', join(cwd, 'a.json')]).out ? readFileSync(join(cwd, 'a.json'), 'utf8') : readFileSync(join(cwd, 'a.json'), 'utf8'));
    assert.equal(plain.summary.findingsInTests, 0);
    assert.equal(run([join(FIXTURES, 'cli'), '--json', join(cwd, 'b.json'), '--test-files', 'seal.js', '--test-files', 'util'], cwd).code, 0);
    const marked = JSON.parse(readFileSync(join(cwd, 'b.json'), 'utf8'));
    assert.equal(marked.summary.findingsInTests, marked.findings.filter((f) => f.file.includes('seal.js') || f.file.includes('util')).length);
    assert.ok(marked.summary.findingsInTests > 0);
    assert.ok(marked.findings.every((f) => f.inTest === (f.file.includes('seal.js') || f.file.includes('util'))));
  });
});

test('--exclude leaves a directory out', () => {
  const r = run([join(FIXTURES, 'cli'), '--exclude', 'high', '--fail-on', 'high']);
  assert.equal(r.code, 0);
  assert.ok(!r.out.includes('high/seal.js'));
  assert.ok(r.out.includes('medium/sign.js'));
});

test('usage and read errors exit 2 and say why on standard error', () => {
  const cases = [
    [['--fail-on', 'low'], /--fail-on takes high or medium, not "low"/],
    [['--frobnicate'], /Unknown option '--frobnicate'/],
    [['a', 'b'], /give one folder to scan/],
    [['--test-files', ''], /--test-files needs some text/],
    [['--json'], /--json/],
    [['--md', ''], /--md needs a file name/],
    [[join(FIXTURES, 'does-not-exist')], /cannot scan .*: no such folder/],
    [[join(FIXTURES, 'cli', 'clean', 'util.js')], /cannot scan .*: not a directory/],
  ];
  for (const [args, message] of cases) {
    const r = run(args);
    assert.equal(r.code, 2, args.join(' '));
    assert.match(r.err, message);
    assert.equal(r.out, '');
  }
  inTemp((dir) => {
    const r = run([join(FIXTURES, 'cli'), '--json', join(dir, 'no', 'such', 'dir', 'r.json')]);
    assert.equal(r.code, 2);
    assert.match(r.err, /cannot write the report/);
  });
});

test('--help and --version', () => {
  const help = run(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, /^Usage: pqc-scan \[dir\] \[options\]/);
  assert.match(help.out, /not a compliance certificate/);
  assert.deepEqual(run(['--version']), { code: 0, out: `${PKG.version}\n`, err: '' });
});

test('the command line uses only the public API', () => {
  const imports = [...readFileSync(BIN, 'utf8').matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['node:fs', 'node:path', 'node:util', '../src/index.js']);
});
