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
    assert.equal(r.out, `pqc-scan: ${report.summary.verdict}.\n`);
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
    [['a', 'b'], /give one directory to scan/],
    [['--json'], /--json/],
    [['--md', ''], /--md needs a file name/],
    [[join(FIXTURES, 'does-not-exist')], /cannot scan .*: no such directory/],
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
  assert.deepEqual(imports, ['node:fs', 'node:util', '../src/index.js']);
});
