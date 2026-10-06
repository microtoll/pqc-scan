// `pqc-scan mcp` (DESIGN.md §8.15): the Model Context Protocol server over a
// real child process, fed what a host sends; the one tool's full result
// checked against the schema and against a scan through the library, and its
// summary against the report it is cut from; its errors as
// tool results; its title and behaviour hints, and the behaviour behind them
// (DESIGN.md §8.17); the command's own arguments; and the registry listing
// kept in step with package.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, FIXTURES } from './helpers.mjs';
import { check } from './schema-check.mjs';
import { scan, createMcpServer, NOTICE, MCP_PROTOCOL_VERSION } from '../src/index.js';
import { agentSummary, PLACES_PER_GROUP, PLACES_IN_ALL } from '../src/mcp.js';

const BIN = join(ROOT, 'bin', 'pqc-scan.mjs');
const SCHEMA = JSON.parse(readFileSync(join(ROOT, 'schema', 'pqc-scan.schema.json'), 'utf8'));
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const SERVER = JSON.parse(readFileSync(join(ROOT, 'server.json'), 'utf8'));

const INITIALIZE = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test-host', version: '0' } } };
const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' };
const call = (id, args, name = 'pqc_scan') => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

/** Runs `pqc-scan mcp` with these lines on standard input, then closes it; the replies by id. Node's own options, if any, go before the script. */
function session(messages, cwd = ROOT, nodeOptions = []) {
  const input = messages.map((m) => (typeof m === 'string' ? m : JSON.stringify(m))).join('\n') + '\n';
  const r = spawnSync(process.execPath, [...nodeOptions, BIN, 'mcp'], { cwd, input, encoding: 'utf8' });
  const replies = r.stdout.split('\n').filter(Boolean).map((line) => JSON.parse(line));
  return { code: r.status, err: r.stderr, replies, byId: new Map(replies.map((m) => [m.id, m])) };
}

/** A report with its one varying field fixed, for comparing two scans. */
const settled = (report) => ({ ...report, scannedAt: 'fixed' });

// Node's permission model with reading allowed and no --allow-fs-write: any
// attempt to write a file throws ERR_ACCESS_DENIED, and starting a child
// process is refused too. The switch is --permission from Node 22.13 and
// 23.5, and --experimental-permission before, as on Node 20, which CI runs.
const [NODE_MAJOR, NODE_MINOR] = process.versions.node.split('.').map(Number);
const PERMISSION = NODE_MAJOR > 23 || (NODE_MAJOR === 23 && NODE_MINOR >= 5) || (NODE_MAJOR === 22 && NODE_MINOR >= 13) ? '--permission' : '--experimental-permission';
const READ_ONLY = [PERMISSION, '--allow-fs-read=*'];

test('a host\'s handshake: the protocol version, the server\'s name and package version, the notice in the instructions', () => {
  const s = session([INITIALIZE, INITIALIZED, { jsonrpc: '2.0', id: 2, method: 'ping' }]);
  assert.equal(s.code, 0);
  assert.equal(s.err, '', 'nothing on standard error when a host, not a person, is on standard input');
  assert.equal(s.replies.length, 2, 'a notification gets no reply');
  const init = s.byId.get(1).result;
  assert.equal(init.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.deepEqual(init.serverInfo, { name: 'pqc-scan', version: PKG.version });
  assert.deepEqual(init.capabilities, { tools: { listChanged: false } });
  assert.ok(init.instructions.includes('pqc_scan') && init.instructions.includes(NOTICE));
  assert.deepEqual(s.byId.get(2).result, {});
});

test('tools/list: one tool, pqc_scan, which needs a directory and says what it is', () => {
  const { tools } = session([INITIALIZE, { jsonrpc: '2.0', id: 2, method: 'tools/list' }]).byId.get(2).result;
  assert.deepEqual(tools.map((t) => t.name), ['pqc_scan']);
  const [tool] = tools;
  assert.deepEqual(tool.inputSchema.required, ['directory']);
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ['detail', 'directory', 'exclude', 'testFiles']);
  assert.deepEqual(tool.inputSchema.properties.detail.enum, ['summary', 'full']);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.ok(tool.description.includes('schema version 1') && tool.description.endsWith(NOTICE));
  // The title and behaviour hints (MCP specification 2025-06-18,
  // "ToolAnnotations"). Exactly these keys: a misspelt hint would be ignored
  // by a host, which would then fall back on the specification's defaults.
  const title = 'List the cryptography a codebase uses';
  assert.equal(tool.title, title);
  assert.deepEqual(tool.annotations, { title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
  assert.ok(!('handler' in tool), 'the handler never goes out on the wire');
});

test('readOnlyHint and idempotentHint: with every file write forbidden, the tool gives the same answers, and a repeat call the same again', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pqc-scan-readonly-'));
  try {
    // The control: the same options do refuse a write, so the test is real.
    const write = spawnSync(process.execPath, [...READ_ONLY, '-e', "require('node:fs').writeFileSync('x.txt', 'x')"], { cwd, encoding: 'utf8' });
    assert.notEqual(write.status, 0);
    assert.match(write.stderr, /ERR_ACCESS_DENIED/);
    const dir = join(FIXTURES, 'cli');
    const calls = [INITIALIZE, call(2, { directory: dir, detail: 'full' }), call(3, { directory: dir }), call(4, { directory: dir, detail: 'full' })];
    const free = session(calls, cwd);
    const held = session(calls, cwd, READ_ONLY);
    const result = (s, id) => {
      const r = s.byId.get(id).result;
      assert.equal(r.isError, false, r.content[0].text);
      return settled(JSON.parse(r.content[0].text));
    };
    assert.ok(result(held, 2).findings.length > 0, 'the fixtures hold findings');
    for (const id of [2, 3]) assert.deepEqual(result(held, id), result(free, id));
    assert.deepEqual(result(held, 4), result(held, 2), 'a repeat call, the same answer');
    assert.deepEqual(readdirSync(cwd), [], 'nothing written, in either run');
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test('openWorldHint false: no source file imports anything that could reach the network or start a program', () => {
  // A tripwire: Node's permission model cannot forbid network access, so
  // this reads the code. Static imports only: the scanner's own rules hold
  // `require(` and `import(` as text to look for in the code it scans.
  const ALLOWED = new Set(['node:fs', 'node:path', 'node:crypto', 'node:util']);
  const files = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(dir, e.name));
      else if (/\.m?js$/.test(e.name)) files.push(join(dir, e.name));
    }
  };
  walk(join(ROOT, 'src'));
  walk(join(ROOT, 'bin'));
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const specifiers = [
      ...text.matchAll(/^\s*(?:import|export)\b[^;'"]*?\bfrom\s+['"]([^'"]+)['"]/gm),
      ...text.matchAll(/^\s*import\s+['"]([^'"]+)['"]/gm),
    ].map((m) => m[1]);
    for (const s of specifiers) {
      assert.ok(s.startsWith('.') || ALLOWED.has(s), `${file} imports ${s}: decide openWorldHint and readOnlyHint again`);
    }
    assert.doesNotMatch(text, /\bfetch\s*\(|\bWebSocket\b/, `${file}: fetch or a socket`);
  }
  assert.ok(files.length > 10, 'the source was found');
});

test('pqc_scan with detail "full" returns the JSON report: valid against the schema, and the same as a scan through the library', () => {
  const dir = join(FIXTURES, 'cli');
  const s = session([INITIALIZE, call(2, { directory: dir, detail: 'full' })]);
  const { content, isError } = s.byId.get(2).result;
  assert.equal(isError, false);
  assert.equal(content.length, 1);
  assert.equal(content[0].type, 'text');
  assert.ok(!content[0].text.includes('\n'), 'compact JSON, without indentation');
  const report = JSON.parse(content[0].text);
  assert.deepEqual(check(SCHEMA, report), []);
  assert.deepEqual(settled(report), settled(JSON.parse(JSON.stringify(scan(dir)))));
  assert.equal(report.summary.byPriority.high, 2);
});

test('pqc_scan: a relative directory is from the server\'s own folder; exclude and testFiles reach the scan', () => {
  const s = session([
    INITIALIZE,
    call(2, { directory: 'cli', detail: 'full' }),
    call(3, { directory: 'cli', exclude: ['high'], detail: 'full' }),
    call(4, { directory: 'cli', testFiles: ['medium'], detail: 'full' }),
  ], FIXTURES);
  const report = (id) => JSON.parse(s.byId.get(id).result.content[0].text);
  assert.equal(report(2).root, 'cli');
  assert.equal(report(2).summary.byPriority.high, 2);
  assert.equal(report(3).summary.byPriority.high, 0);
  assert.deepEqual(settled(report(3)), settled(JSON.parse(JSON.stringify(scan(join(FIXTURES, 'cli'), { exclude: ['high'] })))));
  assert.ok(report(4).findings.filter((f) => f.file.startsWith('medium/')).every((f) => f.inTest));
  assert.ok(report(4).findings.some((f) => f.file.startsWith('medium/')));
});

test('pqc_scan\'s failures are tool results for the agent to read, not protocol errors', () => {
  const s = session([
    INITIALIZE,
    call(2, {}),
    call(3, { directory: '' }),
    call(4, { directory: join(FIXTURES, 'no-such-folder') }),
    call(5, { directory: join(FIXTURES, 'cli', 'high', 'seal.js') }),
    call(6, { directory: FIXTURES, exclude: 'cli' }),
    call(7, { directory: FIXTURES, testFiles: [''] }),
    call(8, { directory: FIXTURES, detail: 'brief' }),
  ]);
  const text = (id) => {
    const { result } = s.byId.get(id);
    assert.equal(result.isError, true, `call ${id}`);
    return result.content[0].text;
  };
  assert.match(text(2), /^directory: give the folder to scan/);
  assert.match(text(3), /^directory: give the folder to scan/);
  assert.match(text(4), /no-such-folder .*: no such folder$/);
  assert.match(text(5), /not a directory/);
  assert.match(text(6), /^exclude: give a list of non-empty texts/);
  assert.match(text(7), /^testFiles: give a list of non-empty texts/);
  assert.match(text(8), /^detail: give summary or full/);
});

test('pqc_scan returns a summary by default: the report\'s counts, every use accounted for, the uses to review with their places, no source lines', () => {
  for (const name of ['cli', 'libraries', 'node-crypto']) {
    const dir = join(FIXTURES, name);
    const s = session([INITIALIZE, call(2, { directory: dir })]);
    const { content, isError } = s.byId.get(2).result;
    assert.equal(isError, false);
    assert.ok(!content[0].text.includes('\n'), 'compact JSON, without indentation');
    const got = JSON.parse(content[0].text);
    const report = JSON.parse(JSON.stringify(scan(dir)));
    assert.deepEqual(settled(got), settled(agentSummary(report)), name);
    assert.equal(got.view, 'summary');
    assert.deepEqual(got.summary, report.summary);
    const uses = (groups) => groups.reduce((n, g) => n + g.uses, 0);
    assert.equal(uses(got.toReview) + uses(got.counted), report.summary.findings, `${name}: every use in one group`);
    const places = new Set(report.findings.filter((f) => f.priority !== null || f.dynamic || f.notes.length).map((f) => `${f.file}:${f.line}`));
    for (const g of got.toReview) {
      assert.ok(g.at.every((p) => places.has(p)), `${name}: ${g.algorithm} at places the report has`);
      assert.equal(g.at.length + g.more, g.uses);
    }
    const ranks = got.toReview.filter((g) => !g.inTest).map((g) => ({ high: 0, medium: 1, low: 2 })[g.priority] ?? 3);
    assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b), `${name}: high first`);
    for (const f of report.findings) assert.ok(!content[0].text.includes(JSON.stringify(f.evidence)), `${name}: no source line`);
  }
});

test(`the summary lists at most ${PLACES_PER_GROUP} places a group and ${PLACES_IN_ALL} in all, the most urgent groups first, and counts the rest`, () => {
  const report = JSON.parse(JSON.stringify(scan(join(FIXTURES, 'cli'))));
  const [high] = report.findings.filter((f) => f.priority === 'high');
  const [medium] = report.findings.filter((f) => f.priority === 'medium');
  const many = (f, n, algorithm) => Array.from({ length: n }, (_, i) => ({ ...f, algorithm, file: `a/${algorithm}.js`, line: i + 1 }));
  // The medium groups come first in the findings, as a file sorted early would.
  const findings = [];
  for (let i = 0; i < 30; i++) findings.push(...many(medium, 25, `M${i}`));
  findings.push(...many(high, 25, 'H'));
  const got = agentSummary({ ...report, findings });
  assert.equal(got.toReview[0].algorithm, 'H');
  assert.equal(got.toReview[0].at.length, PLACES_PER_GROUP);
  assert.equal(got.toReview[0].more, 25 - PLACES_PER_GROUP);
  assert.equal(got.toReview.reduce((n, g) => n + g.at.length, 0), PLACES_IN_ALL);
  assert.ok(got.toReview.every((g) => g.at.length + g.more === g.uses));
  assert.deepEqual(got.toReview.at(-1).at, [], 'the last groups keep their count and lose their places');
});

test('protocol errors: an unknown tool, an unknown method, a line that is not JSON; the session carries on', () => {
  const s = session([INITIALIZE, call(2, {}, 'pqc_sacn'), { jsonrpc: '2.0', id: 3, method: 'resources/list' }, 'not json', { jsonrpc: '2.0', id: 4, method: 'ping' }]);
  assert.equal(s.byId.get(2).error.code, -32602);
  assert.equal(s.byId.get(3).error.code, -32601);
  assert.equal(s.byId.get(null).error.code, -32700);
  assert.deepEqual(s.byId.get(4).result, {});
});

test('the server writes nothing to disk, and standard output carries nothing but the protocol', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'pqc-scan-mcp-'));
  try {
    const s = session([INITIALIZE, call(2, { directory: join(FIXTURES, 'cli') }), call(3, { directory: 'nothing-here' })], cwd);
    assert.equal(s.replies.length, 3);
    assert.ok(s.replies.every((m) => m.jsonrpc === '2.0'));
    assert.deepEqual(readdirSync(cwd), []);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test('the command: pqc-scan mcp takes nothing after it; a folder named mcp is scanned as ./mcp or after --', () => {
  const r = spawnSync(process.execPath, [BIN, 'mcp', '--json', 'x.json'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /pqc-scan mcp takes nothing after it; to scan a folder named mcp, give \.\/mcp/);
  const cwd = mkdtempSync(join(tmpdir(), 'pqc-scan-mcp-'));
  try {
    mkdirSync(join(cwd, 'mcp'));
    copyFileSync(join(FIXTURES, 'cli', 'high', 'seal.js'), join(cwd, 'mcp', 'seal.js'));
    for (const args of [['./mcp'], ['--', 'mcp'], ['--fail-on', 'high', '--', 'mcp']]) {
      const s = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8' });
      assert.match(s.stdout, /^# Post-quantum cryptography inventory: mcp\n/, args.join(' '));
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test('the library: createMcpServer answers the same as the command, with no streams', async () => {
  const server = createMcpServer();
  const init = await server.handle(INITIALIZE);
  assert.equal(init.result.serverInfo.version, PKG.version);
  const reply = await server.handle(call(2, { directory: join(FIXTURES, 'cli', 'clean') }));
  assert.equal(JSON.parse(reply.result.content[0].text).summary.findings, 0);
  assert.equal(await server.handle(INITIALIZED), null);
});

test('the registry listing (server.json) is in step with package.json, and starts the server with "mcp"', () => {
  assert.equal(SERVER.name, PKG.mcpName);
  assert.equal(SERVER.name, 'io.github.microtoll/pqc-scan');
  assert.equal(SERVER.version, PKG.version);
  assert.ok(SERVER.description.length <= 100, 'the registry allows 100 characters');
  assert.equal(SERVER.repository.url, PKG.homepage.replace(/#readme$/, ''));
  const [npm, ...others] = SERVER.packages;
  assert.equal(others.length, 0);
  assert.equal(npm.registryType, 'npm');
  assert.equal(npm.identifier, PKG.name);
  assert.equal(npm.version, PKG.version);
  assert.deepEqual(npm.transport, { type: 'stdio' });
  assert.deepEqual(npm.packageArguments, [{ type: 'positional', value: 'mcp' }]);
});
