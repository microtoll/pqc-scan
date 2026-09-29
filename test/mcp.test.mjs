// `pqc-scan mcp` (DESIGN.md §8.15): the Model Context Protocol server over a
// real child process, fed what a host sends; the one tool's result checked
// against the schema and against a scan through the library; its errors as
// tool results; the command's own arguments; and the registry listing kept
// in step with package.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, FIXTURES } from './helpers.mjs';
import { check } from './schema-check.mjs';
import { scan, createMcpServer, NOTICE, MCP_PROTOCOL_VERSION } from '../src/index.js';

const BIN = join(ROOT, 'bin', 'pqc-scan.mjs');
const SCHEMA = JSON.parse(readFileSync(join(ROOT, 'schema', 'pqc-scan.schema.json'), 'utf8'));
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const SERVER = JSON.parse(readFileSync(join(ROOT, 'server.json'), 'utf8'));

const INITIALIZE = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test-host', version: '0' } } };
const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' };
const call = (id, args, name = 'pqc_scan') => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

/** Runs `pqc-scan mcp` with these lines on standard input, then closes it; the replies by id. */
function session(messages, cwd = ROOT) {
  const input = messages.map((m) => (typeof m === 'string' ? m : JSON.stringify(m))).join('\n') + '\n';
  const r = spawnSync(process.execPath, [BIN, 'mcp'], { cwd, input, encoding: 'utf8' });
  const replies = r.stdout.split('\n').filter(Boolean).map((line) => JSON.parse(line));
  return { code: r.status, err: r.stderr, replies, byId: new Map(replies.map((m) => [m.id, m])) };
}

/** A report with its one varying field fixed, for comparing two scans. */
const settled = (report) => ({ ...report, scannedAt: 'fixed' });

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
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ['directory', 'exclude', 'testFiles']);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.ok(tool.description.includes('schema version 1') && tool.description.endsWith(NOTICE));
});

test('pqc_scan returns the JSON report: valid against the schema, and the same as a scan through the library', () => {
  const dir = join(FIXTURES, 'cli');
  const s = session([INITIALIZE, call(2, { directory: dir })]);
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
    call(2, { directory: 'cli' }),
    call(3, { directory: 'cli', exclude: ['high'] }),
    call(4, { directory: 'cli', testFiles: ['medium'] }),
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
