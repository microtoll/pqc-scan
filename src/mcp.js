// `pqc-scan mcp` (DESIGN.md §8.15): the scanner as a Model Context Protocol
// server over standard input and output, with one tool, `pqc_scan`, whose
// result is a summary of the JSON report (schema version 1), or the whole
// report when asked for, so a coding agent can check
// the cryptography it has just written. The tool reads files only: it writes
// nothing, runs nothing it scans and sends nothing anywhere; the report goes
// back to the host that asked for it, and nowhere else.
import { resolve } from 'node:path';
import { createServer, PROTOCOL_VERSION } from './mcp-protocol.js';
import { scan } from './scan.js';
import { NOTICE, TOOL_VERSION } from './report.js';

export { PROTOCOL_VERSION as MCP_PROTOCOL_VERSION };

export const MCP_INSTRUCTIONS = [
  'pqc-scan: an inventory of the cryptography a JavaScript or TypeScript codebase uses, and which of it a large quantum computer would break.',
  'Call pqc_scan after adding or changing cryptographic code, and consider the replacement it names for anything at high or medium priority.',
  'It reads files only. The report holds source lines as evidence.',
  NOTICE,
].join(' ');

const STRINGS = { type: 'array', items: { type: 'string', minLength: 1 } };
const DETAILS = ['summary', 'full'];

/**
 * The tool carries a `title` and `annotations`: the behaviour hints of the
 * Model Context Protocol specification ("ToolAnnotations", the same in
 * versions 2025-06-18, which this server speaks, 2025-11-25 and 2026-07-28;
 * DESIGN.md §8.17). A host may use them to decide whether to ask the person
 * before a call. They are set from what the code does, and
 * test/mcp.test.mjs checks that behaviour:
 *   readOnlyHint     true: scan.js only lists, inspects and reads files;
 *                    the command line's report writing is never reached
 *                    from here
 *   destructiveHint  false: it neither deletes nor overwrites anything
 *   idempotentHint   true: a repeat call changes nothing further
 *   openWorldHint    false: no network; it reads the folder it is given,
 *                    and follows no symbolic link out of it
 * The specification reads destructiveHint and idempotentHint only when
 * readOnlyHint is false. All four are given anyway, so that a host never
 * falls back on its defaults (may destroy, not idempotent, open world).
 * The title is given twice on purpose: a host reads `title` first, then
 * `annotations.title` (the specification's order); version 2025-03-26 had
 * only the second.
 */
const TITLE = 'List the cryptography a codebase uses';

export function mcpTools() {
  return [
    {
      name: 'pqc_scan',
      title: TITLE,
      annotations: { title: TITLE, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      description: [
        'Scans a JavaScript or TypeScript codebase for the cryptography it uses (Web Crypto, node:crypto, catalogued libraries, TLS configuration, lockfiles)',
        'and returns the report as JSON, pqc-scan schema version 1: each finding with its algorithm, key size or curve, file and line, whether a large quantum computer would break it,',
        'a migration priority (high, medium or low) with the reason, and a replacement to consider; then the dependencies, the TLS configurations and a summary.',
        'An algorithm name the code does not write down is marked dynamic, to check by hand. Reads files only: writes nothing and runs nothing.',
        'By default it returns a summary instead: the counts, each use to review grouped by algorithm with its files and lines, and the rest counted;',
        'detail "full" returns the whole report, with every use and its source line, which on a large codebase can pass the host\'s limit on a tool result, so scan the folder you changed, or skip folders with exclude.',
        NOTICE,
      ].join(' '),
      inputSchema: {
        type: 'object',
        properties: {
          directory: { type: 'string', minLength: 1, description: 'The folder to scan: an absolute path, or one relative to the folder this server was started in. node_modules and .git are never read.' },
          exclude: { ...STRINGS, description: 'Folder or file names, or paths from the scanned folder, to skip.' },
          testFiles: { ...STRINGS, description: 'Texts; a file whose path contains one is marked as test code, besides test, tests, __tests__, spec and .test./.spec. names.' },
          detail: { type: 'string', enum: DETAILS, description: 'summary (the default): the counts, the uses to review grouped with their files and lines, the rest counted. full: the whole JSON report, every use with its source line.' },
        },
        required: ['directory'],
        additionalProperties: false,
      },
      handler: pqcScanTool,
    },
  ];
}

/** The tool: the arguments checked as the command line checks its own, then one scan. */
function pqcScanTool({ directory, exclude = [], testFiles = [], detail = 'summary' }) {
  if (typeof directory !== 'string' || directory === '') return { text: 'directory: give the folder to scan', isError: true };
  if (!DETAILS.includes(detail)) return { text: `detail: give ${DETAILS.join(' or ')}`, isError: true };
  for (const [name, list] of [['exclude', exclude], ['testFiles', testFiles]]) {
    if (!Array.isArray(list) || list.some((s) => typeof s !== 'string' || s === '')) return { text: `${name}: give a list of non-empty texts`, isError: true };
  }
  let report;
  try {
    report = scan(directory, { exclude, testFiles });
  } catch (err) {
    const why = err.code === 'ENOENT' ? 'no such folder' : err.message;
    return { text: `cannot scan ${directory} (${resolve(directory)}): ${why}`, isError: true };
  }
  // Compact: without the indentation, which is a quarter of the length and
  // costs the agent's context. The full report is the document --json writes.
  return JSON.stringify(detail === 'full' ? report : agentSummary(report));
}

/** The places listed for one group of uses to review, and for all of them; the rest are counted. */
export const PLACES_PER_GROUP = 20;
export const PLACES_IN_ALL = 400;

const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };

/**
 * The tool's default result (§8.15): the report cut to what an agent acts
 * on. A whole report passed Claude Code's limit on a tool result ten times
 * over on a 366-file application, most of it one random-number call
 * repeated. Uses to review (a priority, a name that could not be read, or a
 * note) are grouped by what would be done about them, with their places;
 * the rest are counted by algorithm. Everything in it is taken from the
 * report, so it can say nothing the report does not.
 */
export function agentSummary(report) {
  const review = new Map();
  const counted = new Map();
  for (const f of report.findings) {
    const toReview = f.priority !== null || f.dynamic || f.notes.length > 0;
    const key = JSON.stringify(toReview
      ? [f.algorithm, f.class, f.priority, f.replacement, f.notes.map((n) => n.code), f.inTest]
      : [f.algorithm, f.class, f.inTest]);
    const groups = toReview ? review : counted;
    if (!groups.has(key)) {
      groups.set(key, toReview
        ? { algorithm: f.algorithm, class: f.class, priority: f.priority, replacement: f.replacement, notes: f.notes.map((n) => n.text), inTest: f.inTest, uses: 0, files: new Set(), reasons: new Set(), at: [] }
        : { algorithm: f.algorithm, class: f.class, inTest: f.inTest, uses: 0, files: new Set() });
    }
    const g = groups.get(key);
    g.uses += 1;
    g.files.add(f.file);
    if (toReview) {
      if (f.priorityReason) g.reasons.add(f.priorityReason);
      g.at.push(`${f.file}:${f.line}`);
    }
  }
  // The places are given out in the order the groups are listed, the most
  // urgent first, so a cut falls on test code and uses without a priority.
  let places = PLACES_IN_ALL;
  const settle = ({ files, reasons, at, ...g }) => {
    const listed = at && at.slice(0, Math.min(PLACES_PER_GROUP, places));
    if (listed) places -= listed.length;
    return {
      ...g,
      files: files.size,
      ...(reasons && { reasons: [...reasons] }),
      ...(listed && { at: listed, more: g.uses - listed.length }),
    };
  };
  const rank = (g) => (g.inTest ? 4 : 0) + (PRIORITY_ORDER[g.priority] ?? 3);
  return {
    view: 'summary',
    schema: report.schema,
    notice: report.notice,
    tool: report.tool,
    scannedAt: report.scannedAt,
    root: report.root,
    summary: report.summary,
    toReview: [...review.values()].sort((a, b) => rank(a) - rank(b) || b.uses - a.uses).map(settle),
    counted: [...counted.values()].sort((a, b) => a.inTest - b.inTest || b.uses - a.uses).map(settle),
    dependencies: report.dependencies.map(({ name, versions, direct, dev, provides, postQuantum }) => ({ name, versions, direct, dev, provides, postQuantum })),
    tls: report.tls.map(({ evidence, ...c }) => c),
    skipped: report.skipped,
    full: 'Call pqc_scan again with detail "full" for every use with its source line; on a large codebase give the folder you changed.',
  };
}

export function createMcpServer() {
  return createServer({ name: 'pqc-scan', version: TOOL_VERSION, instructions: MCP_INSTRUCTIONS, tools: mcpTools() });
}
