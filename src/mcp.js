// `pqc-scan mcp` (DESIGN.md §8.15): the scanner as a Model Context Protocol
// server over standard input and output, with one tool, `pqc_scan`, whose
// result is the JSON report (schema version 1), so a coding agent can check
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

export function mcpTools() {
  return [
    {
      name: 'pqc_scan',
      description: [
        'Scans a JavaScript or TypeScript codebase for the cryptography it uses (Web Crypto, node:crypto, catalogued libraries, TLS configuration, lockfiles)',
        'and returns the report as JSON, pqc-scan schema version 1: each finding with its algorithm, key size or curve, file and line, whether a large quantum computer would break it,',
        'a migration priority (high, medium or low) with the reason, and a replacement to consider; then the dependencies, the TLS configurations and a summary.',
        'An algorithm name the code does not write down is marked dynamic, to check by hand. Reads files only: writes nothing and runs nothing.',
        'The whole report comes back, so on a large codebase scan the folder you changed, or skip folders with exclude.',
        NOTICE,
      ].join(' '),
      inputSchema: {
        type: 'object',
        properties: {
          directory: { type: 'string', minLength: 1, description: 'The folder to scan: an absolute path, or one relative to the folder this server was started in. node_modules and .git are never read.' },
          exclude: { ...STRINGS, description: 'Folder or file names, or paths from the scanned folder, to skip.' },
          testFiles: { ...STRINGS, description: 'Texts; a file whose path contains one is marked as test code, besides test, tests, __tests__, spec and .test./.spec. names.' },
        },
        required: ['directory'],
        additionalProperties: false,
      },
      handler: pqcScanTool,
    },
  ];
}

/** The tool: the arguments checked as the command line checks its own, then one scan. */
function pqcScanTool({ directory, exclude = [], testFiles = [] }) {
  if (typeof directory !== 'string' || directory === '') return { text: 'directory: give the folder to scan', isError: true };
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
  // Compact: the same document as --json writes, without the indentation,
  // which is a quarter of its length and costs the agent's context.
  return JSON.stringify(report);
}

export function createMcpServer() {
  return createServer({ name: 'pqc-scan', version: TOOL_VERSION, instructions: MCP_INSTRUCTIONS, tools: mcpTools() });
}
