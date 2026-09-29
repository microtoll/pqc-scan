#!/usr/bin/env node
// The command line (DESIGN.md §7, §8.7, §8.13, §8.14, §8.15):
//
//   pqc-scan [dir] [--json <file>] [--md <file>] [--cbom <file>] [--write]
//            [--fail-on high|medium] [--exclude <name>]… [--test-files <text>]…
//   pqc-scan mcp
//
// `pqc-scan mcp`, with nothing after it, is the Model Context Protocol server
// on standard input and output (§8.15); a folder named mcp is scanned with
// `pqc-scan ./mcp` or `pqc-scan -- mcp`.
// Exit codes: 0 done, 1 the --fail-on threshold was met, 2 a usage or read
// error. Run from a terminal with no output named, it writes pqc-scan.md and
// pqc-scan.json into the current folder and prints a short summary (§8.13).
// Piped, with no output named, the Markdown goes to standard output and
// nothing is written to disk. It uses only the package's public API.
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { scan, toJson, toMarkdown, toCbom, createMcpServer, TOOL_VERSION } from '../src/index.js';

const USAGE = `Usage: pqc-scan [dir] [options]
       pqc-scan mcp

An inventory of the cryptography a JavaScript or TypeScript codebase uses,
and which of it a large quantum computer would break. An inventory and
pointers, not a compliance certificate. It reads files only: it runs
nothing it scans and sends nothing anywhere.

  dir                    the folder to scan (default: the current one)
  --write                write pqc-scan.md and pqc-scan.json into the current
                         folder (what a run from a terminal does by default)
  --md <file>            write the human report to this file instead
  --json <file>          write the machine-readable report (schema version 1)
  --cbom <file>          write a CycloneDX 1.6 cryptographic bill of materials
  --fail-on <priority>   exit 1 if anything is at this priority or above:
                         high, or medium (High and Medium)
  --exclude <name>       a folder or file name, or a path from dir, to skip
                         (repeatable); node_modules and .git are never read
  --test-files <text>    treat a file whose path contains this text as test
                         code (repeatable); test, tests, __tests__, spec and
                         .test./.spec. names always count
  --help                 this text
  --version              the version

  mcp                    run as a Model Context Protocol server on standard
                         input and output, for a coding agent: one tool,
                         pqc_scan, which returns the JSON report. To scan a
                         folder named mcp, give ./mcp

Run from a terminal with nothing named, the reports go to the current folder
and a summary is printed. Piped, the Markdown report goes to standard output.
Exit codes: 0 done, 1 the --fail-on threshold was met, 2 a usage or read error.
`;

// The thresholds of DESIGN.md §7: each names the priorities that meet it.
const FAIL_ON = { high: ['high'], medium: ['high', 'medium'] };

function main(argv) {
  if (argv[0] === 'mcp') return mcp(argv.slice(1));
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: 'string' },
        md: { type: 'string' },
        cbom: { type: 'string' },
        write: { type: 'boolean' },
        'fail-on': { type: 'string' },
        exclude: { type: 'string', multiple: true },
        'test-files': { type: 'string', multiple: true },
        help: { type: 'boolean' },
        version: { type: 'boolean' },
      },
    });
  } catch (err) {
    return usageError(err.message);
  }
  const { values, positionals } = parsed;
  if (values.help) { process.stdout.write(USAGE); return 0; }
  if (values.version) { process.stdout.write(`${TOOL_VERSION}\n`); return 0; }
  if (positionals.length > 1) return usageError('give one folder to scan');
  const failOn = values['fail-on'];
  if (failOn !== undefined && !FAIL_ON[failOn]) return usageError(`--fail-on takes high or medium, not "${failOn}"`);
  for (const flag of ['json', 'md', 'cbom']) {
    if (values[flag] === '') return usageError(`--${flag} needs a file name`);
  }
  if ((values['test-files'] ?? []).some((t) => t === '')) return usageError('--test-files needs some text');

  const dir = positionals[0] ?? '.';
  let report;
  try {
    report = scan(dir, { exclude: values.exclude ?? [], testFiles: values['test-files'] ?? [] });
  } catch (err) {
    process.stderr.write(`pqc-scan: cannot scan ${dir}: ${err.code === 'ENOENT' ? 'no such folder' : err.message}\n`);
    return 2;
  }

  // Where the reports go (DESIGN.md §8.13). A person at a terminal who named
  // nothing gets files in the current folder, since a real application's
  // report is far too long to read as it scrolls past; a pipe gets the
  // Markdown, unchanged, so scripts keep working.
  const markdown = toMarkdown(report);
  let json = values.json;
  let md = values.md;
  const cbom = values.cbom; // only ever written when asked for (§8.14)
  const nothingNamed = json === undefined && md === undefined && cbom === undefined;
  if (nothingNamed && (values.write || process.stdout.isTTY)) {
    json = 'pqc-scan.json';
    md = 'pqc-scan.md';
  }
  if (json === undefined && md === undefined && cbom === undefined) {
    process.stdout.write(markdown);
  } else {
    try {
      if (json !== undefined) writeFileSync(json, toJson(report));
      if (md !== undefined) writeFileSync(md, markdown);
      if (cbom !== undefined) writeFileSync(cbom, toCbom(report));
    } catch (err) {
      process.stderr.write(`pqc-scan: cannot write the report: ${err.message}\n`);
      return 2;
    }
    process.stdout.write(summaryLines(report, md, json, cbom));
  }

  if (failOn) {
    const met = FAIL_ON[failOn].reduce((n, p) => n + report.summary.byPriority[p], 0);
    if (met > 0) {
      process.stderr.write(`pqc-scan: --fail-on ${failOn}: ${met} ${met === 1 ? 'entry is' : 'entries are'} at that priority or above.\n`);
      return 1;
    }
  }
  return 0;
}

/** What a person sees after the reports are written: the verdict, the counts, and where to look. */
function summaryLines(report, md, json, cbom) {
  const s = report.summary;
  const p = s.byPriority;
  const lines = [
    `pqc-scan: ${s.verdict}.`,
    `  ${s.filesScanned} files read; ${p.high} High, ${p.medium} Medium, ${p.low} Low; ${s.dynamic} to check by hand.`,
  ];
  if (md !== undefined) lines.push(`  Report: ${resolve(md)}  (open it; read sections 1 and 3 first)`);
  if (json !== undefined) lines.push(`  JSON:   ${resolve(json)}`);
  if (cbom !== undefined) lines.push(`  CBOM:   ${resolve(cbom)}  (CycloneDX 1.6)`);
  return `${lines.join('\n')}\n`;
}

/** `pqc-scan mcp` (DESIGN.md §8.15): standard output is the protocol from here on. */
function mcp(rest) {
  if (rest.length > 0) return usageError('pqc-scan mcp takes nothing after it; to scan a folder named mcp, give ./mcp');
  if (process.stdin.isTTY) {
    process.stderr.write('pqc-scan mcp: a Model Context Protocol server, waiting for a host on standard input (Ctrl+C to stop).\n'
      + 'To scan a folder named mcp instead, run: pqc-scan ./mcp\n');
  }
  createMcpServer().listen();
  return 0;
}

function usageError(message) {
  process.stderr.write(`pqc-scan: ${message}\n\n${USAGE}`);
  return 2;
}

process.exitCode = main(process.argv.slice(2));
