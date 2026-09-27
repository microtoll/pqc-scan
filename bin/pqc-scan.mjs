#!/usr/bin/env node
// The command line (DESIGN.md §7, §8.7):
//
//   pqc-scan [dir] [--json <file>] [--md <file>] [--fail-on high|medium] [--exclude <name>]…
//
// Exit codes: 0 done, 1 the --fail-on threshold was met, 2 a usage or read
// error. With neither --json nor --md, the Markdown goes to standard output
// and nothing is written to disk. It uses only the package's public API.
import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { scan, toJson, toMarkdown, TOOL_VERSION } from '../src/index.js';

const USAGE = `Usage: pqc-scan [dir] [options]

An inventory of the cryptography a JavaScript or TypeScript codebase uses,
and which of it a large quantum computer would break. An inventory and
pointers, not a compliance certificate. It reads files only: it runs
nothing it scans and sends nothing anywhere.

  dir                    the directory to scan (default: the current one)
  --json <file>          write the machine-readable report (schema version 1)
  --md <file>            write the human report
  --fail-on <priority>   exit 1 if anything is at this priority or above:
                         high, or medium (High and Medium)
  --exclude <name>       a directory or file name, or a path from dir, to
                         skip (repeatable); node_modules and .git never are read
  --help                 this text
  --version              the version

With neither --json nor --md, the Markdown report goes to standard output.
Exit codes: 0 done, 1 the --fail-on threshold was met, 2 a usage or read error.
`;

// The thresholds of DESIGN.md §7: each names the priorities that meet it.
const FAIL_ON = { high: ['high'], medium: ['high', 'medium'] };

function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: 'string' },
        md: { type: 'string' },
        'fail-on': { type: 'string' },
        exclude: { type: 'string', multiple: true },
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
  if (positionals.length > 1) return usageError('give one directory to scan');
  const failOn = values['fail-on'];
  if (failOn !== undefined && !FAIL_ON[failOn]) return usageError(`--fail-on takes high or medium, not "${failOn}"`);
  for (const flag of ['json', 'md']) {
    if (values[flag] === '') return usageError(`--${flag} needs a file name`);
  }

  let report;
  try {
    report = scan(positionals[0] ?? '.', { exclude: values.exclude ?? [] });
  } catch (err) {
    process.stderr.write(`pqc-scan: cannot scan ${positionals[0] ?? '.'}: ${err.code === 'ENOENT' ? 'no such directory' : err.message}\n`);
    return 2;
  }

  const markdown = toMarkdown(report);
  if (values.json === undefined && values.md === undefined) {
    process.stdout.write(markdown);
  } else {
    try {
      if (values.json !== undefined) writeFileSync(values.json, toJson(report));
      if (values.md !== undefined) writeFileSync(values.md, markdown);
    } catch (err) {
      process.stderr.write(`pqc-scan: cannot write the report: ${err.message}\n`);
      return 2;
    }
    process.stdout.write(`pqc-scan: ${report.summary.verdict}.\n`);
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

function usageError(message) {
  process.stderr.write(`pqc-scan: ${message}\n\n${USAGE}`);
  return 2;
}

process.exitCode = main(process.argv.slice(2));
