// The report: JSON, schema version 1 (DESIGN.md §4, schema/pqc-scan.schema.json),
// and the Markdown a person reads, written from the JSON alone.
//
// The JSON is the seam a hosted report could read later (DESIGN.md §5). Its
// meaning only changes with a new schema version.
import { readFileSync } from 'node:fs';
import { CLASSES, CLASS_LABELS, CATALOGUE_DATE } from './catalogue.js';

export const SCHEMA_VERSION = 1;

/** The fixed sentence every report carries, in JSON and in Markdown (DESIGN.md §1). */
export const NOTICE = 'An inventory and pointers, not a compliance certificate.';

const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const TOOL_VERSION = PKG.version;

/**
 * Assembles the report object in its fixed order, sorted so that two scans
 * of the same tree differ only in `scannedAt` (DESIGN.md §8.7).
 */
export function buildReport({ root, now, filesScanned, findings, dependencies, tls, skipped }) {
  const sortedFindings = dedupe(findings).sort(compareFindings);
  const sortedTls = [...tls].sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.setting ?? '', b.setting ?? ''));
  const sortedSkipped = [...skipped].sort((a, b) => cmp(a.path, b.path));
  return {
    schema: SCHEMA_VERSION,
    notice: NOTICE,
    tool: { name: 'pqc-scan', version: TOOL_VERSION, catalogue: CATALOGUE_DATE },
    scannedAt: now.toISOString(),
    root,
    summary: summarise({ filesScanned, findings: sortedFindings, dependencies, tls: sortedTls }),
    findings: sortedFindings,
    dependencies,
    tls: sortedTls,
    skipped: sortedSkipped,
  };
}

function summarise({ filesScanned, findings, dependencies, tls }) {
  const byClass = Object.fromEntries(CLASSES.map((c) => [c, 0]));
  const byPriority = { high: 0, medium: 0, low: 0 };
  const files = new Set();
  const qvFiles = new Set();
  let qv = 0;
  let dynamic = 0;
  let inTests = 0;
  for (const f of findings) {
    byClass[f.class]++;
    files.add(f.file);
    if (f.quantumVulnerable) { qv++; qvFiles.add(f.file); }
    if (f.priority) byPriority[f.priority]++;
    if (f.dynamic) dynamic++;
    if (f.inTest) inTests++;
  }
  for (const t of tls) if (t.priority) byPriority[t.priority]++;
  const tlsState = overallTls(tls);
  return {
    filesScanned,
    filesWithFindings: files.size,
    findings: findings.length,
    findingsInTests: inTests,
    byClass,
    byPriority,
    quantumVulnerable: { uses: qv, files: qvFiles.size },
    dynamic,
    libraries: dependencies.length,
    tls: { configurations: tls.length, keyExchange: tlsState },
    verdict: verdict(qv, qvFiles.size, dependencies.length, tlsState),
  };
}

/** hybrid, classical-only, mixed, unstated, or none (no configuration found). */
function overallTls(tls) {
  if (!tls.length) return 'none';
  const states = new Set(tls.map((t) => (t.keyExchange === 'dynamic' ? 'unstated' : t.keyExchange)));
  if (states.size === 1) return [...states][0];
  if (!states.has('hybrid') && !states.has('mixed') && states.has('classical-only')) return 'classical-only';
  return 'mixed';
}

const TLS_WORDS = {
  hybrid: 'TLS hybrid-enabled',
  'classical-only': 'TLS classical-only',
  mixed: 'TLS mixed (hybrid in some configurations only)',
  unstated: 'TLS groups not written down',
  none: 'no TLS configuration found',
};

/** "N quantum-vulnerable public-key uses in M files; K libraries; TLS classical-only" (DESIGN.md §4). */
function verdict(uses, files, libraries, tls) {
  const s = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  return `${s(uses, 'quantum-vulnerable public-key use', 'quantum-vulnerable public-key uses')} in ${s(files, 'file', 'files')}; ${s(libraries, 'library', 'libraries')}; ${TLS_WORDS[tls]}`;
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = [f.file, f.line, f.column, f.algorithm, f.operation, f.interface].join('\u0001');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function compareFindings(a, b) {
  return cmp(a.file, b.file) || a.line - b.line || a.column - b.column
    || cmp(a.algorithm, b.algorithm) || cmp(a.operation, b.operation) || cmp(a.interface, b.interface);
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The JSON text of a report: two-space indentation and a final newline. */
export function toJson(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Markdown (DESIGN.md §4, the eight sections in their order)
// ---------------------------------------------------------------------------

/** What a static scan cannot see (DESIGN.md §3.2), printed verbatim in every Markdown report. */
export const CANNOT_SEE = [
  'It runs nothing it scans, follows no `require` into `node_modules` beyond the library catalogue, reads no environment, sends nothing anywhere, and has no telemetry.',
  'Frameworks\' own cryptography (a session cookie signer inside a web framework) is reported through the library catalogue when the framework is on the list, and otherwise not at all.',
  'An algorithm name held in a variable, a function parameter or a configuration file is reported as "dynamic — check by hand", never guessed.',
  'A file the scanner reads may never run: a library imported only by a file the service never loads is still reported. A static scan cannot tell which files run.',
  'Evidence is the source line as written: a secret written on the same line as a call appears in this report.',
  'Cryptography in other languages, in binaries, in the operating system, in a cloud provider\'s key service or behind a network call is not seen.',
];

const PRIORITY_HEADINGS = {
  high: 'High — data sealed with a classical public key',
  medium: 'Medium — signatures and authentication',
  low: 'Low — session key exchange',
};

const PRIORITY_INTROS = {
  high: 'Harvest now, decrypt later: a ciphertext recorded today can be opened once a large quantum computer exists. A person should review each of these.',
  medium: 'Forgeable only once a large quantum computer exists, not before, so the risk is to long-lived artefacts: software signatures, certificates, documents.',
  low: 'The exposure is the session, not the archive.',
};

const PQ_WORDS = { yes: 'yes', partial: 'partly', no: 'no', check: 'check the version', 'n/a': 'not needed (symmetric or hash only)' };

const TLS_STATE_WORDS = {
  hybrid: 'hybrid enabled',
  'classical-only': 'classical only',
  mixed: 'hybrid in some settings only',
  unstated: 'groups not written down',
  dynamic: 'not readable here',
};

/**
 * The human report. Everything in it comes from the report object, so the
 * Markdown and the JSON never disagree.
 * @param {object} report  a report from scan()
 * @returns {string}
 */
export function toMarkdown(report) {
  const out = [];
  const s = report.summary;
  const w = (line = '') => out.push(line);

  w(`# Post-quantum cryptography inventory: ${escapeText(report.root)}`);
  w();
  w(`**${report.notice}**`);
  w();
  w(`Scanned ${report.scannedAt} by ${report.tool.name} ${report.tool.version} (library catalogue ${report.tool.catalogue}); report schema version ${report.schema}.`);

  // 1. Summary
  w();
  w('## 1. Summary');
  w();
  w(`${escapeText(s.verdict)}.`);
  w();
  w(`${count(s.filesScanned, 'file')} read, ${count(s.findings, 'finding')} in ${count(s.filesWithFindings, 'file')} (${s.findingsInTests} in test code). Priorities: ${s.byPriority.high} High, ${s.byPriority.medium} Medium, ${s.byPriority.low} Low. ${count(s.dynamic, 'use')} could not be read and ${s.dynamic === 1 ? 'needs' : 'need'} checking by hand.`);
  w();
  table(w, ['Class', 'Findings'], CLASSES.map((c) => [CLASS_LABELS[c], String(s.byClass[c])]));

  // 2. What you use, where
  w();
  w('## 2. What you use, where');
  w();
  if (!report.findings.length) w('No cryptographic calls were found in the source files.');
  else {
    table(w, ['Algorithm', 'Class', 'Interface', 'Size or parameters', 'Where'], report.findings.map((f) => [
      escapeText(f.algorithm), CLASS_LABELS[f.class], code(f.interface), sizeOf(f), where(f),
    ]));
  }

  // 3. Quantum-vulnerable public-key uses, with a priority
  w();
  w('## 3. Quantum-vulnerable public-key uses, with a priority');
  w();
  w('The priority is a heuristic from the interface used and the words around the call; each entry says which word decided it.');
  for (const p of ['high', 'medium', 'low']) {
    const items = report.findings.filter((f) => f.priority === p);
    const tlsItems = report.tls.filter((t) => t.priority === p);
    w();
    w(`### ${PRIORITY_HEADINGS[p]}`);
    w();
    if (!items.length && !tlsItems.length) { w('None found.'); continue; }
    w(PRIORITY_INTROS[p]);
    w();
    // prioritise() gives every entry of one priority the same replacement.
    w(`**Replacement to consider:** ${escapeText((items[0] ?? tlsItems[0]).replacement)}`);
    w();
    table(w, ['Algorithm', 'Operation', 'Where', 'Why this priority', 'Evidence'], [
      ...items.map((f) => [escapeText(f.algorithm), escapeText(f.operation), where(f), escapeText(f.priorityReason), code(f.evidence)]),
      ...tlsItems.map((t) => [`TLS (${escapeText(t.server)})`, 'key exchange', where(t), escapeText(t.priorityReason), code(t.evidence)]),
    ]);
  }

  // 4. Symmetric and hash notes
  w();
  w('## 4. Symmetric, hash and other notes');
  w();
  const noted = new Map();
  for (const f of report.findings) {
    for (const n of f.notes) {
      if (!noted.has(n.code)) noted.set(n.code, { text: n.text, places: [] });
      noted.get(n.code).places.push(`${escapeText(f.algorithm)} at ${where(f)}`);
    }
  }
  if (!noted.size) w('Nothing to note.');
  for (const [, { text, places }] of [...noted].sort((a, b) => cmp(a[0], b[0]))) {
    w(`- ${escapeText(text)}`);
    for (const place of places) w(`  - ${place}`);
  }

  // 5. Dependencies
  w();
  w('## 5. Dependencies');
  w();
  if (!report.dependencies.length) w('No catalogued cryptographic library was found in a manifest, a lockfile or an import.');
  else {
    table(w, ['Package', 'Version', 'Direct', 'Provides', 'Post-quantum'], report.dependencies.map((d) => [
      code(d.name), escapeText(d.versions.join(', ') || 'unknown'),
      d.direct ? (d.dev ? 'yes (development)' : 'yes') : 'no (transitive)',
      escapeText(d.provides), PQ_WORDS[d.postQuantum] ?? escapeText(d.postQuantum),
    ]));
  }

  // 6. TLS
  w();
  w('## 6. TLS');
  w();
  if (!report.tls.length) w('No TLS configuration was found written down in the scanned files.');
  else {
    table(w, ['Where', 'Server', 'Key exchange', 'Groups', 'Notes'], report.tls.map((t) => [
      where(t), escapeText(t.setting ? `${t.server} (${t.setting})` : t.server), TLS_STATE_WORDS[t.keyExchange] ?? escapeText(t.keyExchange),
      t.groups ? code(t.groups.join(':')) : '—', t.notes.map((n) => escapeText(n.text)).join(' ') || '—',
    ]));
  }

  // 7. Next steps
  w();
  w('## 7. Next steps');
  w();
  w('In the frame of the UK National Cyber Security Centre\'s post-quantum migration timeline (discovery and a plan by 2028, the highest-priority migrations by 2031, the rest by 2035):');
  w();
  const otherUnknown = s.byClass.unknown - s.dynamic;
  w(`1. **Finish discovery** (2028): check by hand the ${count(s.dynamic, 'use')} this scan could not read${otherUnknown > 0 ? `, the ${otherUnknown} other ${otherUnknown === 1 ? 'entry' : 'entries'} marked unknown` : ''}, and what section 8 says it cannot see.`);
  w(`2. **Decide priorities:** a person reviews each High (${s.byPriority.high}) and confirms or lowers it.`);
  w('3. **Plan the High items for the 2031 milestone:** a hybrid seal for new data, and re-sealing old data that must outlive the transition.');
  w('4. **Plan the rest for 2035:** signatures to ML-DSA or SLH-DSA as platforms offer them; hybrid TLS groups as servers support them.');

  // 8. What this report cannot see
  w();
  w('## 8. What this report cannot see');
  w();
  for (const line of CANNOT_SEE) w(`- ${line}`);
  if (report.skipped.length) {
    w();
    w('Not read:');
    w();
    for (const k of report.skipped) w(`- ${escapeText(k.path)}: ${escapeText(k.reason)}`);
  }
  w();
  w(`*${report.notice}*`);
  return `${out.join('\n')}\n`;
}

function count(n, one) {
  return `${n} ${n === 1 ? one : `${one}s`}`;
}

function where(x) {
  return code(`${x.file}:${x.line}`) + (x.inTest ? ' (test)' : '');
}

function sizeOf(f) {
  const parts = [];
  if (f.keySize) parts.push(`${f.keySize}-bit`);
  if (f.curve && !String(f.algorithm).includes(f.curve)) parts.push(f.curve);
  for (const [k, v] of Object.entries(f.parameters ?? {})) parts.push(`${k} ${typeof v === 'number' ? grouped(v) : v}`);
  return parts.length ? escapeText(parts.join(', ')) : '—';
}

/** 310000 → "310,000", the same on every machine (no locale data involved). */
function grouped(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function table(w, head, rows) {
  w(`| ${head.join(' | ')} |`);
  w(`|${head.map(() => ' --- ').join('|')}|`);
  for (const r of rows) w(`| ${r.join(' | ')} |`);
}

/**
 * Text from a scanned file, made inert in Markdown: nothing a scanned
 * codebase writes can add a link, an image, HTML, emphasis, a code span or
 * a table cell to the report, so a hostile repository cannot put words in
 * its mouth. Escaped with a backslash (CommonMark §2.4): the characters that
 * open those anywhere in a line (a link needs `[`, so `(` is left readable),
 * and a heading, list or block-quote marker at the start.
 */
function escapeText(value) {
  return String(value ?? '')
    .replace(/\r?\n/g, ' ')
    .replace(/[\\`*_[\]|<>~&]/g, (c) => `\\${c}`)
    .replace(/^([#+\-=]|\d+[.)])/, (m) => `\\${m}`);
}

/**
 * A table-cell code span no content can break out of: the fence is one
 * backtick longer than the longest run inside (CommonMark §6.1), and a pipe
 * is escaped so that it cannot end the cell (GitHub Flavored Markdown §4.10).
 */
function code(value) {
  const text = String(value ?? '').replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
  if (!text) return '—';
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((r) => r.length));
  const fence = '`'.repeat(longest + 1);
  const pad = text.startsWith('`') || text.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${text}${pad}${fence}`;
}
