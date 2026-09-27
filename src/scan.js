// Walking a directory and running the detectors (DESIGN.md §3, §8.7).
//
// The scanner only reads: it opens files, tokenizes or parses them as data
// (JSON.parse for package.json and package-lock.json), and returns a
// report object. It never imports, requires or evaluates a scanned file,
// never reads the environment, never touches the network.
import { readdirSync, readFileSync, lstatSync, statSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';
import { posix } from 'node:path';
import { SourceFile } from './source.js';
import { LIBRARIES } from './catalogue.js';
import { detectWebCrypto } from './detect/webcrypto.js';
import { detectNodeCrypto } from './detect/node-crypto.js';
import { detectLibraries } from './detect/libraries.js';
import { detectParameters } from './detect/parameters.js';
import { detectNodeTls, isTlsCandidate, readTlsConfigFile } from './detect/tls.js';
import { LOCKFILE_NAMES, readLockfile, readManifest } from './detect/lockfiles.js';
import { buildReport } from './report.js';

const JS_FILE = /\.(js|mjs|cjs|jsx|ts|mts|cts|tsx)$/i;
// Never walked (DESIGN.md §3.2: no `require` is followed into node_modules
// beyond the catalogue, which is read from the lockfiles instead).
const ALWAYS_SKIPPED = new Set(['node_modules', '.git']);
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
const RESOLVE_EXTENSIONS = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.jsx', '/index.js', '/index.ts', '/index.mjs'];

/**
 * Scans a directory.
 * @param {string} dir
 * @param {{ exclude?: string[], now?: Date }} [options]
 *   exclude: directory or file names, or paths relative to `dir`, to skip.
 *   now: the time written as scannedAt (a test fixes it; nothing else does).
 * @returns {object} the report, schema version 1
 */
export function scan(dir, options = {}) {
  const root = resolve(dir);
  if (!statSync(root).isDirectory()) throw new Error(`not a directory: ${dir}`);
  const exclude = (options.exclude ?? []).map(normaliseExclude).filter(Boolean);
  const files = [];
  const skipped = [];
  walk(root, '', files, skipped, exclude);

  // Read every file once, in path order.
  const texts = new Map();
  for (const f of files) {
    const size = lstatSync(f.abs).size;
    if (size > MAX_FILE_BYTES) { skipped.push({ path: f.rel, reason: 'larger than 2 MB' }); continue; }
    let text;
    try { text = readFileSync(f.abs, 'utf8'); } catch (err) { skipped.push({ path: f.rel, reason: `unreadable (${err.code ?? 'error'})` }); continue; }
    if (text.includes('\u0000')) { skipped.push({ path: f.rel, reason: 'binary' }); continue; }
    texts.set(f.rel, { kind: f.kind, text });
  }

  // Pass 1: module-level constants of every source file, for relative
  // imports (DESIGN.md §8.1 step 2). Tokens are dropped after each file.
  const constants = new Map();
  for (const [rel, { kind, text }] of texts) {
    if (kind === 'js') constants.set(rel, new SourceFile(rel, text).moduleConstants());
  }
  const importedConstant = (fromPath, specifier, name) => {
    const target = resolveRelative(fromPath, specifier, constants);
    return target ? constants.get(target).get(name) ?? null : null;
  };

  // Pass 2: the detectors.
  const findings = [];
  const tls = [];
  const importSites = [];
  const manifests = [];
  const locks = [];
  let filesScanned = 0;
  for (const [rel, { kind, text }] of texts) {
    filesScanned++;
    if (kind === 'js') {
      const src = new SourceFile(rel, text, { importedConstant });
      findings.push(...detectWebCrypto(src), ...detectNodeCrypto(src), ...detectParameters(src));
      const libs = detectLibraries(src);
      findings.push(...libs.findings);
      importSites.push(...libs.importSites);
      tls.push(...detectNodeTls(src));
    } else if (kind === 'manifest') {
      try { manifests.push({ file: rel, deps: readManifest(text) }); } catch { skipped.push({ path: rel, reason: 'not valid JSON' }); }
    } else if (kind === 'lockfile') {
      try { locks.push({ file: rel, records: readLockfile(basename(rel), text) }); } catch { skipped.push({ path: rel, reason: 'lockfile could not be read' }); }
    } else if (kind === 'tls') {
      tls.push(...readTlsConfigFile(rel, text, isTestPath(rel)));
    }
  }

  return buildReport({
    root: basename(root),
    now: options.now ?? new Date(),
    filesScanned,
    findings,
    dependencies: dependencies(manifests, locks, importSites),
    tls,
    skipped,
  });
}

/** One entry per catalogued package seen in a manifest, a lockfile or an import. */
function dependencies(manifests, locks, importSites) {
  const byName = new Map();
  const get = (name) => {
    if (!byName.has(name)) byName.set(name, { name, versions: new Set(), declaredIn: new Set(), lockfiles: new Set(), sections: new Set(), lockDev: [], importedAt: new Set() });
    return byName.get(name);
  };
  for (const m of manifests) {
    for (const d of m.deps) {
      if (!LIBRARIES[d.name]) continue;
      const e = get(d.name);
      e.declaredIn.add(m.file);
      e.sections.add(d.section);
      e.ranges ??= new Set();
      e.ranges.add(d.range);
    }
  }
  for (const l of locks) {
    for (const r of l.records) {
      if (!LIBRARIES[r.name]) continue;
      const e = get(r.name);
      e.versions.add(r.version);
      e.lockfiles.add(l.file);
      e.lockDev.push(r.dev);
    }
  }
  for (const s of importSites) get(s.package).importedAt.add(`${s.file}:${s.line}`);

  const sorted = (set) => [...set].sort(byString);
  return [...byName.values()].sort((a, b) => byString(a.name, b.name)).map((e) => {
    // A version from the lockfile when there is one; otherwise the declared
    // range, marked as such.
    const versions = e.versions.size ? sorted(e.versions) : sorted(e.ranges ?? new Set()).map((r) => `${r} (declared)`);
    let dev = null;
    if (e.lockDev.length && e.lockDev.every((d) => d === true)) dev = true;
    else if (e.lockDev.some((d) => d === false)) dev = false;
    else if (e.sections.size) dev = [...e.sections].every((s) => s === 'devDependencies');
    return {
      name: e.name,
      versions,
      direct: e.declaredIn.size > 0,
      dev,
      declaredIn: sorted(e.declaredIn),
      lockfiles: sorted(e.lockfiles),
      provides: LIBRARIES[e.name].provides,
      postQuantum: LIBRARIES[e.name].pq,
      importedAt: [...e.importedAt].sort(byLocation),
    };
  });
}

function walk(abs, rel, out, skipped, exclude) {
  let entries;
  try { entries = readdirSync(abs, { withFileTypes: true }); } catch (err) {
    skipped.push({ path: rel || '.', reason: `unreadable (${err.code ?? 'error'})` });
    return;
  }
  // Byte order of names, so every machine walks the tree the same way.
  entries.sort((a, b) => byString(a.name, b.name));
  for (const e of entries) {
    const relPath = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory() && ALWAYS_SKIPPED.has(e.name)) continue;
    if (isExcluded(relPath, e.name, exclude)) continue;
    // A symbolic link could lead out of the tree, or round in a loop.
    if (e.isSymbolicLink()) { skipped.push({ path: relPath, reason: 'symbolic link, not followed' }); continue; }
    const childAbs = join(abs, e.name);
    if (e.isDirectory()) { walk(childAbs, relPath, out, skipped, exclude); continue; }
    if (!e.isFile()) continue;
    const kind = fileKind(e.name);
    if (kind) out.push({ abs: childAbs, rel: relPath, kind });
  }
}

function fileKind(name) {
  if (JS_FILE.test(name)) return 'js';
  if (name === 'package.json') return 'manifest';
  if (LOCKFILE_NAMES.has(name)) return 'lockfile';
  if (isTlsCandidate(name)) return 'tls';
  return null;
}

function normaliseExclude(value) {
  return String(value).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
}

/** An exclude matches a name anywhere in the tree, or a path from the root. */
function isExcluded(relPath, name, exclude) {
  return exclude.some((x) => x === name || x === relPath || relPath.startsWith(`${x}/`));
}

function isTestPath(rel) {
  const parts = rel.split('/');
  return parts.slice(0, -1).some((p) => ['test', 'tests', '__tests__', 'spec', 'specs'].includes(p))
    || /\.(test|spec)\./.test(parts[parts.length - 1]);
}

/** './primitives.js' from 'src/seal.js' → 'src/primitives.js', if scanned. */
function resolveRelative(fromPath, specifier, known) {
  if (!specifier.startsWith('.')) return null;
  const base = posix.normalize(posix.join(posix.dirname(fromPath), specifier));
  const candidates = [];
  for (const ext of RESOLVE_EXTENSIONS) candidates.push(base + ext);
  // TypeScript imports './x.js' when the file is './x.ts'.
  if (/\.js$/.test(base)) for (const ext of ['.ts', '.tsx', '.mts']) candidates.push(base.replace(/\.js$/, ext));
  return candidates.find((c) => known.has(c)) ?? null;
}

export function byString(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** 'a.js:10' before 'a.js:9'? No: by file, then by line number. */
function byLocation(a, b) {
  const [fa, la] = splitLocation(a);
  const [fb, lb] = splitLocation(b);
  return byString(fa, fb) || la - lb;
}

function splitLocation(s) {
  const i = s.lastIndexOf(':');
  return [s.slice(0, i), Number(s.slice(i + 1))];
}
