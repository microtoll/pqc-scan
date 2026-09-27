// Package names and versions from package.json and the lockfiles
// (DESIGN.md §3.1): package-lock.json (and npm-shrinkwrap.json) versions 1
// to 3, yarn.lock (version 1 and the later YAML-like format), and
// pnpm-lock.yaml (versions 5, 6 and 9), the last read line by line with no
// YAML library. Only names, versions and the dev flag are read; nothing
// in a lockfile is fetched or run.

/**
 * @typedef {{ name: string, version: string, dev: boolean|null }} LockRecord
 */

export const LOCKFILE_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']);

/**
 * @param {string} fileName  the base name, which says the format
 * @param {string} text
 * @returns {LockRecord[]}
 */
export function readLockfile(fileName, text) {
  if (fileName === 'yarn.lock') return readYarnLock(text);
  if (fileName === 'pnpm-lock.yaml') return readPnpmLock(text);
  return readPackageLock(text);
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 or 3. */
export function readPackageLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  if (lock && typeof lock.packages === 'object' && lock.packages !== null) {
    // Versions 2 and 3: "node_modules/a/node_modules/@s/b" → @s/b.
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key || !entry || typeof entry !== 'object') continue;
      const at = key.lastIndexOf('node_modules/');
      if (at < 0) continue; // a workspace folder itself; its node_modules link is read instead
      const name = entry.name ?? key.slice(at + 'node_modules/'.length);
      let version = entry.version;
      // A workspace package is a link; its version is on its own folder.
      if (!version && entry.link && typeof entry.resolved === 'string') version = lock.packages[entry.resolved]?.version;
      out.push({ name, version: version ?? 'unknown', dev: typeof entry.dev === 'boolean' ? entry.dev : Boolean(entry.devOptional) || false });
    }
    return out;
  }
  // Version 1: nested "dependencies".
  const walk = (deps) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (!entry || typeof entry !== 'object') continue;
      out.push({ name, version: String(entry.version ?? 'unknown'), dev: Boolean(entry.dev) });
      if (entry.dependencies) walk(entry.dependencies);
    }
  };
  walk(lock?.dependencies);
  return out;
}

/**
 * yarn.lock. Version 1:
 *   "@babel/core@^7.0.0", "@babel/core@^7.1.0":
 *     version "7.2.0"
 * The later format (Yarn 2 and after) is the same shape with `version: 7.2.0`
 * and `npm:` protocols in the keys; `__metadata` is skipped.
 */
export function readYarnLock(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  let names = null;
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line) && line.endsWith(':')) {
      const header = line.slice(0, -1);
      if (header === '__metadata') { names = null; continue; }
      names = [...new Set(header.split(/,\s*/).map((s) => nameFromSpecifier(s.replace(/^"|"$/g, ''))).filter(Boolean))];
      continue;
    }
    const m = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (m && names) {
      for (const name of names) out.push({ name, version: m[1], dev: null });
      names = null;
    }
  }
  return out;
}

/** 'lodash@^4.0.0' → 'lodash'; '@babel/core@npm:^7.0.0' → '@babel/core'. */
function nameFromSpecifier(spec) {
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  return at > 0 ? spec.slice(0, at) : null;
}

/**
 * pnpm-lock.yaml, the `packages:` section, keys at two spaces:
 *   version 5:   /name/1.2.3:  /@s/name/1.2.3_peer@1.0.0:
 *   version 6:   /name@1.2.3:  /@s/name@1.2.3(peer@1.0.0):
 *   version 9:   name@1.2.3:   '@s/name@1.2.3':
 * with `dev: true` four spaces in, where the format records it.
 */
export function readPnpmLock(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  const versionLine = lines.find((l) => l.startsWith('lockfileVersion:')) ?? '';
  const major = Number((/(\d+)/.exec(versionLine) ?? [])[1] ?? 9);
  let inPackages = false;
  let current = null;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      inPackages = line.trim() === 'packages:';
      current = null;
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):\s*$/.exec(line);
    if (key) {
      current = parsePnpmKey(key[1].replace(/^['"]|['"]$/g, ''), major);
      if (current) out.push(current);
      continue;
    }
    if (current && /^ {4}dev:\s*true\s*$/.test(line)) current.dev = true;
    if (current && /^ {4}dev:\s*false\s*$/.test(line)) current.dev = false;
  }
  return out;
}

function parsePnpmKey(raw, major) {
  let k = raw.replace(/^\//, '').replace(/\(.*$/, '');
  if (major < 6) {
    const parts = k.split('/');
    if (parts.length < 2) return null;
    return { name: parts.slice(0, -1).join('/'), version: parts[parts.length - 1].split('_')[0], dev: null };
  }
  const at = k.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: k.slice(0, at), version: k.slice(at + 1), dev: null };
}

/**
 * package.json: the declared dependencies, by section.
 * @returns {{ name: string, range: string, section: string }[]}
 */
/**
 * The `name` of a package.json, or null. A package the tree itself provides
 * (its root, or a workspace package) is not one it depends on, however its
 * own files import it (DESIGN.md §8.12).
 */
export function readManifestName(text) {
  const pkg = JSON.parse(text);
  return pkg && typeof pkg.name === 'string' && pkg.name ? pkg.name : null;
}

export function readManifest(text) {
  const pkg = JSON.parse(text);
  const out = [];
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(pkg?.[section] ?? {})) out.push({ name, range: String(range), section });
  }
  return out;
}
