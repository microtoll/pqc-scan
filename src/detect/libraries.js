// Catalogued libraries at their import sites and call sites (DESIGN.md
// §3.1, §8.5). A call counts when its root is bound, in this file, to an
// import or require of a catalogued package; the catalogue maps the member
// path to an algorithm. JSON Web Token libraries are read by their
// algorithm literals.
import {
  LIBRARIES, packageOf, describe, dynamicAlgorithm, fromJoseAlg, normaliseHash, fromCipherName,
} from '../catalogue.js';
import { makeFinding } from './finding.js';

// Helper modules that hold no cryptography: importing only these is not a
// use to point at (`@noble/hashes/utils` gives bytesToHex).
const HELPER_SUBPATHS = /^(utils?|util\/.*|utils\/.*|types?)$/;

/**
 * @param {import('../source.js').SourceFile} src
 * @returns {{ findings: object[], importSites: { package: string, file: string, line: number }[] }}
 */
export function detectLibraries(src) {
  const findings = [];
  const importSites = [];
  /** @type {Map<string, {index: number, line: number, helperOnly: boolean}>} */
  const importedHere = new Map();
  for (const site of src.imports.sites) {
    const pkg = packageOf(site.module);
    if (!pkg || !LIBRARIES[pkg.name]) continue;
    importSites.push({ package: pkg.name, file: src.path, line: site.line });
    const helper = HELPER_SUBPATHS.test(pkg.subpath);
    const prior = importedHere.get(pkg.name);
    if (!prior) importedHere.set(pkg.name, { index: site.index, line: site.line, helperOnly: helper });
    else if (!helper) prior.helperOnly = false;
  }
  if (importedHere.size === 0) return { findings, importSites };

  const used = new Set();
  const iface = (name) => `library:${name}`;

  for (const call of src.calls) {
    const r = src.resolveCall(call);
    if (!r) continue;
    const pkg = packageOf(r.module);
    const entry = pkg && LIBRARIES[pkg.name];
    if (!entry) continue;
    const operation = r.path.length ? r.path.join('.') : '()';
    const spec = lookup(entry, pkg.subpath, r.path);
    if (spec) {
      for (const algo of fromSpec(src, call, spec)) findings.push(makeFinding(src, call.at, algo, { iface: iface(pkg.name), operation }));
      used.add(pkg.name);
    }
    // jsonwebtoken signs with HS256 when no algorithm is given: its
    // documented default, so reported as such, not guessed.
    if (pkg.name === 'jsonwebtoken' && operation === 'sign') {
      const algo = jwtSignDefault(src, call);
      if (algo) { findings.push(makeFinding(src, call.at, algo, { iface: iface(pkg.name), operation })); used.add(pkg.name); }
    }
  }

  // JSON Web Algorithms names written as literals, in a file that imports a
  // JWT library (DESIGN.md §8.5).
  const joseLibs = [...importedHere.keys()].filter((n) => LIBRARIES[n].jose).sort();
  // A bare literal cannot say which of several JWT libraries it is passed
  // to, so a file that imports more than one names them all rather than
  // guessing (DESIGN.md §3.1: never guessed; fixture libraries/src/jwt.js).
  const joseIface = `library:${joseLibs.join(' or ')}`;
  if (joseLibs.length) {
    for (let i = 0; i < src.tokens.length; i++) {
      const t = src.tokens[i];
      if (t.type !== 'string' && t.type !== 'template') continue;
      const alg = String(t.value);
      if (alg === 'none') {
        if (!isAlgField(src, i)) continue;
        findings.push(makeFinding(src, i, describe({ family: 'Unknown', name: 'JWT alg "none"', noteCodes: ['unsigned'] }), { iface: joseIface, operation: 'algorithm literal' }));
        joseLibs.forEach((n) => used.add(n));
        continue;
      }
      const algo = fromJoseAlg(alg);
      if (!algo) continue;
      findings.push(makeFinding(src, i, algo, { iface: joseIface, operation: 'algorithm literal' }));
      joseLibs.forEach((n) => used.add(n));
    }
  }

  // A catalogued package whose calls the catalogue maps, imported here, with
  // none of its uses read: one pointer at the import, reported as dynamic
  // rather than guessed. A package the catalogue has no call map for (its
  // uses can never be read) is listed under Dependencies with its import
  // sites instead, so that a codebase built on one library does not get a
  // pointer per file.
  for (const [name, site] of [...importedHere].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (used.has(name) || site.helperOnly) continue;
    if (!LIBRARIES[name].calls && !LIBRARIES[name].jose) continue;
    findings.push(makeFinding(src, site.index, dynamicAlgorithm(`${name} imported; its uses here could not be read`), { iface: iface(name), operation: 'import' }));
  }
  return { findings, importSites };
}

/** The catalogue entry for a member path: the longest matching key wins. */
function lookup(entry, subpath, path) {
  if (path.length === 0 && subpath && entry.subpaths && entry.subpaths[subpath]) return entry.subpaths[subpath];
  if (!entry.calls) return null;
  const key = path.length === 0 ? '()' : path.join('.');
  let best = null;
  for (const k of Object.keys(entry.calls)) {
    if (k === '*') { if (best === null) best = k; continue; }
    // 'box' matches box, box.open, box.keyPair; libsodium's crypto_box
    // matches crypto_box_easy; never a bare prefix (sign ≠ signature).
    const hit = key === k || key.startsWith(`${k}.`) || key.startsWith(`${k}_`);
    if (hit && (best === null || best === '*' || k.length > best.length)) best = k;
  }
  return best === null ? null : entry.calls[best];
}

/** The algorithm(s) of one catalogued call, with its literal arguments read. */
function fromSpec(src, call, spec) {
  const args = src.args(call.open);
  const read = (i) => (args[i] ? src.readValue(args[i][0], args[i][1]) : undefined);
  const readAt = ([i, field]) => {
    const v = read(i);
    if (!field) return v;
    return v && v.kind === 'object' ? src.field(v, field) : undefined;
  };
  let { curve = null, keySize = null, hash = null } = spec;
  const parameters = {};
  if (spec.cipherArg !== undefined) {
    const v = read(spec.cipherArg);
    return [v && v.kind === 'string' ? fromCipherName(v.value) : dynamicAlgorithm('cipher name not written here')];
  }
  if (spec.keyTypeArg !== undefined) {
    // jsrsasign KEYUTIL.generateKeypair('RSA', 2048) or ('EC', 'secp256r1').
    const type = read(spec.keyTypeArg);
    const second = read(spec.keyTypeArg + 1);
    if (type && type.kind === 'string' && type.value.toUpperCase() === 'EC') {
      return [describe({ family: 'EC', curve: second && second.kind === 'string' ? second.value : null })];
    }
    if (type && type.kind === 'string' && type.value.toUpperCase() === 'RSA') {
      return [describe({ family: 'RSA', keySize: second && second.kind === 'number' ? second.value : null })];
    }
    return [dynamicAlgorithm('key type not written here')];
  }
  if (spec.curveArg !== undefined) {
    const v = read(spec.curveArg);
    if (v && v.kind === 'string') curve = v.value;
  }
  if (spec.sizeArg) {
    const v = readAt(spec.sizeArg);
    if (v && v.kind === 'number') keySize = v.value;
  }
  if (spec.costArg) {
    const v = readAt(spec.costArg);
    if (v && v.kind === 'number') parameters.cost = v.value;
  }
  if (spec.iterationsArg) {
    const v = readAt(spec.iterationsArg);
    if (v && v.kind === 'number') parameters.iterations = v.value;
  }
  if (spec.hashIdentArg !== undefined) {
    // hmac(sha256, key, message): the hash is the imported function's name.
    const range = args[spec.hashIdentArg];
    if (range && range[1] - range[0] === 1 && src.tokens[range[0]].type === 'ident') {
      hash = normaliseHash(String(src.tokens[range[0]].value));
    }
  }
  const algos = [describe({
    family: spec.family, name: spec.name ?? null, curve, keySize, hash, mode: spec.mode ?? null,
    parameters, noteCodes: spec.noteCodes,
  })];
  if (spec.also) algos.push(...fromSpec(src, call, spec.also));
  return algos;
}

/**
 * jwt.sign(payload, key[, options][, callback]): HS256 when options give no
 * `algorithm`. An `algorithm` literal is reported by the literal scan; one
 * held in a variable is dynamic.
 */
function jwtSignDefault(src, call) {
  const args = src.args(call.open);
  const range = args[2];
  const library = { family: 'HMAC', hash: 'SHA-256', name: 'HS256', noteCodes: ['library-default'] };
  if (!range || isFunction(src, range)) return describe(library);
  const v = src.readValue(range[0], range[1]);
  if (v.kind === 'object') {
    const alg = src.field(v, 'algorithm');
    if (alg === undefined) return describe(library);
    return alg.kind === 'string' ? null : dynamicAlgorithm('JWT algorithm not written here');
  }
  return dynamicAlgorithm(`JWT options held in ${v.kind === 'unknown' ? v.text : 'an expression'}`);
}

function isFunction(src, [s, e]) {
  if (src.isIdent(s, 'function') || src.isIdent(s, 'async')) return true;
  for (let j = s; j < e; j++) if (src.isPunct(j, '=>')) return true;
  return false;
}

/** `alg: 'none'`, `algorithm: 'none'`, or 'none' inside `algorithms: [ … ]`. */
function isAlgField(src, i) {
  const isKey = (j) => src.isPunct(j, ':') && (src.isIdent(j - 1, 'alg') || src.isIdent(j - 1, 'algorithm'));
  if (isKey(i - 1)) return true;
  for (let j = i - 1; j >= Math.max(0, i - 50); j--) {
    if (src.isPunct(j, '[') && src.match[j] > i) {
      return src.isPunct(j - 1, ':') && src.isIdent(j - 2, 'algorithms');
    }
  }
  return false;
}
