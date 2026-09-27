// Web Crypto (SubtleCrypto) call sites, and crypto.getRandomValues /
// crypto.randomUUID (DESIGN.md §3.1, §8.2).
import { fromWebCryptoName, dynamicAlgorithm, describe } from '../catalogue.js';
import { makeFinding } from './finding.js';

// The SubtleCrypto methods, and which of their arguments is an algorithm:
// deriveKey(algorithm, baseKey, derivedKeyAlgorithm, …),
// importKey(format, keyData, algorithm, …), wrapKey(format, key,
// wrappingKey, wrapAlgorithm), unwrapKey(format, wrapped, unwrappingKey,
// unwrapAlgorithm, unwrappedKeyAlgorithm, …); the key-encapsulation methods
// are from the Modern Algorithms draft. exportKey and getPublicKey take no
// algorithm and are not findings.
const METHODS = {
  encrypt: [0], decrypt: [0], sign: [0], verify: [0], digest: [0], deriveBits: [0], generateKey: [0],
  deriveKey: [0, 2], importKey: [2], wrapKey: [3], unwrapKey: [3, 4],
  encapsulateBits: [0], encapsulateKey: [0, 2], decapsulateBits: [0], decapsulateKey: [0, 3],
};

// `crypto`, `webcrypto`, `nodeCrypto`, `globalThis.crypto`: the object in
// front of `.subtle` must say crypto. `theme.subtle.encrypt(…)` is not Web
// Crypto (DESIGN.md §8.2).
const CRYPTOISH = /crypto/i;

/**
 * @param {import('../source.js').SourceFile} src
 */
export function detectWebCrypto(src) {
  const findings = [];
  const aliases = subtleAliases(src);
  for (const call of src.calls) {
    const c = call.chain;
    const method = c[c.length - 1];

    if (method === 'getRandomValues' || method === 'randomUUID') {
      if (!isCryptoRoot(src, call)) continue;
      const r = src.resolveCall(call);
      if (r && r.module === 'crypto') continue; // node:crypto's; that detector reports it
      findings.push(makeFinding(src, call.at, describe({ family: 'CSPRNG' }), { iface: 'web-crypto', operation: method }));
      continue;
    }

    const argIndexes = METHODS[method];
    if (!argIndexes || !isSubtleCall(src, call, aliases)) continue;
    const args = src.args(call.open);
    for (const ai of argIndexes) {
      const range = args[ai];
      const { algo, notes } = range ? readAlgorithm(src, range) : { algo: dynamicAlgorithm(`${method}: no algorithm argument`), notes: [] };
      // Point at the argument itself when it is written inline, so a call
      // spread over several lines points at the line that names the
      // algorithm.
      findings.push(makeFinding(src, range ? range[0] : call.at, algo, { iface: 'web-crypto', operation: method, notes }));
    }
  }
  return findings;
}

/** `X.subtle.method(` with X crypto-ish, or `alias.method(` with a bound alias. */
function isSubtleCall(src, call, aliases) {
  const c = call.chain;
  const n = c.length;
  if (n >= 2 && c[n - 2] === 'subtle') {
    if (n >= 3) return CRYPTOISH.test(c[n - 3]) && c[n - 3] !== '[]';
    if (call.rootModule) return CRYPTOISH.test(call.rootModule);
    if (call.rootGroup) return groupMentionsCrypto(src, call.rootGroup[0], call.rootGroup[1]);
  }
  if (n === 2 && !call.rootModule && !call.rootGroup) {
    if (aliases.has(c[0])) return true;
    const r = src.resolveCall(call);
    if (r && r.module === 'crypto' && r.path[r.path.length - 2] === 'subtle') return true;
  }
  return false;
}

/** `crypto.getRandomValues(`, `window.crypto.randomUUID(`, `(a || crypto).getRandomValues(`. */
function isCryptoRoot(src, call) {
  const c = call.chain;
  if (c.length >= 2) return CRYPTOISH.test(c[c.length - 2]);
  if (call.rootModule) return CRYPTOISH.test(call.rootModule);
  if (call.rootGroup) return groupMentionsCrypto(src, call.rootGroup[0], call.rootGroup[1]);
  return false;
}

/**
 * Local names bound to a SubtleCrypto object: `const subtle =
 * globalThis.crypto.subtle`, `this.s = …` is not followed, `const { subtle }
 * = crypto`, `function f(s = crypto.subtle)`. A variable merely named
 * `subtle` is not one.
 */
function subtleAliases(src) {
  const aliases = new Set();
  const toks = src.tokens;
  for (const d of src.declarations) {
    if (d.name && d.init && endsWithCryptoSubtle(src, d.init[0], d.init[1])) aliases.add(d.name);
    if (d.pattern && d.init && src.isPunct(d.pattern[0], '{') && rangeMentionsCrypto(src, d.init[0], d.init[1])) {
      for (const [local, key] of src.patternEntries(d.pattern[0], d.pattern[1])) if (key === 'subtle') aliases.add(local);
    }
  }
  // Plain assignments and default parameters: `subtle = crypto.subtle`.
  for (let e = 1; e < toks.length; e++) {
    if (!src.isPunct(e, '=') || !src.isIdent(e - 1) || src.isMemberDot(e - 2)) continue;
    const end = src.expressionEnd(e + 1);
    if (endsWithCryptoSubtle(src, e + 1, end)) aliases.add(String(toks[e - 1].value));
  }
  return aliases;
}

function endsWithCryptoSubtle(src, s, e) {
  if (e - s < 3 || !src.isIdent(e - 1, 'subtle') || !src.isMemberDot(e - 2)) return false;
  const before = src.tokens[e - 3];
  if (before.type === 'ident') return CRYPTOISH.test(String(before.value));
  if (src.isPunct(e - 3, ')')) {
    const open = src.match[e - 3];
    return open >= s && groupMentionsCrypto(src, open, e - 3);
  }
  return false;
}

function groupMentionsCrypto(src, open, close) {
  for (let j = open; j <= close; j++) {
    const t = src.tokens[j];
    if ((t.type === 'ident' || t.type === 'string') && CRYPTOISH.test(String(t.value))) return true;
  }
  return false;
}

function rangeMentionsCrypto(src, s, e) {
  return e > s && groupMentionsCrypto(src, s, e - 1);
}

/**
 * The algorithm named by one argument: a string, or an object with `name`
 * and its parameters, read through constants (DESIGN.md §8.1).
 */
function readAlgorithm(src, [s, e]) {
  const v = src.readValue(s, e);
  const notes = [];
  if (v.kind === 'string') return { algo: fromWebCryptoName(v.value), notes };
  if (v.kind === 'object') {
    const name = src.fieldString(v, 'name');
    if (typeof name !== 'string') {
      const range = src.fields(v).get('name');
      return { algo: dynamicAlgorithm(`algorithm name held in ${range ? src.textOf(range[0], range[1]) : 'an expression'}`), notes };
    }
    const p = {};
    for (const key of ['namedCurve', 'hash']) {
      const value = src.fieldString(v, key);
      if (typeof value === 'string') p[key] = value;
      else if (value === null) notes.push(parameterNote(src, v, key));
    }
    for (const key of ['length', 'modulusLength', 'iterations']) {
      const value = src.fieldNumber(v, key);
      if (typeof value === 'number') p[key] = value;
      else if (value === null) notes.push(parameterNote(src, v, key));
    }
    return { algo: fromWebCryptoName(name, p), notes };
  }
  return { algo: dynamicAlgorithm(`algorithm held in ${v.text || 'an expression'}`), notes };
}

function parameterNote(src, obj, key) {
  const range = src.fields(obj).get(key);
  const held = range ? src.textOf(range[0], range[1]) : key;
  return { code: 'parameter-not-literal', text: `${key} is not written here (held in ${held}): check it by hand.` };
}
