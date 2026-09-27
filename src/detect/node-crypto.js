// node:crypto call sites (DESIGN.md §3.1, §8.3). A call counts only when
// its root is bound to the `crypto` or `node:crypto` module in this file:
// `crypto.createHash(…)` after `import crypto from 'node:crypto'`,
// `createHash(…)` after `import { createHash } from 'node:crypto'`, or
// `require('crypto').createHash(…)`. A `.sign(` or `.randomBytes(` on any
// other object is not cryptography this detector can vouch for.
import {
  describe, dynamicAlgorithm, unknownLiteral, normaliseHash, fromCipherName, fromNodeKeyType,
  fromJwk, modpBits, fromPostQuantumName,
} from '../catalogue.js';
import { makeFinding } from './finding.js';

const RANDOM = new Set(['randomBytes', 'randomUUID', 'randomInt', 'randomFill', 'randomFillSync', 'getRandomValues', 'pseudoRandomBytes']);

/**
 * @param {import('../source.js').SourceFile} src
 */
export function detectNodeCrypto(src) {
  const findings = [];
  for (const call of src.calls) {
    const r = src.resolveCall(call);
    if (!r || r.module !== 'crypto') continue;
    let path = r.path;
    // Web Crypto reached through node:crypto is the Web Crypto detector's.
    if (path.includes('subtle')) continue;
    if (path[0] === 'webcrypto') path = path.slice(1);
    if (path.length === 0) continue;
    const method = path.join('.');
    const read = (i) => {
      const range = src.args(call.open)[i];
      return range ? src.readValue(range[0], range[1]) : undefined;
    };
    const results = classify(src, method, read, call);
    for (const { algo, notes = [] } of results) {
      findings.push(makeFinding(src, call.at, algo, { iface: 'node:crypto', operation: method, notes }));
    }
  }
  return findings;
}

const str = (v) => (v && v.kind === 'string' ? v.value : null);
const num = (v) => (v && v.kind === 'number' ? v.value : null);
const held = (v, what) => dynamicAlgorithm(v && v.kind === 'unknown' && v.text ? `${what} held in ${v.text}` : `${what} not written here`);

/**
 * The algorithm(s) a node:crypto call uses, from its literal arguments.
 * @returns {{ algo: import('../catalogue.js').Algorithm, notes?: object[] }[]}
 */
function classify(src, method, read, call) {
  if (RANDOM.has(method)) return [{ algo: describe({ family: 'CSPRNG' }) }];

  switch (method) {
    case 'createHash':
    case 'hash': {
      const name = str(read(0));
      if (name === null) return [{ algo: held(read(0), 'hash') }];
      const h = normaliseHash(name);
      return [{ algo: h ? describe({ family: 'Hash', hash: h }) : unknownLiteral(name) }];
    }
    case 'createHmac': {
      const name = str(read(0));
      if (name === null) return [{ algo: held(read(0), 'HMAC hash') }];
      return [{ algo: describe({ family: 'HMAC', hash: normaliseHash(name) ?? name }) }];
    }
    case 'createCipheriv': case 'createDecipheriv': case 'createCipher': case 'createDecipher': {
      const name = str(read(0));
      return [{ algo: name === null ? held(read(0), 'cipher') : fromCipherName(name) }];
    }
    case 'generateKeyPair': case 'generateKeyPairSync': {
      const type = str(read(0));
      if (type === null) return [{ algo: held(read(0), 'key type') }];
      const o = read(1);
      const opts = o && o.kind === 'object' ? {
        modulusLength: num(src.field(o, 'modulusLength')),
        namedCurve: str(src.field(o, 'namedCurve')),
        primeLength: num(src.field(o, 'primeLength')),
        group: str(src.field(o, 'group')),
      } : {};
      return [{ algo: fromNodeKeyType(type, opts) }];
    }
    case 'generateKey': case 'generateKeySync': {
      const type = str(read(0));
      const o = read(1);
      const length = o && o.kind === 'object' ? num(src.field(o, 'length')) : null;
      if (type === 'aes') return [{ algo: describe({ family: 'AES', keySize: length }) }];
      if (type === 'hmac') return [{ algo: describe({ family: 'HMAC', keySize: length }) }];
      return [{ algo: type === null ? held(read(0), 'key type') : unknownLiteral(type) }];
    }
    case 'createSign': case 'createVerify':
      return [{ algo: signatureFromName(read(0)) }];
    case 'sign': case 'verify': {
      // One-shot sign/verify: with null, the key alone decides the algorithm
      // (Ed25519, Ed448 and, in recent Node, ML-DSA) — reported as dynamic.
      const v = read(0);
      if (!v || v.kind === 'null') return [{ algo: dynamicAlgorithm('signature algorithm set by the key'), notes: [] }];
      return [{ algo: signatureFromName(v) }];
    }
    case 'createECDH': {
      const curve = str(read(0));
      return [{ algo: describe({ family: 'ECDH', curve }), notes: curve ? [] : [{ code: 'parameter-not-literal', text: 'The curve is not written here: check it by hand.' }] }];
    }
    case 'createDiffieHellman': {
      const v = read(0);
      return [{ algo: describe({ family: 'DH', keySize: num(v) }) }];
    }
    case 'getDiffieHellman': case 'createDiffieHellmanGroup': {
      const g = str(read(0));
      return [{ algo: describe({ family: 'DH', keySize: g ? modpBits(g) : null }) }];
    }
    case 'diffieHellman':
      return [{ algo: describe({ family: 'DH/ECDH' }), notes: [{ code: 'key-decides', text: 'The curve or group is set by the keys at run time: check the key type.' }] }];
    case 'publicEncrypt': case 'privateDecrypt': {
      // Node's default padding for these is OAEP; PKCS#1 v1.5 only when the
      // call names RSA_PKCS1_PADDING.
      const close = src.match[call.open];
      const v15 = src.tokens.slice(call.open, close).some((t) => t.value === 'RSA_PKCS1_PADDING');
      return [{ algo: describe({ family: v15 ? 'RSAES-PKCS1-v1_5' : 'RSA-OAEP' }) }];
    }
    case 'privateEncrypt': case 'publicDecrypt':
      return [{ algo: describe({ family: 'RSA raw signature' }) }];
    case 'pbkdf2': case 'pbkdf2Sync': {
      const iterations = num(read(2));
      const digest = str(read(4));
      const notes = iterations === null ? [{ code: 'parameter-not-literal', text: 'The iteration count is not written here: check it by hand.' }] : [];
      return [{ algo: describe({ family: 'PBKDF2', hash: digest ? normaliseHash(digest) ?? digest : null, parameters: iterations === null ? {} : { iterations } }), notes }];
    }
    case 'scrypt': case 'scryptSync': {
      const o = read(3);
      const cost = o && o.kind === 'object' ? (num(src.field(o, 'N')) ?? num(src.field(o, 'cost'))) : null;
      return [{ algo: describe({ family: 'scrypt', parameters: cost === null ? {} : { N: cost } }) }];
    }
    case 'hkdf': case 'hkdfSync': {
      const digest = str(read(0));
      return [{ algo: describe({ family: 'HKDF', hash: digest ? normaliseHash(digest) ?? digest : null }) }];
    }
    case 'createPublicKey': case 'createPrivateKey': {
      const o = read(0);
      if (o && o.kind === 'object') {
        const key = src.field(o, 'key');
        const jwk = key && key.kind === 'object' ? key : o;
        const algo = fromJwk(str(src.field(jwk, 'kty')), str(src.field(jwk, 'crv')));
        if (algo) return [{ algo }];
      }
      return [{ algo: dynamicAlgorithm('key type set by the key material') }];
    }
    case 'KeyObject.from':
      return [{ algo: dynamicAlgorithm('key type set by the key') }];
    case 'X509Certificate':
      return [{ algo: dynamicAlgorithm('X.509 certificate: its algorithms are inside the certificate') }];
    case 'encapsulate': case 'decapsulate':
      return [{ algo: dynamicAlgorithm('key encapsulation: the algorithm is set by the key') }];
    default:
      return [];
  }
}

/** 'sha256' → a signature with SHA-256 (the key decides RSA, ECDSA or DSA); 'RSA-SHA256' → RSA. */
function signatureFromName(v) {
  const name = v && v.kind === 'string' ? v.value : null;
  if (name === null) return held(v, 'signature algorithm');
  const pq = fromPostQuantumName(name);
  if (pq) return pq;
  const rsa = /^rsa-(.+)$/i.exec(name);
  if (rsa) return describe({ family: 'RSASSA-PKCS1-v1_5', hash: normaliseHash(rsa[1]) ?? rsa[1] });
  const ecdsa = /^ecdsa-with-(.+)$/i.exec(name);
  if (ecdsa) return describe({ family: 'ECDSA', hash: normaliseHash(ecdsa[1]) ?? ecdsa[1] });
  const h = normaliseHash(name);
  if (h) return describe({ family: 'Signature', hash: h, noteCodes: ['key-decides'] });
  return unknownLiteral(name);
}
