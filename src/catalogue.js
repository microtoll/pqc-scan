// The algorithm classes, the name normalisers, the priority heuristic and
// the library catalogue (DESIGN.md §3.1, §4, §8.4, §8.5).
//
// Everything here is data or a pure function of data. Nothing in this file
// knows about tokens or files.

/** The date the catalogue was last reviewed; printed in every report. */
export const CATALOGUE_DATE = '2026-09';

/**
 * The classes of DESIGN.md §3.1. Only `public-key` is quantum-vulnerable:
 * Shor's algorithm breaks RSA, finite-field and elliptic-curve Diffie–Hellman
 * and every elliptic-curve or RSA signature. Grover's algorithm only halves
 * the effective strength of symmetric keys and hashes.
 */
export const CLASSES = ['public-key', 'post-quantum', 'symmetric', 'hash', 'kdf', 'random', 'unknown'];

export const CLASS_LABELS = {
  'public-key': 'Quantum-vulnerable public-key',
  'post-quantum': 'Post-quantum or hybrid',
  symmetric: 'Symmetric',
  hash: 'Hash',
  kdf: 'Key derivation or password hash',
  random: 'Random numbers',
  unknown: 'Unknown — check by hand',
};

// kind: what the algorithm is used for, which drives the priority.
//   key-agreement, public-key-encryption, signature: as named.
//   public-key: a public-key key whose use the call does not say (an RSA or
//     elliptic-curve key pair, a JSON Web Key).
const FAMILIES = {
  // Quantum-vulnerable public-key.
  ECDH: ['public-key', 'key-agreement'],
  X25519: ['public-key', 'key-agreement'],
  X448: ['public-key', 'key-agreement'],
  DH: ['public-key', 'key-agreement'],
  'DH/ECDH': ['public-key', 'key-agreement'],
  ECDSA: ['public-key', 'signature'],
  Ed25519: ['public-key', 'signature'],
  Ed448: ['public-key', 'signature'],
  EdDSA: ['public-key', 'signature'],
  Schnorr: ['public-key', 'signature'],
  BLS: ['public-key', 'signature'],
  DSA: ['public-key', 'signature'],
  'RSA-PSS': ['public-key', 'signature'],
  'RSASSA-PKCS1-v1_5': ['public-key', 'signature'],
  'RSA raw signature': ['public-key', 'signature'],
  Signature: ['public-key', 'signature'],
  'RSA-OAEP': ['public-key', 'public-key-encryption'],
  'RSAES-PKCS1-v1_5': ['public-key', 'public-key-encryption'],
  ECIES: ['public-key', 'public-key-encryption'],
  'X25519-XSalsa20-Poly1305': ['public-key', 'public-key-encryption'],
  'X25519 sealed box': ['public-key', 'public-key-encryption'],
  'HPKE DHKEM': ['public-key', 'public-key-encryption'],
  OpenPGP: ['public-key', 'public-key-encryption'],
  'OpenPGP signature': ['public-key', 'signature'],
  RSA: ['public-key', 'public-key'],
  EC: ['public-key', 'public-key'],
  // Post-quantum and hybrid (FIPS 203, 204, 205; the IETF hybrid names).
  'ML-KEM': ['post-quantum', 'kem'],
  'ML-DSA': ['post-quantum', 'pq-signature'],
  'SLH-DSA': ['post-quantum', 'pq-signature'],
  Kyber: ['post-quantum', 'kem'],
  'Hybrid KEM': ['post-quantum', 'kem'],
  // Symmetric.
  AES: ['symmetric', 'cipher'],
  'ChaCha20-Poly1305': ['symmetric', 'cipher'],
  'XChaCha20-Poly1305': ['symmetric', 'cipher'],
  'XSalsa20-Poly1305': ['symmetric', 'cipher'],
  ChaCha20: ['symmetric', 'cipher'],
  Salsa20: ['symmetric', 'cipher'],
  '3DES': ['symmetric', 'cipher'],
  DES: ['symmetric', 'cipher'],
  RC4: ['symmetric', 'cipher'],
  RC2: ['symmetric', 'cipher'],
  Blowfish: ['symmetric', 'cipher'],
  Rabbit: ['symmetric', 'cipher'],
  HMAC: ['symmetric', 'mac'],
  KMAC: ['symmetric', 'mac'],
  // Hashes.
  Hash: ['hash', 'hash'],
  // Key derivation and password hashing.
  HKDF: ['kdf', 'kdf'],
  PBKDF2: ['kdf', 'kdf'],
  scrypt: ['kdf', 'password-hash'],
  Argon2: ['kdf', 'password-hash'],
  Argon2id: ['kdf', 'password-hash'],
  Argon2i: ['kdf', 'password-hash'],
  Argon2d: ['kdf', 'password-hash'],
  bcrypt: ['kdf', 'password-hash'],
  // Random numbers.
  CSPRNG: ['random', 'random'],
  // Could not be read.
  Unknown: ['unknown', 'unknown'],
};

// The hybrid key-encapsulation names, as written in TLS group lists and in
// Web Crypto (DESIGN.md §3.1). Kept exactly as their specifications spell
// them; matching is case-insensitive.
export const HYBRID_NAMES = [
  'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'MLKEM768-X25519', 'X-Wing',
  'X25519Kyber768Draft00', 'X25519Kyber768', 'x25519_kyber768', 'p256_kyber768', 'curveSM2MLKEM768',
];
const HYBRID_BY_LOWER = new Map(HYBRID_NAMES.map((n) => [n.toLowerCase(), n]));
// Pre-standard Kyber: post-quantum, but not the algorithm NIST standardised.
const PRE_STANDARD = /kyber/i;

// ---------------------------------------------------------------------------
// Name normalisers
// ---------------------------------------------------------------------------

/** 'sha256', 'SHA-256', 'sha-256' → 'SHA-256'; null when not a hash name. */
export function normaliseHash(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.toLowerCase().replace(/[\s_]/g, '');
  let m;
  if (s === 'md5') return 'MD5';
  if (s === 'md4') return 'MD4';
  if ((m = /^sha-?(1|224|256|384|512)$/.exec(s))) return `SHA-${m[1]}`;
  if ((m = /^sha-?512[-/](224|256)$/.exec(s))) return `SHA-512/${m[1]}`;
  if ((m = /^sha3-?(224|256|384|512)$/.exec(s))) return `SHA3-${m[1]}`;
  if ((m = /^shake-?(128|256)$/.exec(s))) return `SHAKE${m[1]}`;
  if ((m = /^keccak-?(224|256|384|512)$/.exec(s))) return `Keccak-${m[1]}`;
  if (/^(ripemd|rmd)-?160$/.test(s)) return 'RIPEMD-160';
  if ((m = /^blake2([bs])(?:-?(\d+))?$/.exec(s))) return `BLAKE2${m[1]}${m[2] ? `-${m[2]}` : ''}`;
  if (s === 'blake3') return 'BLAKE3';
  if (s === 'sm3') return 'SM3';
  return null;
}

/** 'prime256v1', 'secp256r1', 'P-256', 'p256' → 'P-256'; others as written. */
export function normaliseCurve(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.toLowerCase().replace(/[\s_-]/g, '');
  if (['p256', 'prime256v1', 'secp256r1', 'nistp256'].includes(s)) return 'P-256';
  if (['p384', 'secp384r1', 'nistp384'].includes(s)) return 'P-384';
  if (['p521', 'secp521r1', 'nistp521'].includes(s)) return 'P-521';
  if (['p224', 'secp224r1'].includes(s)) return 'P-224';
  if (['p192', 'prime192v1', 'secp192r1'].includes(s)) return 'P-192';
  if (['secp256k1', 'k256'].includes(s)) return 'secp256k1';
  if (s === 'x25519' || s === 'curve25519') return 'X25519';
  if (s === 'x448' || s === 'curve448') return 'X448';
  if (s === 'ed25519') return 'Ed25519';
  if (s === 'ed448') return 'Ed448';
  return raw;
}

// ---------------------------------------------------------------------------
// Describing an algorithm
// ---------------------------------------------------------------------------

/**
 * @typedef {object} Algorithm
 * @property {string} algorithm   the normalised display name, e.g. 'AES-256-GCM'
 * @property {string} family
 * @property {string} class
 * @property {string} kind
 * @property {number|null} keySize
 * @property {string|null} curve
 * @property {string|null} hash
 * @property {Record<string, number|string>} parameters
 * @property {boolean} dynamic
 * @property {{code: string, text: string}[]} notes
 */

/**
 * Builds the normalised description of one algorithm use.
 * @param {object} spec
 * @param {string} spec.family       a key of FAMILIES
 * @param {number|null} [spec.keySize]
 * @param {string|null} [spec.curve]
 * @param {string|null} [spec.hash]
 * @param {string|null} [spec.mode]  a cipher mode, e.g. 'GCM'
 * @param {string|null} [spec.name]  an exact display name (hybrids, ML-KEM-768)
 * @param {Record<string, number|string>} [spec.parameters]
 * @param {boolean} [spec.dynamic]
 * @param {string[]} [spec.noteCodes] extra notes by code
 * @returns {Algorithm}
 */
export function describe(spec) {
  const family = spec.family in FAMILIES ? spec.family : 'Unknown';
  const [cls, kind] = FAMILIES[family];
  const keySize = typeof spec.keySize === 'number' ? spec.keySize : null;
  const curve = spec.curve ? normaliseCurve(spec.curve) : null;
  const hash = spec.hash ?? null;
  const mode = spec.mode ? String(spec.mode).toUpperCase() : null;
  const parameters = { ...(spec.parameters ?? {}) };
  const algorithm = spec.name ?? displayName(family, { keySize, curve, hash, mode });
  const notes = notesFor({ family, keySize, curve, hash, mode, parameters, algorithm });
  for (const code of spec.noteCodes ?? []) if (NOTE_TEXT[code]) notes.push({ code, text: NOTE_TEXT[code] });
  return {
    algorithm, family, class: cls, kind, keySize, curve, hash, parameters,
    dynamic: Boolean(spec.dynamic), notes,
  };
}

/** A use whose algorithm could not be read statically (DESIGN.md §3.1). */
export function dynamicAlgorithm(what) {
  const text = String(what);
  const short = text.length > 80 ? `${text.slice(0, 79)}…` : text;
  return describe({ family: 'Unknown', name: `dynamic (${short})`, dynamic: true });
}

/** An algorithm written as a literal this catalogue does not know. */
export function unknownLiteral(literal) {
  return describe({ family: 'Unknown', name: literal, noteCodes: ['not-catalogued'] });
}

function displayName(family, { keySize, curve, hash, mode }) {
  switch (family) {
    case 'AES': return ['AES', keySize, mode].filter(Boolean).join('-');
    case 'HMAC': case 'HKDF': case 'PBKDF2': return hash ? `${family}-${hash}` : family;
    case 'Hash': return hash ?? 'Hash';
    case 'ECDH': case 'ECDSA': case 'EC': case 'Schnorr': return curve ? `${family} ${curve}` : family;
    case 'RSA': case 'RSA-OAEP': case 'RSA-PSS': case 'RSASSA-PKCS1-v1_5': case 'RSAES-PKCS1-v1_5': case 'DH': case 'DSA':
      return keySize ? `${family} ${keySize}-bit` : family;
    case 'Signature': return hash ? `Signature with ${hash}` : 'Signature';
    case 'CSPRNG': return 'Random (CSPRNG)';
    case '3DES': case 'DES': case 'Blowfish': case 'RC2':
      return mode ? `${family}-${mode}` : family;
    default: return family;
  }
}

// The fixed texts of the symmetric and hash notes (DESIGN.md §4, item 4).
// The codes are part of the JSON schema; the texts may be reworded.
export const NOTE_TEXT = {
  'aes-128': 'AES-128: consider AES-256 for data that must outlive the transition (Grover\'s algorithm halves the effective strength).',
  'weak-hash': 'SHA-1 and MD5: collisions are practical today, so replace them wherever they protect something (a signature, a stored password, an integrity check), regardless of quantum computers. As a plain identifier the risk is lower: check what a collision would let someone do.',
  'replace-now': 'DES, 3DES, RC4, RC2 and Blowfish: replace now, on classical grounds.',
  ecb: 'ECB mode shows patterns in the data: replace now, on classical grounds.',
  'pbkdf2-iterations': 'PBKDF2 with under 100,000 iterations: weak on classical grounds.',
  unsigned: 'A JSON Web Token with alg "none" has no signature at all: replace now.',
  'pre-standard': 'Kyber before standardisation is not ML-KEM (FIPS 203): move to ML-KEM.',
  'not-catalogued': 'This algorithm name is not in the catalogue: check it by hand.',
  'key-decides': 'The algorithm is set by the key at run time: check the key type.',
  'declared-here': 'Declared here by name; check that it reaches the call that uses it.',
  'library-default': 'Not written at the call: this is the library\'s documented default.',
};

function notesFor({ family, keySize, hash, mode, parameters, algorithm }) {
  const notes = [];
  const add = (code) => notes.push({ code, text: NOTE_TEXT[code] });
  if (family === 'AES' && keySize === 128) add('aes-128');
  if (hash === 'MD5' || hash === 'SHA-1' || hash === 'MD4') {
    // For HMAC, SHA-1 and MD5 are not broken the way a bare hash or a
    // signature is (HMAC does not rely on collision resistance), so the
    // note is only given for hashes and signatures.
    if (family === 'Hash' || FAMILIES[family]?.[1] === 'signature') add('weak-hash');
  }
  if (['3DES', 'DES', 'RC4', 'RC2', 'Blowfish'].includes(family)) add('replace-now');
  if (mode === 'ECB') add('ecb');
  if (family === 'PBKDF2' && typeof parameters.iterations === 'number' && parameters.iterations < 100000) add('pbkdf2-iterations');
  if (family === 'Kyber' || (family === 'Hybrid KEM' && PRE_STANDARD.test(algorithm))) add('pre-standard');
  return notes;
}

// ---------------------------------------------------------------------------
// Web Crypto names (W3C Web Cryptography API, and the Modern Algorithms
// draft for ML-KEM, ML-DSA, ChaCha20-Poly1305 and the hybrids)
// ---------------------------------------------------------------------------

/**
 * @param {string} name   the algorithm name as written
 * @param {object} p      the literal fields read beside it
 * @returns {Algorithm}
 */
export function fromWebCryptoName(name, p = {}) {
  const n = String(name);
  const upper = n.toUpperCase();
  const hash = p.hash ? normaliseHash(p.hash) : null;
  let m;
  if ((m = /^AES-(GCM|CBC|CTR|KW|OCB)$/.exec(upper))) return describe({ family: 'AES', mode: m[1], keySize: p.length });
  if (upper === 'CHACHA20-POLY1305') return describe({ family: 'ChaCha20-Poly1305' });
  if (upper === 'HMAC') return describe({ family: 'HMAC', hash, keySize: p.length });
  if (/^KMAC(128|256)$/.test(upper)) return describe({ family: 'KMAC', name: upper });
  const h = normaliseHash(n);
  if (h) return describe({ family: 'Hash', hash: h });
  if (/^C?SHAKE(128|256)$/.test(upper) || /^TURBOSHAKE(128|256)$/.test(upper)) return describe({ family: 'Hash', hash: n });
  if (upper === 'HKDF') return describe({ family: 'HKDF', hash });
  if (upper === 'PBKDF2') {
    const parameters = typeof p.iterations === 'number' ? { iterations: p.iterations } : {};
    return describe({ family: 'PBKDF2', hash, parameters });
  }
  if (/^ARGON2(ID|I|D)$/.test(upper)) return describe({ family: `Argon2${upper.slice(6).toLowerCase()}` });
  if (upper === 'ECDH') return describe({ family: 'ECDH', curve: p.namedCurve });
  if (upper === 'ECDSA') return describe({ family: 'ECDSA', curve: p.namedCurve, hash });
  if (upper === 'X25519') return describe({ family: 'X25519' });
  if (upper === 'X448') return describe({ family: 'X448' });
  if (upper === 'ED25519') return describe({ family: 'Ed25519' });
  if (upper === 'ED448') return describe({ family: 'Ed448' });
  if (upper === 'RSA-OAEP') return describe({ family: 'RSA-OAEP', keySize: p.modulusLength, hash });
  if (upper === 'RSA-PSS') return describe({ family: 'RSA-PSS', keySize: p.modulusLength, hash });
  if (upper === 'RSASSA-PKCS1-V1_5') return describe({ family: 'RSASSA-PKCS1-v1_5', keySize: p.modulusLength, hash });
  return fromPostQuantumName(n) ?? unknownLiteral(n);
}

/** ML-KEM-768, ML-DSA-65, SLH-DSA-…, and the hybrid names; null otherwise. */
export function fromPostQuantumName(name) {
  const n = String(name);
  const hybrid = HYBRID_BY_LOWER.get(n.toLowerCase());
  if (hybrid) return describe({ family: 'Hybrid KEM', name: hybrid });
  let m;
  if ((m = /^ML-?KEM-?(512|768|1024)$/i.exec(n))) return describe({ family: 'ML-KEM', name: `ML-KEM-${m[1]}` });
  if ((m = /^ML-?DSA-?(44|65|87)$/i.exec(n))) return describe({ family: 'ML-DSA', name: `ML-DSA-${m[1]}` });
  if (/^SLH-?DSA/i.test(n)) return describe({ family: 'SLH-DSA', name: n.toUpperCase().replace(/^SLHDSA/, 'SLH-DSA') });
  if ((m = /^kyber-?(512|768|1024)$/i.exec(n))) return describe({ family: 'Kyber', name: `Kyber${m[1]}` });
  return null;
}

// ---------------------------------------------------------------------------
// node:crypto and OpenSSL names
// ---------------------------------------------------------------------------

/** 'aes-256-gcm', 'aes256', 'des-ede3-cbc', 'chacha20-poly1305', 'rc4' … */
export function fromCipherName(name) {
  const s = String(name).toLowerCase();
  let m;
  if ((m = /^(?:id-)?aes-?(128|192|256)(?:-([a-z0-9]+))?/.exec(s))) {
    // OpenSSL's bare 'aes256' is AES-256-CBC.
    return describe({ family: 'AES', keySize: Number(m[1]), mode: m[2] ?? 'CBC' });
  }
  if ((m = /^aes-(gcm|cbc|ctr|ecb|ofb|cfb|ccm|ocb|kw|siv|gcm-siv)$/.exec(s))) return describe({ family: 'AES', mode: m[1] });
  if (s === 'chacha20-poly1305') return describe({ family: 'ChaCha20-Poly1305' });
  if (s === 'chacha20') return describe({ family: 'ChaCha20' });
  if (/^(des-ede3|des3|3des|tripledes)/.test(s)) return describe({ family: '3DES', mode: (/-(cbc|ecb|cfb|ofb)$/.exec(s) ?? [])[1] });
  if (/^des(-|$)/.test(s)) return describe({ family: 'DES', mode: (/-(cbc|ecb|cfb|ofb)$/.exec(s) ?? [])[1] });
  if (/^rc4/.test(s)) return describe({ family: 'RC4' });
  if (/^rc2/.test(s)) return describe({ family: 'RC2' });
  if (/^(bf|blowfish)/.test(s)) return describe({ family: 'Blowfish' });
  return unknownLiteral(String(name));
}

const MODP_BITS = { modp1: 768, modp2: 1024, modp5: 1536, modp14: 2048, modp15: 3072, modp16: 4096, modp17: 6144, modp18: 8192 };
export function modpBits(group) { return MODP_BITS[String(group).toLowerCase()] ?? null; }

/**
 * A node:crypto key-pair type ('rsa', 'ec', 'ed25519', 'x25519', 'dh', …)
 * with its literal options.
 */
export function fromNodeKeyType(type, opts = {}) {
  const t = String(type).toLowerCase();
  switch (t) {
    case 'rsa': return describe({ family: 'RSA', keySize: opts.modulusLength });
    case 'rsa-pss': return describe({ family: 'RSA-PSS', keySize: opts.modulusLength });
    case 'dsa': return describe({ family: 'DSA', keySize: opts.modulusLength });
    case 'ec': return describe({ family: 'EC', curve: opts.namedCurve });
    case 'ed25519': return describe({ family: 'Ed25519' });
    case 'ed448': return describe({ family: 'Ed448' });
    case 'x25519': return describe({ family: 'X25519' });
    case 'x448': return describe({ family: 'X448' });
    case 'dh': return describe({ family: 'DH', keySize: opts.primeLength ?? modpBits(opts.group) });
    default: return fromPostQuantumName(t) ?? unknownLiteral(String(type));
  }
}

/** A JSON Web Key's kty and crv (RFC 7517, RFC 8037). */
export function fromJwk(kty, crv) {
  const c = typeof crv === 'string' ? crv : null;
  if (c === 'Ed25519' || c === 'Ed448') return describe({ family: c });
  if (c === 'X25519' || c === 'X448') return describe({ family: c });
  if (c) return describe({ family: 'EC', curve: c });
  if (typeof kty === 'string' && kty.toUpperCase() === 'RSA') return describe({ family: 'RSA' });
  if (typeof kty === 'string' && kty.toUpperCase() === 'AKP') return describe({ family: 'ML-DSA' });
  return null;
}

// ---------------------------------------------------------------------------
// JSON Web Algorithms (RFC 7518, RFC 8037, RFC 9864, the ML-DSA JOSE draft)
// ---------------------------------------------------------------------------

const JWS_HASH = { 256: 'SHA-256', 384: 'SHA-384', 512: 'SHA-512' };
const ES_CURVE = { 256: 'P-256', 384: 'P-384', 512: 'P-521' };

/** A JWS or JWE algorithm identifier → Algorithm; null when it is not one. */
export function fromJoseAlg(alg) {
  if (typeof alg !== 'string') return null;
  let m;
  if ((m = /^HS(256|384|512)$/.exec(alg))) return describe({ family: 'HMAC', hash: JWS_HASH[m[1]], name: alg });
  if ((m = /^RS(256|384|512)$/.exec(alg))) return describe({ family: 'RSASSA-PKCS1-v1_5', hash: JWS_HASH[m[1]], name: alg });
  if ((m = /^PS(256|384|512)$/.exec(alg))) return describe({ family: 'RSA-PSS', hash: JWS_HASH[m[1]], name: alg });
  if ((m = /^ES(256|384|512)$/.exec(alg))) return describe({ family: 'ECDSA', curve: ES_CURVE[m[1]], hash: JWS_HASH[m[1]], name: alg });
  if (alg === 'ES256K') return describe({ family: 'ECDSA', curve: 'secp256k1', hash: 'SHA-256', name: alg });
  if (alg === 'EdDSA') return describe({ family: 'EdDSA', name: alg });
  if (alg === 'Ed25519' || alg === 'Ed448') return describe({ family: alg, name: alg });
  if (/^RSA-OAEP(-256|-384|-512)?$/.test(alg)) return describe({ family: 'RSA-OAEP', name: alg });
  if (alg === 'RSA1_5') return describe({ family: 'RSAES-PKCS1-v1_5', name: alg });
  if (/^ECDH-ES(\+A(128|192|256)KW)?$/.test(alg)) return describe({ family: 'ECDH', name: alg });
  if ((m = /^A(128|192|256)KW$/.exec(alg))) return describe({ family: 'AES', keySize: Number(m[1]), mode: 'KW', name: alg });
  if ((m = /^A(128|192|256)GCMKW$/.exec(alg))) return describe({ family: 'AES', keySize: Number(m[1]), mode: 'GCM', name: alg });
  if ((m = /^A(128|192|256)GCM$/.exec(alg))) return describe({ family: 'AES', keySize: Number(m[1]), mode: 'GCM', name: alg });
  if ((m = /^A(128|192|256)CBC-HS(256|384|512)$/.exec(alg))) return describe({ family: 'AES', keySize: Number(m[1]), mode: 'CBC', name: alg });
  if (/^PBES2-HS(256|384|512)\+A(128|192|256)KW$/.test(alg)) return describe({ family: 'PBKDF2', name: alg });
  if ((m = /^ML-DSA-(44|65|87)$/.exec(alg))) return describe({ family: 'ML-DSA', name: alg });
  return null;
}

// ---------------------------------------------------------------------------
// The priority heuristic (DESIGN.md §4 item 3, §8.4)
// ---------------------------------------------------------------------------

// Words are compared after splitting identifiers at camelCase, underscores,
// hyphens and digits, lower-cased: `deriveSealingSharedBits` gives
// derive, sealing, shared, bits.
const SEAL_WORDS = [/^seal/, /^unseal/, /^encrypt/, /^decrypt/, /^(un)?wrap/, /^stor(e|ed|es|age|ing)$/, /^envelope/, /^archiv/, /^backup/, /^persist/];
const SESSION_WORDS = [/^tls$/, /^sessions?$/, /^handshake/, /^transport/, /^sockets?$/];
// WebAuthn, passkey, assertion and COSE (the key format WebAuthn uses): a
// passkey's public key only ever verifies signatures. Found on a real
// application, where a WebAuthn P-256 key read from COSE was reported High
// (fixture node-crypto/webauthn.js).
// A certificate (X.509, or a key pair a server calls its "certs") is a
// signing artefact. Found on a public wiki, where the RSA key pair that signs
// its tokens was made under the comment "Generate certificates" and reported
// High (fixture node-crypto/certificates.js, DESIGN.md §8.12).
const SIGN_WORDS = [/^sign(s|ed|ing|er|ature|atures)?$/, /^verif/, /^jwt$/, /^auth/, /^webauthn$/, /^passkeys?$/, /^assertions?$/, /^cose$/, /^certs?$/, /^certificates?$/, /^x509$/];

const firstWord = (words, patterns) => {
  for (const w of words) if (patterns.some((p) => p.test(w))) return w;
  return null;
};

const REPLACEMENT = {
  high: 'A hybrid seal (X25519MLKEM768, or ML-KEM-768 with the classical curve) for everything sealed from now on; re-seal old data that must outlive the transition.',
  medium: 'ML-DSA or SLH-DSA where the platform offers them; plan, do not rush.',
  low: 'Enable a hybrid key-exchange group (X25519MLKEM768); the exposure is the session, not the archive.',
};

/**
 * @param {string} kind       the Algorithm's kind
 * @param {string[]} words    the words near the call, in order
 * @returns {{ priority: 'high'|'medium'|'low', reason: string, replacement: string }}
 */
export function prioritise(kind, words) {
  const result = (priority, reason) => ({ priority, reason, replacement: REPLACEMENT[priority] });
  if (kind === 'signature') return result('medium', 'signature: forgeable only once a large quantum computer exists');
  const seal = firstWord(words, SEAL_WORDS);
  if (kind === 'public-key') {
    // A key whose use the call does not say: a signing word decides Medium
    // unless a sealing word is also there (the conservative reading).
    const sign = firstWord(words, SIGN_WORDS);
    if (sign && !seal) return result('medium', `key of unstated use; word "${sign}" near the call suggests signing`);
  }
  if (seal) return result('high', `word "${seal}" near the call: data sealed with a classical key can be recorded now and opened later`);
  const session = firstWord(words, SESSION_WORDS);
  if (session) return result('low', `word "${session}" near the call: a session key exchange`);
  return result('high', 'no context words near the call; treated as High until a person checks');
}

export const TLS_LOW = {
  priority: 'low',
  reason: 'TLS key exchange without a hybrid group: a session key exchange',
  replacement: REPLACEMENT.low,
};

/**
 * Splits identifiers and prose into lower-case words.
 * @param {string} text
 * @returns {string[]}
 */
export function splitWords(text) {
  return String(text)
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

// ---------------------------------------------------------------------------
// The library catalogue (DESIGN.md §8.5)
// ---------------------------------------------------------------------------
//
// pq: whether the package offers post-quantum algorithms —
//   'yes', 'partial' (some, or off by default), 'no', 'check' (depends on
//   the version or the platform: read its release notes), 'n/a' (it offers
//   only symmetric, hash or key-derivation algorithms, which quantum
//   computers do not break).
// calls: member paths (from the module object) → the algorithm the call
//   uses. The longest matching path wins; 'box' matches box, box.open and
//   box.keyPair; libsodium's names match at underscores. '()' is a call on
//   the module itself; '*' is any call.
//   Optional argument readers: curveArg (index), sizeArg ([index, field]),
//   costArg ([index, field?]), iterationsArg ([index, field?]),
//   hashIdentArg (index: the argument is an imported hash function whose
//   name gives the hash, e.g. hmac(sha256, …)), cipherArg (index: a cipher
//   name string), also (a second algorithm the same call uses).
// subpaths: a module subpath whose default export is itself the algorithm
//   (require('crypto-js/sha256')).
// jose: the package takes JSON Web Algorithms names as string literals.

const S = (family, extra = {}) => ({ family, ...extra });
const hashSpec = (hash) => ({ family: 'Hash', hash });
const CURVE_CALLS = (exportName, curve) => ({
  [exportName]: S('EC', { curve }),
  [`${exportName}.sign`]: S('ECDSA', { curve }),
  [`${exportName}.verify`]: S('ECDSA', { curve }),
  [`${exportName}.getSharedSecret`]: S('ECDH', { curve }),
});
const NOBLE_HASHES = {
  sha1: hashSpec('SHA-1'), md5: hashSpec('MD5'), ripemd160: hashSpec('RIPEMD-160'),
  sha224: hashSpec('SHA-224'), sha256: hashSpec('SHA-256'), sha384: hashSpec('SHA-384'), sha512: hashSpec('SHA-512'),
  sha512_256: hashSpec('SHA-512/256'), sha3_256: hashSpec('SHA3-256'), sha3_512: hashSpec('SHA3-512'),
  keccak_256: hashSpec('Keccak-256'), blake2b: hashSpec('BLAKE2b'), blake2s: hashSpec('BLAKE2s'), blake3: hashSpec('BLAKE3'),
  hmac: S('HMAC', { hashIdentArg: 0 }),
  hkdf: S('HKDF', { hashIdentArg: 0 }),
  pbkdf2: S('PBKDF2', { hashIdentArg: 0, iterationsArg: [3, 'c'] }),
  pbkdf2Async: S('PBKDF2', { hashIdentArg: 0, iterationsArg: [3, 'c'] }),
  scrypt: S('scrypt'), scryptAsync: S('scrypt'),
  argon2id: S('Argon2id'), argon2i: S('Argon2i'), argon2d: S('Argon2d'),
};
const SODIUM_CALLS = {
  crypto_box_seal: S('X25519 sealed box'),
  crypto_box: S('X25519-XSalsa20-Poly1305'),
  crypto_kx: S('X25519'),
  crypto_scalarmult: S('X25519'),
  crypto_sign: S('Ed25519'),
  crypto_secretbox: S('XSalsa20-Poly1305'),
  crypto_aead_xchacha20poly1305_ietf: S('XChaCha20-Poly1305'),
  crypto_secretstream_xchacha20poly1305: S('XChaCha20-Poly1305'),
  crypto_aead_chacha20poly1305: S('ChaCha20-Poly1305'),
  crypto_aead_aes256gcm: S('AES', { keySize: 256, mode: 'GCM' }),
  crypto_pwhash_scryptsalsa208sha256: S('scrypt'),
  // libsodium's crypto_pwhash with its default algorithm is Argon2id.
  crypto_pwhash: S('Argon2id'),
  crypto_generichash: hashSpec('BLAKE2b'),
  crypto_hash_sha256: hashSpec('SHA-256'),
  crypto_hash_sha512: hashSpec('SHA-512'),
  crypto_hash: hashSpec('SHA-512'),
  crypto_auth_hmacsha256: S('HMAC', { hash: 'SHA-256' }),
  crypto_auth_hmacsha512: S('HMAC', { hash: 'SHA-512' }),
  randombytes: S('CSPRNG'),
};
const SODIUM = { provides: 'X25519 (box, sealed box, key exchange), Ed25519, XChaCha20-Poly1305, XSalsa20-Poly1305, AES-256-GCM, Argon2id, BLAKE2b', pq: 'no', calls: SODIUM_CALLS };
const JWT = (provides, pq = 'no') => ({ provides, pq, jose: true });

/** @type {Record<string, {provides: string, pq: string, calls?: object, subpaths?: object, jose?: boolean, plain?: string[]}>} */
export const LIBRARIES = {
  tweetnacl: {
    provides: 'X25519 with XSalsa20-Poly1305 (box), Ed25519 (sign), XSalsa20-Poly1305 (secretbox), SHA-512', pq: 'no',
    calls: {
      box: S('X25519-XSalsa20-Poly1305'), scalarMult: S('X25519'), sign: S('Ed25519'),
      secretbox: S('XSalsa20-Poly1305'), hash: hashSpec('SHA-512'), randomBytes: S('CSPRNG'),
    },
  },
  'libsodium-wrappers': SODIUM,
  'libsodium-wrappers-sumo': SODIUM,
  'sodium-native': SODIUM,
  '@noble/curves': {
    provides: 'ECDSA and ECDH on P-256, P-384, P-521 and secp256k1; Ed25519, Ed448, X25519, X448; Schnorr; BLS12-381', pq: 'no',
    calls: {
      ed25519: S('Ed25519'), ed25519ph: S('Ed25519'), ed25519ctx: S('Ed25519'), ed448: S('Ed448'),
      x25519: S('X25519'), x448: S('X448'), schnorr: S('Schnorr', { curve: 'secp256k1' }), bls12_381: S('BLS'),
      ...CURVE_CALLS('secp256k1', 'secp256k1'), ...CURVE_CALLS('p256', 'P-256'), ...CURVE_CALLS('secp256r1', 'P-256'),
      ...CURVE_CALLS('p384', 'P-384'), ...CURVE_CALLS('secp384r1', 'P-384'), ...CURVE_CALLS('p521', 'P-521'), ...CURVE_CALLS('secp521r1', 'P-521'),
    },
  },
  '@noble/ed25519': { provides: 'Ed25519', pq: 'no', calls: { '*': S('Ed25519') } },
  '@noble/secp256k1': {
    provides: 'ECDSA, ECDH and Schnorr on secp256k1', pq: 'no',
    calls: { '*': S('EC', { curve: 'secp256k1' }), sign: S('ECDSA', { curve: 'secp256k1' }), signAsync: S('ECDSA', { curve: 'secp256k1' }), verify: S('ECDSA', { curve: 'secp256k1' }), getSharedSecret: S('ECDH', { curve: 'secp256k1' }) },
  },
  '@noble/hashes': { provides: 'SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3, RIPEMD-160, MD5, HMAC, HKDF, PBKDF2, scrypt, Argon2', pq: 'n/a', calls: NOBLE_HASHES },
  '@noble/ciphers': {
    provides: 'AES (GCM, GCM-SIV, CBC, CTR, key wrap), ChaCha20-Poly1305, XChaCha20-Poly1305, XSalsa20-Poly1305', pq: 'n/a',
    calls: {
      gcm: S('AES', { mode: 'GCM' }), siv: S('AES', { mode: 'GCM-SIV' }), gcmsiv: S('AES', { mode: 'GCM-SIV' }), cbc: S('AES', { mode: 'CBC' }),
      ctr: S('AES', { mode: 'CTR' }), ecb: S('AES', { mode: 'ECB' }), aeskw: S('AES', { mode: 'KW' }),
      chacha20poly1305: S('ChaCha20-Poly1305'), xchacha20poly1305: S('XChaCha20-Poly1305'), xsalsa20poly1305: S('XSalsa20-Poly1305'),
      chacha20: S('ChaCha20'), salsa20: S('Salsa20'),
    },
  },
  '@noble/post-quantum': {
    provides: 'ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid KEMs in recent versions', pq: 'yes',
    calls: {
      ml_kem512: S('ML-KEM', { name: 'ML-KEM-512' }), ml_kem768: S('ML-KEM', { name: 'ML-KEM-768' }), ml_kem1024: S('ML-KEM', { name: 'ML-KEM-1024' }),
      ml_dsa44: S('ML-DSA', { name: 'ML-DSA-44' }), ml_dsa65: S('ML-DSA', { name: 'ML-DSA-65' }), ml_dsa87: S('ML-DSA', { name: 'ML-DSA-87' }),
      slh_dsa: S('SLH-DSA'),
      ml_kem768_x25519: S('Hybrid KEM', { name: 'MLKEM768-X25519' }), xwing: S('Hybrid KEM', { name: 'X-Wing' }), XWing: S('Hybrid KEM', { name: 'X-Wing' }),
      ml_kem768_p256: S('Hybrid KEM', { name: 'SecP256r1MLKEM768' }), ml_kem1024_p384: S('Hybrid KEM', { name: 'SecP384r1MLKEM1024' }),
    },
  },
  'node-forge': {
    provides: 'RSA, Ed25519, AES, 3DES, DES, RC2, SHA-1, SHA-2, MD5, HMAC, PBKDF2, X.509, a TLS implementation', pq: 'no',
    calls: {
      'pki.rsa': S('RSA', { sizeArg: [0, 'bits'] }), 'pki.ed25519': S('Ed25519'), ed25519: S('Ed25519'),
      'md.sha1': hashSpec('SHA-1'), 'md.md5': hashSpec('MD5'), 'md.sha256': hashSpec('SHA-256'), 'md.sha384': hashSpec('SHA-384'), 'md.sha512': hashSpec('SHA-512'),
      'cipher.createCipher': S('AES', { cipherArg: 0 }), 'cipher.createDecipher': S('AES', { cipherArg: 0 }),
      'pkcs5.pbkdf2': S('PBKDF2', { iterationsArg: [2] }), random: S('CSPRNG'),
    },
  },
  elliptic: {
    provides: 'ECDSA and ECDH on secp256k1, P-256 and other curves; EdDSA on Ed25519', pq: 'no',
    calls: { ec: S('EC', { curveArg: 0 }), eddsa: S('Ed25519') },
  },
  // `plain`: members that do no cryptography (reading a token without checking
  // it; picking the token out of a request). A file that uses only these gets
  // no "could not be read" pointer: its use was read, and there is nothing to
  // report (fixture libraries/src/decode.js, DESIGN.md §8.5, §8.12).
  jsonwebtoken: { ...JWT('JSON Web Token signatures: HMAC (HS*), RSA (RS*, PS*), ECDSA (ES*)'), plain: ['decode'] },
  jose: { ...JWT('JSON Web Signature and Encryption: RSA, ECDSA, EdDSA, HMAC, RSA-OAEP, ECDH-ES, AES key wrap, AES-GCM', 'check'), plain: ['decodeJwt', 'decodeProtectedHeader', 'base64url', 'errors'] },
  jws: { ...JWT('JSON Web Signature: HMAC, RSA, ECDSA'), plain: ['decode'] },
  jwa: JWT('JSON Web Algorithms: HMAC, RSA, ECDSA'),
  'fast-jwt': { ...JWT('JSON Web Token signatures: HMAC, RSA, ECDSA, EdDSA'), plain: ['createDecoder'] },
  'express-jwt': JWT('JSON Web Token verification for Express (uses jsonwebtoken)'),
  'passport-jwt': { ...JWT('JSON Web Token verification for Passport (uses jsonwebtoken)'), plain: ['ExtractJwt'] },
  jsrsasign: { ...JWT('RSA, ECDSA, DSA, X.509, JSON Web Signature'), calls: { 'KEYUTIL.generateKeypair': S('RSA', { keyTypeArg: 0 }) } },
  bcrypt: { provides: 'bcrypt password hashing', pq: 'n/a', calls: { hash: S('bcrypt', { costArg: [1] }), hashSync: S('bcrypt', { costArg: [1] }), genSalt: S('bcrypt', { costArg: [0] }), genSaltSync: S('bcrypt', { costArg: [0] }), compare: S('bcrypt'), compareSync: S('bcrypt') } },
  bcryptjs: { provides: 'bcrypt password hashing', pq: 'n/a', calls: { hash: S('bcrypt', { costArg: [1] }), hashSync: S('bcrypt', { costArg: [1] }), genSalt: S('bcrypt', { costArg: [0] }), genSaltSync: S('bcrypt', { costArg: [0] }), compare: S('bcrypt'), compareSync: S('bcrypt') } },
  argon2: { provides: 'Argon2 password hashing (Argon2id, Argon2i, Argon2d)', pq: 'n/a', calls: { hash: S('Argon2'), verify: S('Argon2') } },
  'scrypt-js': { provides: 'scrypt key derivation', pq: 'n/a', calls: { scrypt: S('scrypt'), syncScrypt: S('scrypt') } },
  'hash-wasm': { provides: 'hashes (SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3, MD5), HMAC, PBKDF2, scrypt, bcrypt, Argon2', pq: 'n/a', calls: { md5: hashSpec('MD5'), sha1: hashSpec('SHA-1'), sha256: hashSpec('SHA-256'), sha512: hashSpec('SHA-512'), argon2id: S('Argon2id'), bcrypt: S('bcrypt'), scrypt: S('scrypt'), pbkdf2: S('PBKDF2'), blake3: hashSpec('BLAKE3') } },
  'crypto-js': {
    provides: 'AES, DES, 3DES, RC4, Rabbit, MD5, SHA-1, SHA-2, SHA-3, RIPEMD-160, HMAC, PBKDF2 (unmaintained upstream)', pq: 'n/a',
    calls: {
      AES: S('AES'), DES: S('DES'), TripleDES: S('3DES'), RC4: S('RC4'), RC4Drop: S('RC4'), Rabbit: S('Rabbit'),
      MD5: hashSpec('MD5'), SHA1: hashSpec('SHA-1'), SHA224: hashSpec('SHA-224'), SHA256: hashSpec('SHA-256'), SHA384: hashSpec('SHA-384'), SHA512: hashSpec('SHA-512'),
      SHA3: hashSpec('SHA-3'), RIPEMD160: hashSpec('RIPEMD-160'),
      HmacMD5: S('HMAC', { hash: 'MD5' }), HmacSHA1: S('HMAC', { hash: 'SHA-1' }), HmacSHA256: S('HMAC', { hash: 'SHA-256' }), HmacSHA512: S('HMAC', { hash: 'SHA-512' }),
      PBKDF2: S('PBKDF2', { iterationsArg: [2, 'iterations'] }),
    },
    subpaths: {
      aes: S('AES'), des: S('DES'), tripledes: S('3DES'), rc4: S('RC4'), md5: hashSpec('MD5'), sha1: hashSpec('SHA-1'),
      sha256: hashSpec('SHA-256'), sha512: hashSpec('SHA-512'), 'hmac-sha256': S('HMAC', { hash: 'SHA-256' }),
      'hmac-sha1': S('HMAC', { hash: 'SHA-1' }), pbkdf2: S('PBKDF2', { iterationsArg: [2, 'iterations'] }),
    },
  },
  openpgp: {
    provides: 'OpenPGP: RSA, ECC (Curve25519, NIST curves), AES; newer versions add post-quantum keys', pq: 'check',
    calls: { encrypt: S('OpenPGP', { noteCodes: ['key-decides'] }), decrypt: S('OpenPGP', { noteCodes: ['key-decides'] }), sign: S('OpenPGP signature', { noteCodes: ['key-decides'] }), verify: S('OpenPGP signature', { noteCodes: ['key-decides'] }) },
  },
  ssh2: { provides: 'SSH: key exchange (Curve25519, ECDH, Diffie–Hellman), RSA, ECDSA and Ed25519 host keys, AES', pq: 'check' },
  '@peculiar/webcrypto': { provides: 'a Web Crypto implementation: RSA, ECDSA, ECDH, Ed25519, X25519, AES, HMAC, HKDF, PBKDF2', pq: 'no' },
  '@peculiar/x509': { provides: 'X.509 certificates (RSA and ECDSA signatures)', pq: 'no' },
  mlkem: { provides: 'ML-KEM (FIPS 203)', pq: 'yes', calls: { MlKem512: S('ML-KEM', { name: 'ML-KEM-512' }), MlKem768: S('ML-KEM', { name: 'ML-KEM-768' }), MlKem1024: S('ML-KEM', { name: 'ML-KEM-1024' }) } },
  'crystals-kyber-js': { provides: 'Kyber (before standardisation as ML-KEM)', pq: 'yes', calls: { Kyber512: S('Kyber', { name: 'Kyber512' }), Kyber768: S('Kyber', { name: 'Kyber768' }), Kyber1024: S('Kyber', { name: 'Kyber1024' }) } },
  'pqc-kyber': { provides: 'Kyber (before standardisation as ML-KEM)', pq: 'yes', calls: { '*': S('Kyber') } },
  'eth-crypto': {
    provides: 'secp256k1 ECDSA signatures and ECIES encryption', pq: 'no',
    calls: { encryptWithPublicKey: S('ECIES', { curve: 'secp256k1' }), decryptWithPrivateKey: S('ECIES', { curve: 'secp256k1' }), sign: S('ECDSA', { curve: 'secp256k1' }), recover: S('ECDSA', { curve: 'secp256k1' }), recoverPublicKey: S('ECDSA', { curve: 'secp256k1' }), createIdentity: S('EC', { curve: 'secp256k1' }) },
  },
  secp256k1: { provides: 'ECDSA and ECDH on secp256k1 (native bindings)', pq: 'no', calls: { ecdsaSign: S('ECDSA', { curve: 'secp256k1' }), ecdsaVerify: S('ECDSA', { curve: 'secp256k1' }), ecdh: S('ECDH', { curve: 'secp256k1' }), '*': S('EC', { curve: 'secp256k1' }) } },
  'web-push': {
    provides: 'VAPID signatures (ECDSA P-256, ES256) and push-message encryption (ECDH P-256 with AES-128-GCM, RFC 8291)', pq: 'no',
    calls: {
      sendNotification: S('ECDH', { curve: 'P-256', also: S('ECDSA', { curve: 'P-256', hash: 'SHA-256' }) }),
      generateRequestDetails: S('ECDH', { curve: 'P-256', also: S('ECDSA', { curve: 'P-256', hash: 'SHA-256' }) }),
      encrypt: S('ECDH', { curve: 'P-256' }),
      generateVAPIDKeys: S('ECDSA', { curve: 'P-256' }), setVapidDetails: S('ECDSA', { curve: 'P-256' }), getVapidHeaders: S('ECDSA', { curve: 'P-256' }),
    },
  },
  http_ece: { provides: 'HTTP encrypted content encoding (RFC 8188): AES-128-GCM, with ECDH P-256 when keys are used', pq: 'no', calls: { encrypt: S('AES', { keySize: 128, mode: 'GCM' }), decrypt: S('AES', { keySize: 128, mode: 'GCM' }) } },
  'node-rsa': { provides: 'RSA encryption and signatures', pq: 'no', calls: { '()': S('RSA', { sizeArg: [0, 'b'] }) } },
  '@simplewebauthn/server': { provides: 'WebAuthn: verifies authenticator signatures (ECDSA P-256, RSA, Ed25519)', pq: 'no', calls: { verifyRegistrationResponse: S('Signature', { noteCodes: ['key-decides'] }), verifyAuthenticationResponse: S('Signature', { noteCodes: ['key-decides'] }) } },
  otplib: { provides: 'one-time passwords (HOTP, TOTP): HMAC-SHA-1 by default', pq: 'n/a', calls: { authenticator: S('HMAC'), totp: S('HMAC'), hotp: S('HMAC') } },
  speakeasy: { provides: 'one-time passwords (HOTP, TOTP): HMAC-SHA-1 by default', pq: 'n/a', calls: { totp: S('HMAC'), hotp: S('HMAC') } },
  'cookie-signature': { provides: 'cookie signing with HMAC-SHA-256', pq: 'n/a', calls: { sign: S('HMAC', { hash: 'SHA-256' }), unsign: S('HMAC', { hash: 'SHA-256' }) } },
  keygrip: { provides: 'cookie signing with HMAC (hash configurable)', pq: 'n/a', calls: { '()': S('HMAC') } },
  'express-session': { provides: 'session cookies signed with HMAC-SHA-256 (through cookie-signature)', pq: 'n/a' },
  'cookie-session': { provides: 'session cookies signed with HMAC (through keygrip)', pq: 'n/a' },
  '@hpke/core': {
    provides: 'Hybrid Public Key Encryption (RFC 9180): DHKEM with X25519 or P-256/384/521, HKDF, AES-GCM', pq: 'no',
    calls: {
      DhkemX25519HkdfSha256: S('HPKE DHKEM', { curve: 'X25519', name: 'HPKE DHKEM(X25519)' }),
      DhkemP256HkdfSha256: S('HPKE DHKEM', { curve: 'P-256', name: 'HPKE DHKEM(P-256)' }),
      DhkemP384HkdfSha384: S('HPKE DHKEM', { curve: 'P-384', name: 'HPKE DHKEM(P-384)' }),
      DhkemP521HkdfSha512: S('HPKE DHKEM', { curve: 'P-521', name: 'HPKE DHKEM(P-521)' }),
      HkdfSha256: S('HKDF', { hash: 'SHA-256' }), HkdfSha384: S('HKDF', { hash: 'SHA-384' }), HkdfSha512: S('HKDF', { hash: 'SHA-512' }),
      Aes128Gcm: S('AES', { keySize: 128, mode: 'GCM' }), Aes256Gcm: S('AES', { keySize: 256, mode: 'GCM' }),
    },
  },
  '@hpke/ml-kem': { provides: 'ML-KEM for HPKE', pq: 'yes', calls: { MlKem512: S('ML-KEM', { name: 'ML-KEM-512' }), MlKem768: S('ML-KEM', { name: 'ML-KEM-768' }), MlKem1024: S('ML-KEM', { name: 'ML-KEM-1024' }) } },
  '@hpke/hybridkem-x-wing': { provides: 'the X-Wing hybrid KEM (ML-KEM-768 with X25519) for HPKE', pq: 'yes', calls: { XWing: S('Hybrid KEM', { name: 'X-Wing' }) } },
  '@microtoll/crypto-core': { provides: 'AES-256-GCM, HKDF-SHA-256, Ed25519, a P-256 ECDH seal, PBKDF2-SHA-256; an optional hybrid MLKEM768-X25519 seal (off by default)', pq: 'partial' },
  // Added after the false-positive review of three public repositories
  // (DESIGN.md §8.12): a wiki's SAML sign-in, its encrypted assertions and its
  // two-factor codes went unreported because their libraries were not here.
  'passport-saml': { provides: 'SAML 2.0 sign-in for Passport: the identity provider\'s XML signatures (RSA with SHA-1, SHA-256 or SHA-512, set by configuration); RSA key transport where assertions are encrypted', pq: 'no', calls: { Strategy: S('Signature', { name: 'SAML signature', noteCodes: ['key-decides'] }) } },
  '@node-saml/passport-saml': { provides: 'SAML 2.0 sign-in for Passport (the maintained passport-saml): XML signatures with RSA; RSA key transport where assertions are encrypted', pq: 'no', calls: { Strategy: S('Signature', { name: 'SAML signature', noteCodes: ['key-decides'] }) } },
  '@node-saml/node-saml': { provides: 'SAML 2.0 (the core of passport-saml): XML signatures with RSA; RSA key transport where assertions are encrypted', pq: 'no', calls: { SAML: S('Signature', { name: 'SAML signature', noteCodes: ['key-decides'] }) } },
  'xml-crypto': { provides: 'XML digital signatures (RSA-SHA-1, RSA-SHA-256, RSA-SHA-512, HMAC-SHA-1) and digests, as SAML uses them', pq: 'no', calls: { SignedXml: S('Signature', { name: 'XML signature', noteCodes: ['key-decides'] }) } },
  'xml-encryption': { provides: 'XML encryption as SAML uses it: RSA key transport (RSA-OAEP or RSA-1.5) of an AES content key', pq: 'no', calls: { encrypt: S('RSA', { name: 'RSA key transport (XML encryption)' }), decrypt: S('RSA', { name: 'RSA key transport (XML encryption)' }) } },
  'node-2fa': { provides: 'one-time passwords (TOTP): HMAC-SHA-1 (through notp)', pq: 'n/a', calls: { generateToken: S('HMAC', { hash: 'SHA-1' }), verifyToken: S('HMAC', { hash: 'SHA-1' }) } },
  'jwks-rsa': { ...JWT('fetches JSON Web Key Sets to verify JSON Web Tokens (RSA and ECDSA keys)') },
  'openid-client': { ...JWT('OpenID Connect client: ID token signatures (RS256, ES256, EdDSA, …) and optional encrypted tokens, through jose', 'check') },
};

/** '@noble/curves/ed25519.js' → { name: '@noble/curves', subpath: 'ed25519' }; null for relative or node: paths. */
export function packageOf(specifier) {
  const s = String(specifier);
  if (s.startsWith('.') || s.startsWith('/') || s.startsWith('node:') || /^[a-z]:/i.test(s)) return null;
  const parts = s.split('/');
  const nameParts = s.startsWith('@') ? parts.slice(0, 2) : parts.slice(0, 1);
  const subpath = parts.slice(nameParts.length).join('/').replace(/\.(c|m)?js$/, '');
  return { name: nameParts.join('/'), subpath };
}
