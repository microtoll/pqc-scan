// The CycloneDX 1.6 cryptographic bill of materials (CBOM), written from the
// report object alone, as the Markdown is (DESIGN.md §8.14). Every
// cryptographic use in the report becomes an occurrence of a
// `cryptographic-asset` component; the interfaces and libraries the uses go
// through become components that `provide` those assets; each TLS
// configuration becomes a `protocol` asset that references the key-exchange
// groups it names. Nothing here is detected: what the report does not say,
// the bill of materials does not say either.
//
// Field names and enumerations follow the CycloneDX 1.6 JSON schema
// (test/schemas/bom-1.6.schema.json, Apache-2.0, from the CycloneDX
// specification repository at tag 1.6.1); every fixture's output is checked
// against it in test/cbom.test.mjs. What CycloneDX has no field for (the
// scanner's class, kind, migration priority, parameters and notes) travels
// in `properties` under the prefix `microtoll:pqc-scan:`, as the CycloneDX
// property taxonomy allows.
import { createHash } from 'node:crypto';
import { HYBRID_NAMES } from './catalogue.js';

export const CBOM_SPEC_VERSION = '1.6';
const SCHEMA_URL = 'http://cyclonedx.org/schema/bom-1.6.schema.json';
const P = 'microtoll:pqc-scan';
const ROOT_REF = 'pqc-scan:root';
const TOOL_REF = 'pqc-scan:tool';

const PRIORITY_RANK = { high: 3, medium: 2, low: 1 };
const HYBRID_BY_LOWER = new Map(HYBRID_NAMES.map((n) => [n.toLowerCase(), n]));

/** The bill of materials as an object (DESIGN.md §8.14). */
export function buildCbom(report) {
  const refs = new RefBook();
  const assets = new Map(); // asset key → the asset being assembled
  const provides = new Map(); // provider bom-ref → Set of asset bom-refs
  const libraries = new Map(); // package name → library component

  for (const d of report.dependencies) libraries.set(d.name, libraryComponent(d, refs));

  for (const f of report.findings) {
    const asset = assetFor(assets, refs, {
      algorithm: f.algorithm, family: f.family, class: f.class, kind: f.kind,
      keySize: f.keySize, curve: f.curve, hash: f.hash, parameters: f.parameters,
    });
    asset.occurrences.push(occurrence(f.file, f.line, `${f.interface}:${f.operation}`, context(f)));
    addUse(asset, f);
    for (const provider of providersOf(f.interface, libraries, refs)) link(provides, provider, asset.ref);
  }

  const protocols = [];
  for (const t of report.tls) {
    const groupRefs = [];
    for (const group of t.groups ?? []) {
      const asset = assetFor(assets, refs, groupAlgorithm(group));
      asset.occurrences.push(occurrence(t.file, t.line, `tls-group:${t.server}`, t.evidence));
      addUse(asset, { priority: t.priority, priorityReason: t.priorityReason, replacement: t.replacement, dynamic: false, notes: [], inTest: t.inTest, operation: 'key exchange', kind: 'key-agreement' });
      if (!groupRefs.includes(asset.ref)) groupRefs.push(asset.ref);
    }
    protocols.push(protocolComponent(t, groupRefs, refs));
  }

  const interfaceComponents = [...provides.keys()]
    .filter((ref) => ref.startsWith('pqc-scan:interface:'))
    .sort()
    .map((ref) => INTERFACES[ref]);
  const assetComponents = [...assets.values()]
    .sort((a, b) => cmp(a.component.name, b.component.name) || cmp(a.key, b.key))
    .map(finishAsset);
  const libraryComponents = [...libraries.values()].sort((a, b) => cmp(a.name, b.name));

  const dependencies = [{
    ref: ROOT_REF,
    dependsOn: [
      ...libraryComponents.filter((c) => c.properties.some((p) => p.name === `${P}:direct` && p.value === 'true')).map((c) => c['bom-ref']),
      ...interfaceComponents.map((c) => c['bom-ref']),
    ],
  }];
  for (const c of [...interfaceComponents, ...libraryComponents]) {
    const entry = { ref: c['bom-ref'] };
    const provided = provides.get(c['bom-ref']);
    if (provided?.size) entry.provides = [...provided].sort();
    dependencies.push(entry);
  }

  const bom = {
    $schema: SCHEMA_URL,
    bomFormat: 'CycloneDX',
    specVersion: CBOM_SPEC_VERSION,
    version: 1,
    metadata: {
      timestamp: report.scannedAt,
      tools: {
        components: [{
          type: 'application',
          'bom-ref': TOOL_REF,
          name: report.tool.name,
          version: report.tool.version,
          properties: [prop('catalogue', report.tool.catalogue), prop('schema', String(report.schema))],
        }],
      },
      component: { type: 'application', 'bom-ref': ROOT_REF, name: report.root },
      properties: [
        prop('notice', report.notice),
        prop('verdict', report.summary.verdict),
        prop('filesScanned', String(report.summary.filesScanned)),
        prop('filesWithFindings', String(report.summary.filesWithFindings)),
        prop('dynamic', String(report.summary.dynamic)),
        prop('tls.keyExchange', report.summary.tls.keyExchange),
        ...report.skipped.map((k) => prop('skipped', `${k.path}: ${k.reason}`)),
      ],
    },
    components: [...assetComponents, ...protocols, ...libraryComponents, ...interfaceComponents],
    dependencies,
  };
  const { $schema, bomFormat, specVersion, ...rest } = bom;
  return { $schema, bomFormat, specVersion, serialNumber: serialNumberOf(bom), ...rest };
}

/**
 * The serial number (DESIGN.md §8.14): a UUID worked out from the rest of
 * the bill of materials, its timestamp included, so every scan's file has
 * its own serial number and one report always gives one file. CycloneDX
 * makes it optional but recommended, and a widely used open-source viewer
 * for these files refuses a file without it. The UUID is RFC 9562's version 8 from SHA-256, the
 * name-based construction of its Appendix B.2; version 5 would mean SHA-1,
 * which this scanner itself reports as weak.
 */
function serialNumberOf(bom) {
  const b = createHash('sha256').update(JSON.stringify(bom)).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80; // version 8
  b[8] = (b[8] & 0x3f) | 0x80; // the RFC 9562 variant
  const h = b.toString('hex');
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** The JSON text of the bill of materials: two-space indentation and a final newline. */
export function toCbom(report) {
  return `${JSON.stringify(buildCbom(report), null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Cryptographic assets (algorithms)
// ---------------------------------------------------------------------------

/**
 * One asset per distinct algorithm variant: the normalised name with its
 * key size, curve, hash and literal parameters. AES-256-GCM reached through
 * Web Crypto and through node:crypto is one asset with two providers.
 */
function assetFor(assets, refs, algo) {
  const params = Object.entries(algo.parameters ?? {}).sort(([a], [b]) => cmp(a, b));
  const key = [algo.algorithm, algo.keySize ?? '', algo.curve ?? '', algo.hash ?? '', params.map(([k, v]) => `${k}=${v}`).join(',')].join('|');
  let asset = assets.get(key);
  if (!asset) {
    asset = {
      key,
      ref: refs.claim(`pqc-scan:algorithm:${slug(key.replace(/\|+$/, '').replace(/\|/g, ' '))}`),
      algo: { ...algo, parameters: Object.fromEntries(params) },
      occurrences: [],
      functions: new Set(),
      priority: null,
      priorityRank: 0,
      replacement: null,
      dynamic: false,
      notes: new Map(),
      component: { name: algo.algorithm },
    };
    assets.set(key, asset);
  }
  return asset;
}

function addUse(asset, use) {
  for (const fn of cryptoFunctions(use.kind, use.operation)) asset.functions.add(fn);
  const rank = PRIORITY_RANK[use.priority] ?? 0;
  if (rank > asset.priorityRank) {
    asset.priorityRank = rank;
    asset.priority = use.priority;
    asset.replacement = use.replacement;
  }
  if (use.dynamic) asset.dynamic = true;
  for (const n of use.notes ?? []) if (!asset.notes.has(n.code)) asset.notes.set(n.code, n.text);
}

function finishAsset(asset) {
  const a = asset.algo;
  const algorithmProperties = {
    primitive: primitiveOf(a),
    ...defined('parameterSetIdentifier', parameterSet(a)),
    ...defined('curve', a.curve),
    executionEnvironment: 'software-plain-ram',
    implementationPlatform: 'generic',
    ...defined('mode', modeOf(a)),
    ...defined('padding', paddingOf(a)),
    cryptoFunctions: asset.functions.size ? [...asset.functions].sort() : [asset.dynamic ? 'unknown' : 'other'],
    ...defined('classicalSecurityLevel', classicalLevel(a)),
    ...defined('nistQuantumSecurityLevel', quantumLevel(a)),
  };
  const properties = [
    prop('class', a.class),
    prop('kind', a.kind),
    prop('quantumVulnerable', String(a.class === 'public-key')),
  ];
  if (a.hash) properties.push(prop('hash', a.hash));
  for (const [k, v] of Object.entries(a.parameters)) properties.push(prop(`parameter:${k}`, String(v)));
  if (asset.priority) {
    properties.push(prop('priority', asset.priority));
    if (asset.replacement) properties.push(prop('replacement', asset.replacement));
  }
  if (asset.dynamic) properties.push(prop('dynamic', 'true'));
  for (const [code, text] of [...asset.notes].sort(([x], [y]) => cmp(x, y))) properties.push(prop(`note:${code}`, text));
  return {
    type: 'cryptographic-asset',
    'bom-ref': asset.ref,
    name: a.algorithm,
    cryptoProperties: { assetType: 'algorithm', algorithmProperties },
    evidence: { occurrences: asset.occurrences },
    properties,
  };
}

/** The CycloneDX primitive of an algorithm, from the scanner's kind and name. */
function primitiveOf(a) {
  switch (a.kind) {
    case 'key-agreement': return 'key-agree';
    case 'public-key-encryption': return 'pke';
    case 'signature': case 'pq-signature': return 'signature';
    case 'kem': return a.family === 'Hybrid KEM' ? 'combiner' : 'kem';
    case 'cipher': return isAead(a.algorithm) ? 'ae' : isStreamCipher(a.family) ? 'stream-cipher' : 'block-cipher';
    case 'mac': return 'mac';
    case 'hash': return /shake/i.test(a.algorithm) ? 'xof' : 'hash';
    case 'kdf': case 'password-hash': return 'kdf';
    case 'random': return 'drbg';
    // 'public-key': a key pair whose use the call does not say; 'unknown': not read.
    default: return 'unknown';
  }
}

function isAead(name) {
  return /-(GCM|CCM)\b|Poly1305/i.test(name);
}

function isStreamCipher(family) {
  return ['ChaCha20', 'Salsa20', 'RC4', 'Rabbit'].includes(family);
}

function modeOf(a) {
  if (a.kind !== 'cipher') return undefined;
  const m = /-(GCM|CCM|CBC|CTR|ECB|CFB|OFB)\b/i.exec(a.algorithm);
  if (m) return m[1].toLowerCase();
  return /-KW\b/i.test(a.algorithm) ? 'other' : undefined;
}

function paddingOf(a) {
  if (a.family === 'RSA-OAEP') return 'oaep';
  if (a.family === 'RSASSA-PKCS1-v1_5' || a.family === 'RSAES-PKCS1-v1_5') return 'pkcs1v15';
  return undefined;
}

/** "256" for AES-256 or SHA-256, "2048" for RSA 2048-bit, "65" for ML-DSA-65, "SHA2-128s" for SLH-DSA. */
function parameterSet(a) {
  if (a.keySize) return String(a.keySize);
  let m;
  if ((m = /^SLH-DSA-(.+)$/i.exec(a.algorithm))) return m[1];
  if ((m = /^(?:ML-KEM|ML-DSA|Kyber)-?(\d+)$/i.exec(a.algorithm))) return m[1];
  if (a.kind === 'hash' && (m = /(?:SHA-?3?-?|SHAKE|BLAKE2[bs]-?)(\d{3})$/i.exec(a.algorithm))) return m[1];
  return undefined;
}

// SP 800-57 Part 1 (Rev. 5) table 2: comparable strengths, in bits.
const RSA_DH_STRENGTH = { 1024: 80, 2048: 112, 3072: 128, 7680: 192, 15360: 256 };
const CURVE_STRENGTH = { 'P-256': 128, secp256k1: 128, 'P-384': 192, 'P-521': 256 };

function classicalLevel(a) {
  const name = a.algorithm;
  if (a.family === 'AES' && a.keySize) return a.keySize;
  if (/ChaCha20|Salsa20/.test(a.family)) return 256;
  if (a.family === '3DES') return 112;
  if (a.curve && CURVE_STRENGTH[a.curve]) return CURVE_STRENGTH[a.curve];
  if (/^(X25519|Ed25519)$/.test(a.family)) return 128;
  if (/^(X448|Ed448)$/.test(a.family)) return 224;
  if (/^(RSA|DH)/.test(a.family) && a.keySize) return RSA_DH_STRENGTH[a.keySize];
  if (a.kind === 'hash') {
    const m = /^SHA-?3?-?(256|384|512)$/i.exec(name);
    if (m) return Number(m[1]) / 2; // collision resistance
  }
  const pq = quantumLevel(a);
  if (a.class === 'post-quantum' && pq) return { 1: 128, 2: 128, 3: 192, 4: 192, 5: 256 }[pq];
  return undefined;
}

/**
 * NIST's post-quantum security categories, 1 to 5, or 0 where none is met:
 * every classical public-key algorithm (Shor); MD5 and SHA-1 (broken
 * classically). Omitted where the level is not settled by the name.
 */
function quantumLevel(a) {
  const name = a.algorithm;
  if (a.class === 'public-key') return 0;
  if (a.class === 'post-quantum') {
    if (/44\b/.test(name)) return 2;
    if (/(512|128)\b/.test(name)) return 1;
    if (/(768|65|192)\b/.test(name)) return 3;
    if (/(1024|87|256)\b/.test(name)) return 5;
    return undefined;
  }
  if (a.family === 'AES' && a.keySize) return { 128: 1, 192: 3, 256: 5 }[a.keySize];
  if (/ChaCha20|Salsa20/.test(a.family)) return 5;
  if (a.kind === 'hash') {
    if (/^(MD4|MD5|SHA-1)$/i.test(name)) return 0;
    const m = /^SHA-?3?-?(256|384|512)$/i.exec(name);
    if (m) return { 256: 2, 384: 4, 512: 5 }[m[1]];
  }
  return undefined;
}

/** What the use does with the algorithm, in CycloneDX's words; from the kind first, then the call's name. */
function cryptoFunctions(kind, operation) {
  const op = String(operation ?? '').toLowerCase();
  const out = new Set();
  if (/generatekey|keygen|createecdh|getdiffiehellman|generateprime|generatekeypair/.test(op)) out.add('keygen');
  if (/decapsulate/.test(op)) out.add('decapsulate');
  else if (/encapsulate/.test(op)) out.add('encapsulate');
  if (/verify/.test(op)) out.add('verify');
  else if (/\bsign\b|^sign|\.sign|createsign|setvapid/.test(op)) out.add('sign');
  if (/decrypt|unwrapkey|createdecipheriv|privatedecrypt|\.open|unbox/.test(op)) out.add('decrypt');
  else if (/encrypt|wrapkey|createcipheriv|publicencrypt|secretbox|\bbox\b|seal/.test(op)) out.add('encrypt');
  if (/digest|createhash|^(md5|sha\d*|sha3-?\d*|shake\d*)$/.test(op)) out.add('digest');
  if (/hmac|kmac|createhmac/.test(op)) out.add('tag');
  // A cipher or MAC key that arrives by deriveKey or importKey is that
  // algorithm's key coming into being (keygen); the deriving is the KDF's
  // function, and the KDF is its own asset. A key agreement or a KDF derives.
  if (/derive|pbkdf2|hkdf|scrypt|argon|bcrypt|getsharedsecret|computesecret/.test(op)) out.add(kind === 'cipher' || kind === 'mac' ? 'keygen' : 'keyderive');
  else if (/importkey/.test(op) && (kind === 'cipher' || kind === 'mac')) out.add('keygen');
  if (/random/.test(op)) out.add('generate');
  if (!out.size) {
    switch (kind) {
      case 'hash': out.add('digest'); break;
      case 'mac': out.add('tag'); break;
      case 'kdf': case 'password-hash': out.add('keyderive'); break;
      case 'random': out.add('generate'); break;
      default: break;
    }
  }
  return out;
}

/** The evidence line, prefixed with the use's priority and whether it is test code. */
function context(f) {
  const parts = [];
  if (f.priority) parts.push(`${f.priority[0].toUpperCase()}${f.priority.slice(1)} priority (${f.priorityReason}).`);
  if (f.inTest) parts.push('Test code.');
  parts.push(f.evidence);
  return parts.join(' ');
}

function occurrence(location, line, symbol, additionalContext) {
  return { location, line, symbol, additionalContext };
}

// ---------------------------------------------------------------------------
// TLS configurations and their key-exchange groups
// ---------------------------------------------------------------------------

const GROUP_NAMES = {
  x25519: { algorithm: 'X25519', family: 'X25519' },
  x448: { algorithm: 'X448', family: 'X448' },
  prime256v1: { algorithm: 'ECDH P-256', family: 'ECDH', curve: 'P-256' },
  secp256r1: { algorithm: 'ECDH P-256', family: 'ECDH', curve: 'P-256' },
  'p-256': { algorithm: 'ECDH P-256', family: 'ECDH', curve: 'P-256' },
  secp384r1: { algorithm: 'ECDH P-384', family: 'ECDH', curve: 'P-384' },
  'p-384': { algorithm: 'ECDH P-384', family: 'ECDH', curve: 'P-384' },
  secp521r1: { algorithm: 'ECDH P-521', family: 'ECDH', curve: 'P-521' },
  'p-521': { algorithm: 'ECDH P-521', family: 'ECDH', curve: 'P-521' },
};

/**
 * A TLS group as the scanner would name the same algorithm in code, so that
 * X25519 in a server's group list and X25519 in a Web Crypto call are one
 * asset. A hybrid keeps its specification's spelling; an unrecognised group
 * keeps the name as written.
 */
function groupAlgorithm(group) {
  const lower = group.toLowerCase();
  const hybrid = HYBRID_BY_LOWER.get(lower);
  if (hybrid || /mlkem|kyber/i.test(group)) {
    return { algorithm: hybrid ?? group, family: 'Hybrid KEM', class: 'post-quantum', kind: 'kem', keySize: null, curve: null, hash: null, parameters: {} };
  }
  let m;
  if ((m = /^ffdhe(\d+)$/i.exec(group))) {
    return { algorithm: `DH ${m[1]}-bit`, family: 'DH', class: 'public-key', kind: 'key-agreement', keySize: Number(m[1]), curve: null, hash: null, parameters: {} };
  }
  const known = GROUP_NAMES[lower];
  return {
    algorithm: known?.algorithm ?? group, family: known?.family ?? 'ECDH', class: 'public-key', kind: 'key-agreement',
    keySize: null, curve: known?.curve ?? null, hash: null, parameters: {},
  };
}

function protocolComponent(t, groupRefs, refs) {
  const name = `TLS (${t.setting ? `${t.server}, ${t.setting}` : t.server})`;
  const protocolProperties = { type: 'tls' };
  const version = tlsVersion(t.protocols);
  if (version) protocolProperties.version = version;
  if (groupRefs.length) protocolProperties.cryptoRefArray = groupRefs;
  const properties = [prop('keyExchange', t.keyExchange)];
  if (t.protocols) properties.push(prop('protocols', t.protocols.join(' ')));
  if (t.ciphers) properties.push(prop('ciphers', t.ciphers));
  if (t.hybridGroups.length) properties.push(prop('hybridGroups', t.hybridGroups.join(' ')));
  if (t.priority) {
    properties.push(prop('priority', t.priority));
    if (t.replacement) properties.push(prop('replacement', t.replacement));
  }
  for (const n of t.notes) properties.push(prop(`note:${n.code}`, n.text));
  return {
    type: 'cryptographic-asset',
    'bom-ref': refs.claim(`pqc-scan:tls:${slug(`${t.file} ${t.line} ${t.setting ?? ''}`)}`),
    name,
    cryptoProperties: { assetType: 'protocol', protocolProperties },
    evidence: { occurrences: [occurrence(t.file, t.line, t.setting ?? t.server, `${t.inTest ? 'Test code. ' : ''}${t.evidence}`)] },
    properties,
  };
}

/** The highest TLS version a configuration names ("1.3"), or undefined when it names none. */
function tlsVersion(protocols) {
  let best;
  for (const p of protocols ?? []) {
    if (p.startsWith('-')) continue; // an exclusion (Apache "all -TLSv1")
    const m = /tls\s*v?\s*(1(?:\.\d)?)\b/i.exec(p);
    if (!m) continue;
    const v = m[1].includes('.') ? m[1] : `${m[1]}.0`;
    if (!best || Number(v) > Number(best)) best = v;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Providers: the interfaces and the catalogued libraries
// ---------------------------------------------------------------------------

const INTERFACES = {
  'pqc-scan:interface:web-crypto': {
    type: 'library', 'bom-ref': 'pqc-scan:interface:web-crypto', name: 'Web Crypto API',
    description: 'The Web Cryptography API (crypto.subtle and crypto.getRandomValues) of the browser or runtime.',
  },
  'pqc-scan:interface:node-crypto': {
    type: 'library', 'bom-ref': 'pqc-scan:interface:node-crypto', name: 'node:crypto',
    description: "Node.js's crypto module, over the runtime's OpenSSL.",
  },
};

/**
 * Who provides an algorithm to the code: the interface, or the catalogued
 * package(s) the finding names. "library:a or b" (DESIGN.md §8.9) names both,
 * since the scanner could not tell which. A named constant has no provider.
 */
function providersOf(iface, libraries, refs) {
  if (iface === 'web-crypto') return ['pqc-scan:interface:web-crypto'];
  if (iface === 'node:crypto') return ['pqc-scan:interface:node-crypto'];
  if (!iface.startsWith('library:')) return [];
  return iface.slice('library:'.length).split(' or ').map((name) => {
    if (!libraries.has(name)) {
      libraries.set(name, libraryComponent({ name, versions: [], direct: false, dev: null, declaredIn: [], lockfiles: [], provides: '', postQuantum: 'check', importedAt: [] }, refs));
    }
    return libraries.get(name)['bom-ref'];
  });
}

function libraryComponent(d, refs) {
  const version = d.versions.find((v) => /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v));
  const component = {
    type: 'library',
    'bom-ref': refs.claim(`pqc-scan:library:${slug(d.name)}`),
    name: d.name,
    ...defined('version', version),
    ...defined('description', d.provides || undefined),
    // The package URL (purl) of an npm package: a scope's "@" is percent-encoded.
    purl: `pkg:npm/${d.name.replace(/^@/, '%40')}${version ? `@${version}` : ''}`,
    properties: [
      prop('direct', String(d.direct)),
      prop('dev', d.dev === null ? 'unknown' : String(d.dev)),
      prop('postQuantum', d.postQuantum),
    ],
  };
  if (d.versions.length) component.properties.push(prop('versions', d.versions.join(', ')));
  for (const f of d.declaredIn) component.properties.push(prop('declaredIn', f));
  for (const f of d.lockfiles) component.properties.push(prop('lockfile', f));
  for (const at of d.importedAt) component.properties.push(prop('importedAt', at));
  return component;
}

function link(provides, providerRef, assetRef) {
  if (!provides.has(providerRef)) provides.set(providerRef, new Set());
  provides.get(providerRef).add(assetRef);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Unique bom-refs: a second claim on the same text gets "-2", "-3", … */
class RefBook {
  constructor() { this.taken = new Set([ROOT_REF, TOOL_REF]); }

  claim(text) {
    let ref = text;
    for (let n = 2; this.taken.has(ref); n++) ref = `${text}-${n}`;
    this.taken.add(ref);
    return ref;
  }
}

function slug(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9.]+/g, '-').replace(/^-+|-+$/g, '') || 'x';
}

function prop(name, value) {
  return { name: `${P}:${name}`, value };
}

function defined(key, value) {
  return value === undefined || value === null ? {} : { [key]: value };
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
