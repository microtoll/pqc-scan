// The detectors, fixture by fixture (DESIGN.md §3.1, §8.1–§8.6). Every scan
// goes through the public API; each expectation was checked by hand against
// the fixture's source, and each fixture says in its first lines what it is
// for. A false positive found later becomes a fixture and a line here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanFixture, lines, only } from './helpers.mjs';

test('Web Crypto: every call shape, the nearest literal, one-hop imported constants (§3.1, §8.1, §8.2)', () => {
  const r = scanFixture('webcrypto');
  assert.deepEqual(lines(r, 'seal.js'), [
    'seal.js:9 HKDF [importKey]',
    'seal.js:11 HKDF-SHA-256 [deriveKey]',          // hash: KDF_HASH, imported from ./params.js
    'seal.js:13 AES-256-GCM [deriveKey]',           // length: AEAD_BITS, imported
    'seal.js:20 ECDH P-256 [generateKey] high',     // namedCurve: SEAL_CURVE, imported; "seal" near
    'seal.js:21 ECDH [deriveBits] high',
    'seal.js:23 Random (CSPRNG) [getRandomValues]',
    'seal.js:25 AES-GCM [encrypt]',                 // a conditional whose branches share a name
    'seal.js:29 MLKEM768-X25519 [encapsulateBits]', // name: PQ_KEM, imported
  ]);
  assert.deepEqual(lines(r, 'shapes.ts'), [
    'shapes.ts:6 SHA-1 [digest]',                   // a typed const, through window.crypto.subtle
    'shapes.ts:12 RSA-OAEP 2048-bit [generateKey] low', // "session" and "transport" near, no sealing word
    'shapes.ts:19 ECDSA [sign] medium',             // `const { subtle } = globalThis.crypto`
    'shapes.ts:23 AES-128-CBC [generateKey]',       // through a TypeScript `as` cast
    'shapes.ts:27 PBKDF2-SHA-256 [deriveBits]',     // 10_000: a numeric separator
    'shapes.ts:31 AES-KW [wrapKey]',
    'shapes.ts:32 RSA-OAEP [unwrapKey] high',
    'shapes.ts:32 AES-256-GCM [unwrapKey]',
    'shapes.ts:36 X25519MLKEM768 [generateKey]',
    'shapes.ts:37 ML-DSA-65 [generateKey]',
    'shapes.ts:42 dynamic (algorithm held in algorithmFromConfig) [encrypt]',
    'shapes.ts:46 Random (CSPRNG) [getRandomValues]',
  ]);
  // A call inside a template substitution is code; the text around it is not.
  assert.deepEqual(lines(r, 'template.js'), ['template.js:4 SHA-512 [digest]']);
  assert.deepEqual(lines(r, 'params.js'), [], 'a constant alone is not a use');

  const byLine = (file, line, algorithm) => only(r, file).find((f) => f.line === line && f.algorithm === algorithm);
  assert.deepEqual(byLine('shapes.ts', 6, 'SHA-1').notes.map((n) => n.code), ['weak-hash']);
  assert.deepEqual(byLine('shapes.ts', 23, 'AES-128-CBC').notes.map((n) => n.code), ['aes-128']);
  const weak = byLine('shapes.ts', 27, 'PBKDF2-SHA-256');
  assert.deepEqual(weak.parameters, { iterations: 10000 });
  assert.deepEqual(weak.notes.map((n) => n.code), ['pbkdf2-iterations']);
  const rsa = byLine('shapes.ts', 12, 'RSA-OAEP 2048-bit');
  assert.equal(rsa.keySize, 2048);
  assert.equal(rsa.priorityReason, 'word "session" near the call: a session key exchange');
  const seal = byLine('seal.js', 20, 'ECDH P-256');
  assert.equal(seal.curve, 'P-256');
  assert.equal(seal.quantumVulnerable, true);
  assert.match(seal.priorityReason, /^word "seal/);
  assert.match(seal.replacement, /X25519MLKEM768/);
  const pq = byLine('seal.js', 29, 'MLKEM768-X25519');
  assert.equal(pq.class, 'post-quantum');
  assert.equal(pq.quantumVulnerable, false);
  assert.equal(pq.priority, null);
  const dyn = only(r, 'shapes.ts').find((f) => f.dynamic);
  assert.equal(dyn.class, 'unknown');
  assert.equal(r.summary.dynamic, 1);
  for (const f of r.findings) assert.equal(f.interface, 'web-crypto');
});

test('node:crypto: default, destructured, renamed, required inline, dynamic and TypeScript imports (§8.3)', () => {
  const r = scanFixture('node-crypto');
  assert.deepEqual(lines(r, 'cjs.cjs'), [
    'cjs.cjs:7 SHA-1 [createHash]',
    'cjs.cjs:11 Random (CSPRNG) [randomBytes]',     // `randomBytes: rb`
    'cjs.cjs:15 HMAC-SHA-512 [createHmac]',         // on require('crypto') itself
    'cjs.cjs:19 SHA3-256 [createHash]',             // a second namespace name
  ]);
  assert.deepEqual(lines(r, 'dynamic-import.mjs'), ['dynamic-import.mjs:5 dynamic (hash held in algo) [createHash]']);
  assert.deepEqual(lines(r, 'import-equals.ts'), ['import-equals.ts:5 SHA-384 [createHash]']);
  assert.deepEqual(lines(r, 'esm.mjs'), [
    'esm.mjs:6 MD5 [createHash]',
    'esm.mjs:10 HMAC-SHA-256 [createHmac]',
    'esm.mjs:14 AES-128-CBC [createCipheriv]',
    'esm.mjs:15 3DES-CBC [createCipheriv]',
    'esm.mjs:16 AES-256-ECB [createCipheriv]',
    'esm.mjs:21 RSA 2048-bit [generateKeyPairSync] high',
    'esm.mjs:22 EC secp256k1 [generateKeyPairSync] high',
    'esm.mjs:23 Ed25519 [generateKeyPairSync] medium',
    'esm.mjs:28 RSASSA-PKCS1-v1_5 [createSign] medium',
    'esm.mjs:32 ECDH P-256 [createECDH] high',          // prime256v1, normalised
    'esm.mjs:33 DH 2048-bit [getDiffieHellman] high',   // modp14
    'esm.mjs:38 RSA-OAEP [publicEncrypt] high',         // Node's default padding is OAEP
    'esm.mjs:42 PBKDF2-SHA-1 [pbkdf2Sync]',
    'esm.mjs:43 scrypt [scryptSync]',
    'esm.mjs:44 HKDF-SHA-512 [hkdfSync]',
    'esm.mjs:49 Random (CSPRNG) [randomBytes]',
    'esm.mjs:49 Random (CSPRNG) [randomUUID]',
    'esm.mjs:49 Random (CSPRNG) [getRandomValues]',
    'esm.mjs:53 dynamic (signature algorithm set by the key) [verify]', // verify(null, …)
    'esm.mjs:57 dynamic (X.509 certificate: its algorithms are inside the certificate) [X509Certificate]',
  ]);
  const at = (line, algorithm) => only(r, 'esm.mjs').find((f) => f.line === line && f.algorithm === algorithm);
  assert.deepEqual(at(6, 'MD5').notes.map((n) => n.code), ['weak-hash']);
  assert.deepEqual(at(15, '3DES-CBC').notes.map((n) => n.code), ['replace-now']);
  assert.deepEqual(at(16, 'AES-256-ECB').notes.map((n) => n.code), ['ecb']);
  assert.deepEqual(at(42, 'PBKDF2-SHA-1').parameters, { iterations: 1000 });
  assert.deepEqual(at(42, 'PBKDF2-SHA-1').notes.map((n) => n.code), ['pbkdf2-iterations']);
  assert.equal(at(22, 'EC secp256k1').priorityReason, 'no context words near the call; treated as High until a person checks');
  assert.equal(at(38, 'RSA-OAEP').priorityReason.startsWith('word "encrypt'), true);
  // HMAC with SHA-1 or MD5 is not flagged as a weak hash: HMAC does not rely on collision resistance.
  for (const f of r.findings) assert.equal(f.interface, 'node:crypto');
});

test('traps: mentions in comments, strings, templates and regular expressions; look-alike names (§3.1, §8.2, §8.3)', () => {
  const r = scanFixture('traps');
  assert.deepEqual(lines(r, 'comments-and-strings.js'), []);
  assert.deepEqual(lines(r, 'sign-not-crypto.js'), [], '.sign( and createHash( on other things');
  assert.deepEqual(lines(r, 'subtle-not-webcrypto.js'), [], 'a variable merely named subtle');
  // Method definitions named like node:crypto imports are not calls; the real calls inside are.
  assert.deepEqual(lines(r, 'method-definitions.ts'), [
    'method-definitions.ts:9 dynamic (signature algorithm set by the key) [sign]',
    'method-definitions.ts:21 SHA-256 [createHash]',
  ]);
});

test('libraries: calls mapped by the catalogue, JWT algorithm literals, the documented default, an unreadable import (§8.5)', () => {
  const r = scanFixture('libraries');
  assert.deepEqual(lines(r, 'src/jwt.js'), [
    'src/jwt.js:6 ES256 [algorithm literal] medium',
    'src/jwt.js:14 HS256 [sign]',                   // jsonwebtoken's documented default
    'src/jwt.js:18 RS256 [algorithm literal] medium',
    'src/jwt.js:22 JWT alg "none" [algorithm literal]',
    'src/jwt.js:22 EdDSA [algorithm literal] medium',
    // `display: 'none'` on line 26 is CSS, not an algorithm field: not reported.
  ]);
  const jwt = only(r, 'src/jwt.js');
  assert.deepEqual(jwt.find((f) => f.line === 14).notes.map((n) => n.code), ['library-default']);
  assert.equal(jwt.find((f) => f.line === 14).interface, 'library:jsonwebtoken');
  assert.deepEqual(jwt.find((f) => f.algorithm === 'JWT alg "none"').notes.map((n) => n.code), ['unsigned']);
  // Two JWT libraries in one file: a bare literal cannot say which it goes to, so both are named.
  assert.equal(jwt.find((f) => f.line === 18).interface, 'library:jose or jsonwebtoken');

  assert.deepEqual(lines(r, 'src/nacl.js'), [
    'src/nacl.js:5 X25519-XSalsa20-Poly1305 [box] high',
    'src/nacl.js:9 Ed25519 [sign.detached] medium',
    'src/nacl.js:13 XSalsa20-Poly1305 [secretbox]',
  ]);
  assert.deepEqual(lines(r, 'src/noble.js'), [
    'src/noble.js:10 Ed25519 [ed25519.sign] medium',
    'src/noble.js:14 X25519 [x25519.getSharedSecret] low',
    'src/noble.js:18 ECDSA P-256 [p256.sign] medium',
    'src/noble.js:22 ML-KEM-768 [ml_kem768.encapsulate]',
    'src/noble.js:26 HMAC-SHA-256 [hmac]',          // the hash from the imported function's name
  ]);
  assert.deepEqual(lines(r, 'src/passwords.js'), [
    'src/passwords.js:6 bcrypt [hash]',
    'src/passwords.js:10 MD5 [MD5]',
    'src/passwords.js:14 AES [AES.encrypt]',
    'src/passwords.js:18 PBKDF2 [PBKDF2]',
  ]);
  assert.deepEqual(only(r, 'src/passwords.js').find((f) => f.line === 6).parameters, { cost: 12 });
  assert.deepEqual(only(r, 'src/passwords.js').find((f) => f.line === 18).parameters, { iterations: 1000 });
  // Web push: a VAPID signature, and push-message encryption (ECDH with the subscriber's key).
  assert.deepEqual(lines(r, 'src/push.js'), [
    'src/push.js:4 ECDSA P-256 [setVapidDetails] medium',
    'src/push.js:7 ECDH P-256 [sendNotification] high',
    'src/push.js:7 ECDSA P-256 [sendNotification] medium',
  ]);
  // A computed member: one dynamic pointer at the import, never a guess.
  assert.deepEqual(lines(r, 'src/unread.js'), ['src/unread.js:3 dynamic (tweetnacl imported; its uses here could not be read) [import]']);
});

test('dependencies: from package.json, the lockfile and the imports; uncatalogued packages left out (§3.1, §8.5)', () => {
  const r = scanFixture('libraries');
  const deps = Object.fromEntries(r.dependencies.map((d) => [d.name, d]));
  assert.deepEqual(Object.keys(deps), ['@noble/curves', '@noble/hashes', '@noble/post-quantum', 'bcrypt', 'crypto-js', 'http_ece', 'jose', 'jsonwebtoken', 'jws', 'tweetnacl', 'web-push']);
  assert.equal(deps['left-pad'], undefined);
  assert.deepEqual(deps.tweetnacl, {
    name: 'tweetnacl', versions: ['1.0.3'], direct: true, dev: false,
    declaredIn: ['package.json'], lockfiles: ['package-lock.json'],
    provides: deps.tweetnacl.provides, postQuantum: 'no',
    importedAt: ['src/nacl.js:2', 'src/unread.js:3'],
  });
  assert.equal(deps['@noble/hashes'].dev, true, 'a devDependency');
  assert.equal(deps['@noble/post-quantum'].postQuantum, 'yes');
  assert.equal(deps.jose.postQuantum, 'check');
  assert.equal(deps.bcrypt.postQuantum, 'n/a');
  // Transitive: in the lockfile only, never imported.
  assert.equal(deps.http_ece.direct, false);
  assert.deepEqual(deps.jws.versions, ['3.2.2', '4.0.0']);
  assert.deepEqual(deps.jws.importedAt, []);
});

test('lockfiles: npm v1 and v3, yarn v1 and Berry, pnpm v5, v6 and v9 — names and versions only (§3.1)', () => {
  const versions = (dir) => Object.fromEntries(scanFixture(`lockfiles/${dir}`).dependencies.map((d) => [d.name, [d.versions.join(','), d.dev]]));
  assert.deepEqual(versions('npm-v1'), {
    jsonwebtoken: ['8.5.1', false], jws: ['3.2.2', false], 'node-forge': ['0.10.0', true],
  });
  assert.deepEqual(versions('npm-v3'), {
    '@hpke/core': ['1.7.2', false], '@microtoll/crypto-core': ['0.3.0', false],
    argon2: ['0.41.1', true], 'cookie-signature': ['1.0.6', false],
  });
  assert.deepEqual(versions('yarn-v1'), { '@noble/hashes': ['1.4.0', null], elliptic: ['6.5.4', null] });
  assert.deepEqual(versions('yarn-berry'), { '@simplewebauthn/server': ['10.0.1', null], openpgp: ['5.11.2', null] });
  assert.deepEqual(versions('pnpm-v5'), { '@peculiar/webcrypto': ['1.4.3', true], 'sodium-native': ['4.0.4', false] });
  assert.deepEqual(versions('pnpm-v6'), { '@hpke/ml-kem': ['0.1.0', false], mlkem: ['2.3.1', false] });
  assert.deepEqual(versions('pnpm-v9'), { '@noble/post-quantum': ['0.5.1', null], bcryptjs: ['2.4.3', null] });
  const all = scanFixture('lockfiles');
  assert.equal(all.findings.length, 0, 'a lockfile is inventory, not a use');
  for (const d of all.dependencies) assert.equal(d.direct, false);
});

test('TLS: nginx, Apache, Caddy and Node; hybrid, classical-only, unstated and not readable (§3.1, §8.6)', () => {
  const r = scanFixture('tls');
  const state = r.tls.map((t) => `${t.file}:${t.line} ${t.server}${t.setting ? ` ${t.setting}` : ''} ${t.keyExchange}${t.priority ? ` ${t.priority}` : ''}`);
  assert.deepEqual(state, [
    'apache/httpd-ssl.conf:7 apache hybrid',
    'caddy-default/Caddyfile:2 caddy unstated',
    'caddy/Caddyfile:4 caddy classical-only low',
    'nginx-classical/site.conf:7 nginx classical-only low',
    'nginx-hybrid/nginx.conf:11 nginx hybrid',
    'nginx-unstated/default.conf.template:2 nginx unstated',
    'node/server.mjs:9 node https.createServer hybrid',
    'node/server.mjs:12 node tls.createServer classical-only low',  // options read from a const
    'node/server.mjs:15 node https.createServer dynamic',           // options from the caller
    // https.get with no TLS fields (line 19) is not a configuration; supervisord.conf is not TLS.
  ]);
  const at = (file) => r.tls.find((t) => t.file === file);
  assert.deepEqual(at('nginx-hybrid/nginx.conf').hybridGroups, ['X25519MLKEM768']);
  assert.deepEqual(at('nginx-hybrid/nginx.conf').groups, ['X25519MLKEM768', 'X25519', 'prime256v1']);
  assert.deepEqual(at('nginx-classical/site.conf').notes.map((n) => n.code), ['old-protocol', 'weak-ciphers']);
  assert.match(at('nginx-classical/site.conf').replacement, /X25519MLKEM768/);
  // No groups written: the library's defaults apply, so "unstated", never guessed classical.
  assert.deepEqual(at('nginx-unstated/default.conf.template').notes.map((n) => n.code), ['groups-unstated']);
  assert.match(at('nginx-unstated/default.conf.template').notes[0].text, /OpenSSL 3\.5/);
  assert.equal(at('nginx-unstated/default.conf.template').priority, null);
  assert.deepEqual(r.summary.tls, { configurations: 9, keyExchange: 'mixed' });
  assert.equal(r.summary.byPriority.low, 3);
  assert.equal(r.findings.length, 0);
});

test('the command-line fixtures: one High, one Medium and one clean directory', () => {
  assert.deepEqual(lines(scanFixture('cli')), [
    'high/seal.js:3 ECDH P-384 [generateKey] high',
    'high/seal.js:4 ECDH [deriveBits] high',
    'medium/sign.js:3 Ed25519 [sign] medium',
  ]);
  assert.equal(scanFixture('cli/clean').findings.length, 0);
});
