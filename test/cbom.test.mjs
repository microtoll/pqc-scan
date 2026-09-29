// The CycloneDX 1.6 cryptographic bill of materials (DESIGN.md §8.14): every
// fixture's output against the published CycloneDX schema, one occurrence
// per finding, one asset per algorithm variant, providers and TLS groups
// linked by reference, the mapping of a known set of algorithms, and the
// same bill of materials on every machine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan, toCbom, buildCbom, CBOM_SPEC_VERSION } from '../src/index.js';
import { ROOT, FIXTURES, FIXED_NOW, scanFixture } from './helpers.mjs';
import { check } from './cyclonedx-check.mjs';

const SCHEMA = JSON.parse(readFileSync(join(ROOT, 'test', 'schemas', 'bom-1.6.schema.json'), 'utf8'));
const FIXTURE_SETS = ['webcrypto', 'node-crypto', 'traps', 'libraries', 'lockfiles', 'tls', 'cli', 'self', '.'];
const P = 'microtoll:pqc-scan';

const propOf = (c, name) => c.properties?.find((p) => p.name === `${P}:${name}`)?.value;
const byName = (bom, name) => bom.components.filter((c) => c.name === name);
const assetsOf = (bom) => bom.components.filter((c) => c.type === 'cryptographic-asset');

test('every fixture bill of materials matches the CycloneDX 1.6 schema, and the checker is not a rubber stamp', () => {
  assert.equal(SCHEMA.$id, 'http://cyclonedx.org/schema/bom-1.6.schema.json');
  for (const set of FIXTURE_SETS) {
    const bom = JSON.parse(toCbom(scanFixture(set)));
    assert.equal(bom.bomFormat, 'CycloneDX');
    assert.equal(bom.specVersion, CBOM_SPEC_VERSION);
    assert.deepEqual(check(SCHEMA, bom), [], set);
  }
  const bad = buildCbom(scanFixture('webcrypto'));
  bad.components[0].cryptoProperties.algorithmProperties.primitive = 'magic';
  bad.components[0].surprise = true;
  bad.metadata.timestamp = 'yesterday';
  delete bad.bomFormat;
  const errors = check(SCHEMA, bad);
  assert.ok(errors.some((e) => e.includes('magic')) && errors.some((e) => e.includes('surprise')) && errors.some((e) => e.includes('date-time')) && errors.some((e) => e.includes('missing bomFormat')), errors.join('\n'));
});

test('one occurrence per finding, one asset per algorithm variant, every reference resolves, every bom-ref is unique', () => {
  for (const set of ['webcrypto', 'node-crypto', 'libraries', 'tls', '.']) {
    const report = scanFixture(set);
    const bom = buildCbom(report);
    const assets = assetsOf(bom);
    const algorithms = assets.filter((c) => c.cryptoProperties.assetType === 'algorithm');
    const protocols = assets.filter((c) => c.cryptoProperties.assetType === 'protocol');
    const refs = bom.components.map((c) => c['bom-ref']);
    assert.equal(new Set(refs).size, refs.length, `${set}: unique bom-refs`);
    // Findings become occurrences of algorithm assets; TLS groups add one occurrence each.
    const groupUses = report.tls.reduce((n, t) => n + (t.groups?.length ?? 0), 0);
    const occurrences = algorithms.reduce((n, c) => n + c.evidence.occurrences.length, 0);
    assert.equal(occurrences, report.findings.length + groupUses, `${set}: occurrences`);
    for (const f of report.findings) {
      const asset = algorithms.find((c) => c.name === f.algorithm && c.evidence.occurrences.some((o) => o.location === f.file && o.line === f.line && o.symbol === `${f.interface}:${f.operation}`));
      assert.ok(asset, `${set}: ${f.file}:${f.line} ${f.algorithm} is an occurrence`);
      assert.equal(propOf(asset, 'class'), f.class);
    }
    // The variants are distinct by name, size, curve, hash and parameters, and there is one component per variant.
    const variants = new Set(report.findings.map((f) => [f.algorithm, f.keySize, f.curve, f.hash, JSON.stringify(Object.entries(f.parameters).sort())].join('|')));
    assert.ok(algorithms.length >= variants.size, `${set}: at least one asset per variant`);
    // One protocol per TLS configuration, referencing existing group assets.
    assert.equal(protocols.length, report.tls.length, `${set}: protocols`);
    for (const p of protocols) for (const ref of p.cryptoProperties.protocolProperties.cryptoRefArray ?? []) assert.ok(refs.includes(ref), `${set}: ${ref}`);
    // The dependency graph names only components in the bill of materials.
    for (const d of bom.dependencies) {
      assert.ok(refs.includes(d.ref) || d.ref === 'pqc-scan:root', `${set}: ${d.ref}`);
      for (const r of [...(d.dependsOn ?? []), ...(d.provides ?? [])]) assert.ok(refs.includes(r), `${set}: ${d.ref} → ${r}`);
    }
    // Every algorithm reached through an interface or a library is provided by it.
    for (const f of report.findings) {
      const providers = f.interface === 'web-crypto' ? ['pqc-scan:interface:web-crypto']
        : f.interface === 'node:crypto' ? ['pqc-scan:interface:node-crypto']
          : f.interface.startsWith('library:') ? f.interface.slice(8).split(' or ').map((n) => bom.components.find((c) => c.type === 'library' && c.name === n)['bom-ref']) : [];
      const asset = algorithms.find((c) => c.evidence.occurrences.some((o) => o.location === f.file && o.line === f.line && o.symbol === `${f.interface}:${f.operation}`));
      for (const provider of providers) {
        const entry = bom.dependencies.find((d) => d.ref === provider);
        assert.ok(entry?.provides?.includes(asset['bom-ref']), `${set}: ${provider} provides ${asset.name}`);
      }
    }
  }
});

test('the mapping of known algorithms: primitive, parameters, mode, padding, functions, security levels, properties', () => {
  const bom = buildCbom(scanFixture('webcrypto'));
  const one = (name) => { const found = byName(bom, name); assert.equal(found.length, 1, name); return found[0]; };
  const alg = (name) => one(name).cryptoProperties.algorithmProperties;

  const aes = alg('AES-256-GCM');
  assert.equal(aes.primitive, 'ae');
  assert.equal(aes.mode, 'gcm');
  assert.equal(aes.parameterSetIdentifier, '256');
  assert.equal(aes.classicalSecurityLevel, 256);
  assert.equal(aes.nistQuantumSecurityLevel, 5);
  assert.deepEqual(aes.cryptoFunctions, ['decrypt', 'keygen']); // unwrapKey, and deriveKey (the cipher's key coming into being) in the fixture

  const ecdh = one('ECDH P-256');
  assert.equal(ecdh.cryptoProperties.algorithmProperties.primitive, 'key-agree');
  assert.equal(ecdh.cryptoProperties.algorithmProperties.curve, 'P-256');
  assert.equal(ecdh.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0);
  assert.equal(ecdh.cryptoProperties.algorithmProperties.classicalSecurityLevel, 128);
  assert.equal(propOf(ecdh, 'quantumVulnerable'), 'true');
  assert.ok(['high', 'medium', 'low'].includes(propOf(ecdh, 'priority')));
  assert.ok(ecdh.evidence.occurrences.every((o) => /^(High|Medium|Low) priority \(/.test(o.additionalContext)));

  const oaep = alg('RSA-OAEP 2048-bit');
  assert.equal(oaep.primitive, 'pke');
  assert.equal(oaep.padding, 'oaep');
  assert.equal(oaep.parameterSetIdentifier, '2048');
  assert.equal(oaep.classicalSecurityLevel, 112);
  assert.equal(oaep.nistQuantumSecurityLevel, 0);

  assert.equal(alg('ML-DSA-65').primitive, 'signature');
  assert.equal(alg('ML-DSA-65').nistQuantumSecurityLevel, 3);
  assert.equal(alg('ML-DSA-65').parameterSetIdentifier, '65');
  assert.equal(alg('MLKEM768-X25519').primitive, 'combiner');
  assert.equal(alg('MLKEM768-X25519').nistQuantumSecurityLevel, 3);

  const pbkdf2 = one('PBKDF2-SHA-256');
  assert.equal(pbkdf2.cryptoProperties.algorithmProperties.primitive, 'kdf');
  assert.deepEqual(pbkdf2.cryptoProperties.algorithmProperties.cryptoFunctions, ['keyderive']);
  assert.equal(propOf(pbkdf2, 'parameter:iterations'), '10000');
  assert.equal(propOf(pbkdf2, 'hash'), 'SHA-256');

  const sha1 = alg('SHA-1');
  assert.equal(sha1.primitive, 'hash');
  assert.deepEqual(sha1.cryptoFunctions, ['digest']);
  assert.equal(sha1.nistQuantumSecurityLevel, 0);
  assert.equal(alg('SHA-512').parameterSetIdentifier, '512');
  assert.equal(alg('SHA-512').classicalSecurityLevel, 256);

  assert.equal(alg('Random (CSPRNG)').primitive, 'drbg');
  assert.deepEqual(alg('Random (CSPRNG)').cryptoFunctions, ['generate']);
  assert.equal(alg('AES-KW').mode, 'other');
  assert.equal(alg('AES-128-CBC').mode, 'cbc');
  assert.equal(alg('AES-128-CBC').primitive, 'block-cipher');

  const dynamic = byName(bom, 'dynamic (algorithm held in algorithmFromConfig)')[0];
  assert.equal(dynamic.cryptoProperties.algorithmProperties.primitive, 'unknown');
  assert.equal(propOf(dynamic, 'dynamic'), 'true');
  assert.equal(dynamic.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, undefined);

  // Both interfaces provide, the Web Crypto one everything in this fixture.
  const web = bom.dependencies.find((d) => d.ref === 'pqc-scan:interface:web-crypto');
  assert.ok(web.provides.includes(one('AES-256-GCM')['bom-ref']));
  assert.ok(bom.dependencies.find((d) => d.ref === 'pqc-scan:root').dependsOn.includes('pqc-scan:interface:web-crypto'));
});

test('node:crypto, libraries and MACs: HMAC is a mac with a tag function, RSA PKCS#1 v1.5 padding, a library with a purl provides its algorithms', () => {
  const node = buildCbom(scanFixture('node-crypto'));
  const hmac = byName(node, 'HMAC-SHA-256')[0].cryptoProperties.algorithmProperties;
  assert.equal(hmac.primitive, 'mac');
  assert.deepEqual(hmac.cryptoFunctions, ['tag']);
  const pkcs1 = byName(node, 'RSASSA-PKCS1-v1_5')[0].cryptoProperties.algorithmProperties;
  assert.equal(pkcs1.primitive, 'signature');
  assert.equal(pkcs1.padding, 'pkcs1v15');
  assert.deepEqual(pkcs1.cryptoFunctions, ['sign']);
  assert.equal(byName(node, '3DES-CBC')[0].cryptoProperties.algorithmProperties.classicalSecurityLevel, 112);
  assert.equal(byName(node, 'AES-256-ECB')[0].cryptoProperties.algorithmProperties.mode, 'ecb');
  assert.ok(propOf(byName(node, 'AES-256-ECB')[0], 'note:ecb') || byName(node, 'AES-256-ECB')[0].properties.some((p) => p.name.startsWith(`${P}:note:`)), 'the ECB note travels');
  assert.equal(byName(node, 'RSA 2048-bit')[0].cryptoProperties.algorithmProperties.primitive, 'unknown'); // a key pair whose use the call does not say

  const libs = buildCbom(scanFixture('libraries'));
  const jose = libs.components.find((c) => c.type === 'library' && c.name === 'jose');
  assert.equal(jose.purl, 'pkg:npm/jose@5.9.6');
  assert.equal(jose.version, '5.9.6');
  assert.equal(propOf(jose, 'direct'), 'true');
  const noble = libs.components.find((c) => c.type === 'library' && c.name === '@noble/curves');
  assert.equal(noble.purl, 'pkg:npm/%40noble/curves@1.9.2');
  // An "a or b" interface (DESIGN.md §8.9) is provided by both packages.
  const es256 = byName(libs, 'ES256')[0];
  for (const name of ['jose', 'jsonwebtoken']) {
    const ref = libs.components.find((c) => c.type === 'library' && c.name === name)['bom-ref'];
    assert.ok(libs.dependencies.find((d) => d.ref === ref).provides.includes(es256['bom-ref']), name);
  }
  assert.equal(byName(libs, 'bcrypt').find((c) => c.type === 'cryptographic-asset').cryptoProperties.algorithmProperties.primitive, 'kdf');
  assert.equal(propOf(byName(libs, 'bcrypt').find((c) => c.type === 'cryptographic-asset'), 'parameter:cost'), '12');
});

test('TLS: a protocol asset per configuration, its version, and its groups as shared algorithm assets', () => {
  const bom = buildCbom(scanFixture('tls'));
  const protocols = assetsOf(bom).filter((c) => c.cryptoProperties.assetType === 'protocol');
  assert.equal(protocols.length, 9);
  const nginxHybrid = protocols.find((c) => c.evidence.occurrences[0].location === 'nginx-hybrid/nginx.conf');
  assert.equal(nginxHybrid.cryptoProperties.protocolProperties.type, 'tls');
  assert.equal(nginxHybrid.cryptoProperties.protocolProperties.version, '1.3');
  assert.equal(propOf(nginxHybrid, 'keyExchange'), 'hybrid');
  const groupRefs = nginxHybrid.cryptoProperties.protocolProperties.cryptoRefArray;
  const groups = groupRefs.map((ref) => bom.components.find((c) => c['bom-ref'] === ref));
  assert.deepEqual(groups.map((g) => g.name), ['X25519MLKEM768', 'X25519', 'ECDH P-256']);
  assert.equal(groups[0].cryptoProperties.algorithmProperties.primitive, 'combiner');
  assert.equal(groups[0].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 3);
  assert.equal(groups[2].cryptoProperties.algorithmProperties.curve, 'P-256');
  // X25519 named by four configurations is one asset with an occurrence for each.
  const x25519 = byName(bom, 'X25519');
  assert.equal(x25519.length, 1);
  assert.ok(x25519[0].evidence.occurrences.length >= 4);
  assert.ok(x25519[0].evidence.occurrences.every((o) => o.symbol.startsWith('tls-group:')));
  // The classical-only nginx configuration carries the Low priority; the Apache one names no version ("all").
  const classical = protocols.find((c) => c.evidence.occurrences[0].location === 'nginx-classical/site.conf');
  assert.equal(propOf(classical, 'priority'), 'low');
  assert.equal(classical.cryptoProperties.protocolProperties.version, '1.2');
  const apache = protocols.find((c) => c.evidence.occurrences[0].location === 'apache/httpd-ssl.conf');
  assert.equal(apache.cryptoProperties.protocolProperties.version, undefined);
  assert.equal(propOf(apache, 'ciphers'), 'HIGH:!aNULL');
  const unstated = protocols.find((c) => c.evidence.occurrences[0].location === 'caddy-default/Caddyfile');
  assert.equal(unstated.cryptoProperties.protocolProperties.cryptoRefArray, undefined);
});

test('two scans of the same tree give the same bill of materials apart from the timestamp; no absolute path; sorted', () => {
  const a = buildCbom(scan(FIXTURES, { now: FIXED_NOW }));
  const b = buildCbom(scan(FIXTURES, { now: new Date('2030-01-01T00:00:00Z') }));
  assert.equal(a.metadata.timestamp, FIXED_NOW.toISOString());
  assert.notEqual(a.metadata.timestamp, b.metadata.timestamp);
  a.metadata.timestamp = b.metadata.timestamp = null;
  assert.deepEqual(a, b);
  const text = toCbom(scan(FIXTURES, { now: FIXED_NOW }));
  assert.ok(!text.includes(FIXTURES) && !text.includes(FIXTURES.replace(/\\/g, '/')), 'no absolute path');
  assert.equal(a.metadata.component.name, 'fixtures');
  const names = assetsOf(a).filter((c) => c.cryptoProperties.assetType === 'algorithm').map((c) => c.name);
  assert.deepEqual(names, [...names].sort());
  assert.ok(a.metadata.properties.some((p) => p.name === `${P}:notice` && p.value === 'An inventory and pointers, not a compliance certificate.'));
});
