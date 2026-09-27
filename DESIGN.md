# `pqc-scan` — design

Status: **decided 2026-09-27.** Decisions D-42, D-43, D-44 and D-45 (in the
Microtoll Engine's `DECISIONS.md`) were each taken as option (a), "as
designed". This document is the design those decisions approved, moved here
from the engine's `docs/` when this repository was created, with §8 added:
the details the design left open and how each was settled.

The engine's publish gate (D-01) applies here exactly as there: built and
checked locally, nothing pushed, `"private": true` in `package.json` until
the gate opens.

## 1. What it is, in one paragraph

A command-line tool, and a GitHub Action around it, that reads a JavaScript
or TypeScript codebase and its lockfile and writes an **inventory of the
cryptography it uses**: which algorithms, through which interface (Web
Crypto, `node:crypto`, a library), with what key sizes where they are
written down, where in the code, and which of them a large enough quantum
computer would break. The report is shaped like the discovery exercise the
UK National Cyber Security Centre (NCSC) asks organisations to complete in
its post-quantum migration timeline (discovery and a plan by 2028, the
highest-priority migrations by 2031, the rest by 2035): what you use,
where, a migration priority, and the hybrid or post-quantum replacement to
consider. It says on every page what it is: **an inventory and pointers,
not a compliance certificate.** It runs nothing it scans and sends nothing
anywhere.

## 2. Decision D-42: repository, name, licence, runtime — (a)

- **Repository:** `pqc-scan`, its own git history, the same gate. On GitHub
  it becomes `microtoll/pqc-scan` when the gate opens.
- **Name:** npm `@microtoll/pqc-scan`, binary `pqc-scan` (the scoped name
  cannot be squatted; the binary is what people type).
- **Licence:** Apache-2.0 — a tool people run in their own continuous
  integration (CI); permissive maximises adoption, and there is nothing to
  protect by copyleft.
- **Runtime:** Node 20 or later (it runs in other people's CI, where 24 is
  not yet everywhere), tested on 20 and 24; `node:test`; **zero runtime
  dependencies** — the scanner reads files and writes files.
- **Free forever at the command-line level.** The paid hosted report is not
  built (§5).

## 3. Decision D-43: what it detects, and how — (a)

### 3.1 How: a tokenizer, not a parser and not a grep

The scanner tokenizes each `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`,
`.tsx`, `.jsx` file — strings, template literals and comments recognised so
that a mention in a comment or in a string is never mistaken for a call, and
a `'` inside a template never ends a string — and then matches **call
sites** and **object-literal fields** near them:

- `subtle.<method>(…)` and `crypto.subtle.<method>(…)` for `generateKey`,
  `importKey`, `deriveKey`, `deriveBits`, `encrypt`, `decrypt`, `sign`,
  `verify`, `digest`, `wrapKey`, `unwrapKey` (and the key-encapsulation
  methods `encapsulateBits`, `encapsulateKey`, `decapsulateBits`,
  `decapsulateKey`), with the algorithm read from the nearest literal:
  `'AES-GCM'`, `{ name: 'ECDH', namedCurve: 'P-256' }`,
  `{ name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' }`, `'Ed25519'`,
  `'X25519'`, `'HKDF'`, `'PBKDF2'`, `'SHA-256'`, and the hybrid names
  (`'X25519MLKEM768'`, `'MLKEM768-X25519'`, `'ML-KEM-768'`, `'ML-DSA-65'`).
- `node:crypto` (`crypto.` or a destructured import): `createHash`,
  `createHmac`, `createCipheriv`/`createDecipheriv`, `generateKeyPair`(`Sync`),
  `createSign`/`createVerify`, `sign`/`verify`, `createECDH`,
  `createDiffieHellman`, `diffieHellman`, `publicEncrypt`/`privateDecrypt`,
  `pbkdf2`, `scrypt`, `hkdf`, `randomBytes`, `randomUUID`, `getRandomValues`,
  `webcrypto`, `KeyObject`/`createPublicKey`, `X509Certificate`; the
  algorithm from the literal argument (`'sha1'`, `'aes-128-cbc'`, `'rsa'` with
  `modulusLength`, `'ec'` with `namedCurve`, `'ed25519'`).
- **Libraries**, from `package.json` and the lockfile (`package-lock.json`
  v1–v3, `yarn.lock` v1, `pnpm-lock.yaml` — package names and versions only),
  against a catalogue of about forty packages with what each provides
  (`tweetnacl`, `libsodium-wrappers`, `@noble/curves`, `@noble/hashes`,
  `@noble/ciphers`, `@noble/post-quantum`, `node-forge`, `elliptic`,
  `jsonwebtoken`, `jose`, `bcrypt`/`bcryptjs`, `argon2`, `crypto-js`,
  `openpgp`, `ssh2`, `@peculiar/webcrypto`, `mlkem`, `pqc-kyber`,
  `eth-crypto`, `web-push`, …), and the import sites of each
  (`from 'jose'`, `require('bcrypt')`) with the algorithm literals they are
  called with where the library takes one (`alg: 'RS256'`, `'ES256'`,
  `'EdDSA'`, `'HS256'`).
- **TLS configuration** where it is written down: nginx (`ssl_protocols`,
  `ssl_ciphers`, `ssl_ecdh_curve`), Apache (`SSLProtocol`,
  `SSLOpenSSLConfCmd Curves`), Caddy (`protocols`, `curves`), and Node's
  `tls.createServer` / `https.createServer` options (`minVersion`,
  `ciphers`, `ecdhCurve`). A configuration that lists groups but no
  post-quantum hybrid group is reported as classical-only key exchange (see
  §8.6 for a configuration that lists none).

Each finding carries: the algorithm name as normalised, the **class**
(quantum-vulnerable public-key: RSA, DSA, DH, ECDH, ECDSA, EdDSA, X25519,
Ed25519, secp256k1; symmetric; hash; KDF or password hash; random;
post-quantum or hybrid; unknown), the key size or curve where it is
literal, the interface, `file:line`, and the evidence line. What cannot be
read statically (an algorithm name held in a variable) is reported as
"dynamic — check by hand", never guessed.

### 3.2 What it does not do

It runs nothing it scans, follows no `require` into `node_modules` beyond
the catalogue, reads no environment, sends nothing anywhere, and has no
telemetry. Frameworks' own cryptography (a session cookie signer inside a
web framework) is reported through the library catalogue when the
framework is on the list, and otherwise not at all — the report says so.

### 3.3 Alternatives (not taken)

(b) A real parser (TypeScript's) as a dependency: exact scoping of
variables, at the cost of an eight-megabyte dependency and a much harder
audit of the tool. (c) Regular expressions over raw text: no dependency,
but comments and strings produce false positives.

## 4. Decision D-44: the report — (a)

Two outputs from one scan:

- **`pqc-scan.json`** — schema version 1, the machine-readable inventory:
  `{ schema, notice, tool, scannedAt, root, summary, findings[],
  dependencies[], tls[], skipped[] }`. This JSON is the **seam** a hosted
  report would consume later (§5); it is documented in
  `schema/pqc-scan.schema.json` and versioned.
- **`pqc-scan.md`** — the human report, in this order:
  1. **Summary**: counts by class; the one-line verdict ("N
     quantum-vulnerable public-key uses in M files; K libraries; TLS
     classical-only"); the fixed sentence *an inventory and pointers, not a
     compliance certificate*.
  2. **What you use, where**: the inventory table (algorithm, class,
     interface, key size, file:line).
  3. **Quantum-vulnerable public-key uses, with a priority**:
     - **High** — data at rest sealed with a classical public-key seal
       (ECDH/RSA key agreement or encryption): harvest-now-decrypt-later
       applies; a recorded ciphertext can be opened later. Replacement: a
       hybrid seal (X25519MLKEM768 / ML-KEM-768 with the classical curve)
       for everything sealed from now on; re-sealing old data where it must
       outlive the transition.
     - **Medium** — signatures and authentication (ECDSA, Ed25519, RSA
       signatures, JWT `RS256`/`ES256`/`EdDSA`): forgeable once a large
       quantum computer exists, not before, so the risk is to long-lived
       artefacts (software signatures, certificates, documents). Replacement:
       ML-DSA or SLH-DSA where the platform offers them; plan, do not rush.
     - **Low** — ephemeral session key exchange (TLS with a hybrid group
       available, Diffie–Hellman for a session): enable the hybrid group;
       the exposure is the session, not the archive.
     The priority is a **heuristic** from the interface used and the words
     around the call (`encrypt`, `seal`, `store`, `sign`, `verify`, `tls`,
     `session`); the report says so on the page and asks for a person's
     review of each High.
  4. **Symmetric and hash notes**: AES-128 → consider 256 for data that
     must outlive the transition (Grover's algorithm halves the effective
     strength); SHA-1 and MD5 → replace regardless of quantum; 3DES/RC4/DES
     → replace now; PBKDF2 iterations under 100,000 flagged as weak on
     classical grounds.
  5. **Dependencies**: each catalogued library, its version, what it
     provides, whether it offers post-quantum algorithms.
  6. **TLS**: each configuration found and whether a hybrid group is
     enabled.
  7. **Next steps**, in the NCSC's three-milestone frame: finish discovery
     (the dynamic and unknown items), decide priorities, plan the High items
     for the 2031 milestone, the rest for 2035.
  8. **What this report cannot see** (§3.2), verbatim.

Options not taken: (b) JSON only; (c) SARIF (Static Analysis Results
Interchange Format) as well, for code-scanning tabs — deferred; the JSON
schema keeps the door open.

## 5. Decision D-45: the GitHub Action, and the paid seam — (a)

- **`action.yml`** in the same repository, a composite action: run the CLI
  from the action's own checkout (or, after publish, from npm at a pinned
  version), run it on the workspace, append `pqc-scan.md` to the job
  summary, upload `pqc-scan.json` as an artefact, and optionally fail the
  job when a threshold is crossed (`fail-on: high`). No marketplace listing
  until the gate opens.
- **The paid seam is the JSON schema and nothing else.** A hosted report —
  trends over time, an organisation-wide view, the tracked plan — would read
  `pqc-scan.json`. Nothing of it is built: no upload, no account, no
  endpoint, no code path that could phone home. The README says the CLI is
  free forever and that a hosted report may exist later.

## 6. Acceptance, and how it is shown

- Running it on **the Microtoll Engine** finds: AES-256-GCM, HKDF-SHA-256,
  PBKDF2 (310,000 iterations), SHA-256, Ed25519 (medium), P-256 ECDH (high:
  the seal), the hybrid `MLKEM768-X25519` (post-quantum), and reports the
  server's `node:crypto` verify and hash; the nginx sample as
  hybrid-enabled.
- Running it on **a second, real application** (read-only, chosen by the
  founder) finds the same constructions and whatever that application adds:
  a push-notification library (VAPID — Voluntary Application Server
  Identification — signatures and push-message encryption), a hybrid TLS
  group such as `X25519MLKEM768:X25519:prime256v1` in its nginx
  configuration, a composition in its test tooling. A library that is
  declared and imported only by a file the service never loads is still
  reported: a static scan cannot tell whether a file runs, and the report
  says so rather than guessing.
- Three public repositories chosen by the founder: the false-positive rate
  reviewed by hand; every false positive becomes a test case.
- Both reports read cleanly to someone IT-literate but not a specialist.

## 7. Shape of the repository

```
pqc-scan/
  bin/pqc-scan.mjs         the CLI: pqc-scan [dir] [--json out] [--md out] [--fail-on high|medium]
  src/tokenize.js          the JS/TS tokenizer
  src/source.js            reading the token stream: calls, arguments, object fields, constants, imports
  src/detect/webcrypto.js  node-crypto.js  libraries.js  tls.js  lockfiles.js  parameters.js
  src/catalogue.js         the library catalogue and the algorithm classes
  src/scan.js              walking the directory and running the detectors
  src/report.js            JSON (schema v1) and Markdown
  schema/                  the JSON schema of pqc-scan.json, version 1
  action.yml               the composite GitHub Action
  test/                    node:test; fixtures of real code shapes, each false positive found becomes one
  README.md  DESIGN.md  CHANGELOG.md  LICENSE  SECURITY.md (pointing at the engine's)
```

## 8. Details the design left open, and how each was settled

Each is the simplest choice that meets the design; each is stated here so
that an auditor can check the code against it.

### 8.1 Reading a value that is not written at the call

The design reads "the nearest literal". A tokenizer sees the call; the
literal is often one step away in a constant. The scanner follows exactly
these steps, and no others:

1. A `const` declared with a single literal (`const CURVE = 'P-256'`), or
   with an object literal, or with a conditional whose branches are object
   literals with the same `name`, **when the call sits inside the block
   where the `const` was declared, after it.** (The block test is
   bracket-counting: the declaration's `{…}` block must not have closed
   between the declaration and the call.)
2. The same, one hop across files: a named import from a **relative** path
   (`import { CURVE } from './primitives.js'`) resolved to a module-level
   `const` in a scanned file.
3. Nothing else. `let` and `var` are never followed (they can change), nor
   function parameters, nor anything under `node_modules`. What is left is
   reported as dynamic.

A function parameter that shadows a module-level constant of the same name
is not detected; this is the one known way step 1 can mislead, and it is
listed in the README's limits.

### 8.2 What counts as Web Crypto

A call `X.subtle.<method>(…)` where `X` is an identifier containing
`crypto` (`crypto`, `globalThis.crypto`, `webcrypto`, `nodeCrypto`) or a
bracketed expression that mentions one; or `<alias>.<method>(…)` where the
file binds `<alias>` from such an expression (`const subtle =
globalThis.crypto.subtle`, `const { subtle } = crypto`, `import { subtle }
from 'node:crypto'`). A variable merely *named* `subtle` is not Web Crypto
(a test fixture proves it). `crypto.getRandomValues` and
`crypto.randomUUID` are reported as random-number use.

### 8.3 What counts as `node:crypto`

A call through a name bound by `import … from 'crypto'` or
`'node:crypto'`, `require('crypto')`, `await import('node:crypto')` or
TypeScript's `import x = require('crypto')`, or directly on
`require('crypto')`. A `.sign(` or `.randomBytes(` on any other object is
not reported. `verify(null, …)` and `sign(null, …)`, where the key alone
decides the algorithm, are reported as dynamic. Node's one-shot
`crypto.hash()` is read like `createHash`.

### 8.4 The priority heuristic

- Signatures → **Medium**.
- Key agreement and public-key encryption → **High** if a sealing word is
  near the call (`seal`, `encrypt`, `decrypt`, `wrap`, `store`, `envelope`,
  `archive`, `backup`, `persist`); otherwise **Low** if a session word is
  (`tls`, `session`, `handshake`, `transport`, `socket`); otherwise **High**,
  with the reason "no context words; treated as High until a person
  checks". A sealing word wins over a session word: the conservative
  reading.
- A key whose use the call does not say (`generateKeyPair('ec')`, a JSON
  Web Key with `crv: 'P-256'`) → Medium if a signing word is near
  (`sign`, `verify`, `signature`, `jwt`, `auth`) and no sealing word;
  otherwise as key agreement.
- "Near" means the call's line, the eight lines above it, and the file's
  name; identifiers are split at camelCase and underscores, and comments
  count. Every finding's `priorityReason` names the word that decided it.
- TLS configurations that are classical-only → Low.

### 8.5 Libraries

The catalogue (`src/catalogue.js`, 45 packages, dated) records what each
package provides and whether it offers post-quantum algorithms (`yes`,
`no`, `partial`, or `check` where it depends on the version). For the
common packages it also maps calls to algorithms (`nacl.box` → X25519 with
XSalsa20-Poly1305, `bcrypt.hash(pw, 12)` → bcrypt with cost 12). JSON Web
Token (JWT) libraries are read by their algorithm literals: in a file that
imports one, a string that is exactly a JSON Web Algorithms name (`'RS256'`,
`'ES256'`, `'EdDSA'`, `'HS256'`, …) is a finding; `'none'` only as the value
of an `alg` or `algorithm` field. When a file imports a catalogued package
and none of its uses there could be read, one dynamic finding points at the
import. `jsonwebtoken`'s `sign` without an `algorithm` is reported as
HS256, its documented default.

### 8.6 TLS configuration that states no groups

A configuration that lists no key-exchange groups at all is reported as
**"unstated"**, not classical-only: the TLS library's defaults then apply,
and OpenSSL 3.5 and later offer `X25519MLKEM768` by default where older
versions do not. The report says to check the server's OpenSSL version.
Reporting it as classical-only would be a guess; the design's rule is
never to guess. A configuration that lists groups without a hybrid is
classical-only, as designed.

Which files are read: names ending `.conf` (with or without a further
suffix such as `.conf.template`), names starting `nginx`, `httpd` or
`apache`, and `Caddyfile`s. nginx is recognised by its `ssl_` directives,
Apache by `SSL…` directives, Caddy by a `tls { … }` block. Node's options
are read at `tls.createServer`, `tls.createSecureContext`,
`https.createServer`, `http2.createSecureServer` (always) and at
`tls.connect`, `https.request`, `https.get`, `https.Agent` (only when TLS
fields are written).

### 8.7 The report

- `root` is the scanned directory's name only, and every path is relative
  with forward slashes: a report says nothing about the machine that wrote
  it, and two machines write the same report.
- Findings are sorted by file, line, column, algorithm and operation;
  dependencies by name; configurations by file and line; directories are
  walked in byte order of their names. Only `scannedAt` differs between two
  scans of the same tree.
- Test code (a `test`, `tests`, `__tests__`, `spec` directory, or a
  `.test.`/`.spec.` file name) is scanned and marked `inTest`, not hidden:
  a composition in test tooling is part of the inventory.
- Evidence is the source line, trimmed and cut at 200 characters. It is
  copied as written: a secret written on the same line as a call will
  appear in the report (README, "what it cannot see").
- `node_modules` and `.git` are never walked; `--exclude` adds names.
  Symbolic links are not followed (a link could lead out of the tree); files
  over 2 MB are skipped; both are listed in `skipped[]`.
- Exit codes: 0 done, 1 the `--fail-on` threshold was met, 2 a usage or
  read error.
- With neither `--json` nor `--md`, the Markdown goes to standard output
  and nothing is written to disk.

### 8.8 Additions within the design

- Named parameters (`src/detect/parameters.js`): a module-level constant
  whose name says it is a PBKDF2 iteration count (`PBKDF2_ITERATIONS =
  310000`) is reported with its value, because a count passed through a
  function parameter can never be read at the call. The finding says where
  the count is declared, not that it reaches a call.
- ECB mode and unsigned JWTs (`alg: 'none'`) get a "replace now" note; both
  are wrong on classical grounds, like SHA-1.
