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
     strength); SHA-1 and MD5 → replace wherever they protect something,
     regardless of quantum (lower risk as a plain identifier); 3DES/RC4/DES
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
  reviewed by hand; every false positive becomes a test case. (Done on
  2026-09-27: §8.12.)
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
  src/cbom.js              the CycloneDX 1.6 bill of materials (§8.14)
  src/mcp.js               pqc-scan mcp, the tool for coding agents (§8.15)
  src/mcp-protocol.js      the Model Context Protocol subset, copied from @microtoll/mcp
  schema/                  the JSON schema of pqc-scan.json, version 1
  action.yml               the composite GitHub Action
  server.json              the MCP registry listing (§8.15)
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
  (`sign`, `verify`, `signature`, `jwt`, `auth`; since the acceptance
  run `webauthn`, `passkey`, `assertion`, `cose`: a passkey's key only
  verifies signatures; since the public review (§8.12) `cert`,
  `certificate`, `x509`: a certificate is a signing artefact) and no sealing
  word; otherwise as key agreement.
- "Near" means the call's line, the eight lines above it, and the file's
  name; identifiers are split at camelCase and underscores, and comments
  count. Every finding's `priorityReason` names the word that decided it.
- TLS configurations that are classical-only → Low.

### 8.5 Libraries

The catalogue (`src/catalogue.js`, 57 packages, dated) records what each
package provides and whether it offers post-quantum algorithms (`yes`,
`no`, `partial`, or `check` where it depends on the version). For the
common packages it also maps calls to algorithms (`nacl.box` → X25519 with
XSalsa20-Poly1305, `bcrypt.hash(pw, 12)` → bcrypt with cost 12). JSON Web
Token (JWT) libraries are read by their algorithm literals: in a file that
imports one, a string that is exactly a JSON Web Algorithms name (`'RS256'`,
`'ES256'`, `'EdDSA'`, `'HS256'`, …) is a finding; `'none'` only as the value
of an `alg` or `algorithm` field, or in an `algorithms: [...]` list (a
verifier that accepts unsigned tokens). When a file imports a catalogued package
and none of its uses there could be read, one dynamic finding points at the
import. `jsonwebtoken`'s `sign` without an `algorithm` is reported as
HS256, its documented default. A member the catalogue marks as doing no
cryptography (`plain`: `jwt.decode`, `passport-jwt`'s `ExtractJwt`, `jose`'s
`decodeJwt`) counts as a use that was read, so a file that only decodes a
token gets no pointer (§8.12).

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
- Test code (a `test`, `tests`, `__tests__`, `spec`, `specs` or `test-d`
  directory, a path containing a text given with `--test-files`, or a
  `.test.`/`.spec.` file name) is scanned and marked `inTest`, not hidden:
  a composition in test tooling is part of the inventory.
- Evidence is the source line, trimmed and cut at 200 characters. It is
  copied as written: a secret written on the same line as a call will
  appear in the report (README, "what it cannot see").
- `node_modules` and `.git` are never walked; `--exclude` adds names.
  Symbolic links are not followed (a link could lead out of the tree); files
  over 2 MB are skipped, and so are binary files (a NUL in the first 8,000
  bytes, git's own rule; a NUL anywhere skipped a real source file with a
  raw control character in a regular expression); all are listed in
  `skipped[]`.
- Exit codes: 0 done, 1 the `--fail-on` threshold was met, 2 a usage or
  read error.
- With neither `--json` nor `--md`, and standard output a pipe, the Markdown
  goes to standard output and nothing is written to disk. At a terminal the
  reports go to the current folder instead (§8.13).

### 8.8 Additions within the design

- Named parameters (`src/detect/parameters.js`): a module-level constant
  whose name says it is a PBKDF2 iteration count (`PBKDF2_ITERATIONS =
  310000`) is reported with its value, because a count passed through a
  function parameter can never be read at the call. The finding says where
  the count is declared, not that it reaches a call.
- ECB mode and unsigned JWTs (`alg: 'none'`) get a "replace now" note; both
  are wrong on classical grounds, like SHA-1.

### 8.9 A JWT algorithm literal in a file that imports several JWT libraries

A bare literal (`'RS256'`) cannot say which library it is passed to. When a
file imports more than one JWT library, the finding's interface names them
all (`library:jose or jsonwebtoken`) rather than picking one. Found on the
fixture `test/fixtures/libraries/src/jwt.js`, where the first version
attributed `jsonwebtoken`'s `RS256` to `jose`.

### 8.10 The Markdown cannot be written into by a scanned repository

Everything in the Markdown that comes from a scanned file (evidence, paths,
algorithm names read from literals) is made inert: evidence and paths go in
code spans whose fence is longer than any backtick run inside them, with
`|` escaped so a table cell cannot end early; other text has the characters
that open links, images, HTML, emphasis and code spans backslash-escaped
(CommonMark §2.4). A hostile repository therefore cannot put a link or a
sentence into a report that a reviewer might trust. A test proves it with a
file named `[x](evil).js` and an evidence line full of pipes, backticks and
HTML.

### 8.11 The GitHub Action

- The threshold is applied in the last step, after the job summary and the
  upload, so a failing job still shows and keeps its report.
- Inputs reach its scripts through environment variables, never by
  expanding `${{ inputs.* }}` inside a script, so an input cannot run as
  shell code (SECURITY.md).
- GitHub accepts at most 1 MiB of job summary per step; a larger report is
  replaced there by a pointer to the artefact.
- It runs `node` from the runner and checks for version 20 or later; it
  does not install Node, which would change the Node the rest of the job
  uses.
- `actions/upload-artifact` is pinned to a full commit SHA, as the engine
  pins its own actions.

### 8.12 From the false-positive review of three public repositories (2026-09-27)

The third acceptance item (§6). Three repositories of different shapes,
proposed at the founder's request, each a shallow clone read once and never
written to:

| Repository | Commit | Why this shape | Read | Findings | Quantum-vulnerable |
| --- | --- | --- | --- | --- | --- |
| `panva/jose` | `55c959f` | a JSON Web Token library: every finding should be genuine | 145 files | 108 in 32 files, 16 dynamic | 21 (11 High, 10 Medium) |
| `excalidraw/excalidraw` | `84e3f5a` | a large browser application with almost no cryptography: noise | 712 files | 9 in 4 files | 2 (Medium) |
| `requarks/wiki` | `712a3a5` | a server application with a typical sign-in stack | 272 files | 13 in 11 files | 6, then 7 after the fixes |

Every reported finding was a genuine cryptographic use, and a hand search of
jose's source (31 `subtle` calls) and of Excalidraw (10 call sites) found
nothing missed; `exportKey` and `getPublicKey` are not read, by design, since
they perform no cryptography. The faults were around the findings, in the
report and the catalogue. Each is fixed with a fixture and a test:

1. **Every dependency version printed as `\1.0.6`.** `escapeText` escaped an
   ordered-list marker by putting the backslash before the digit; CommonMark
   §2.4 escapes only punctuation, so the backslash was printed. Now `1\.0.6`,
   which renders as `1.0.6` (§8.10; a test in `report.test.mjs`). This was
   in every report with a lockfile.
2. **A package listed as a transitive dependency of itself.** jose's type
   tests import `jose` by name (a package self-reference) and the table
   listed it, version unknown. The engine's own report had likewise listed
   `@microtoll/crypto-core`, declared by its sibling packages. A package the
   tree provides (the root `package.json`'s name, or a workspace package's,
   including its `node_modules` link in the lockfile) is not a dependency and
   is left out of the table; its uses are still findings. Fixture `self/`.
3. **`test-d` not marked as test code.** tsd's directory for type tests; 21
   of jose's findings. Added to the test directories (§8.7).
4. **Two "could not be read" pointers at code that does no cryptography.**
   Wiki.js's browser code imports `jsonwebtoken` only to `decode` a token
   without checking it, and its server imports `passport-jwt` only for
   `ExtractJwt`. The catalogue now marks such members `plain`; a file that
   uses only those has been read and gets no pointer (§8.5). Fixture
   `libraries/src/decode.js`.
5. **A token-signing key pair reported High.** Wiki.js makes its RSA key pair
   under the comment "Generate certificates" and nothing else nearby; the
   same call elsewhere in the tree was Medium only because a doc comment
   said "Authentication". A certificate is a signing artefact: `cert`,
   `certificate` and `x509` are signing words (§8.4). Fixture
   `node-crypto/certificates.js`.
6. **SAML sign-in, encrypted assertions and two-factor codes unreported.**
   Wiki.js's `passport-saml` (RSA signatures on assertions, RSA key
   transport where they are encrypted) and `node-2fa` were not catalogued,
   so invisible. §3.2 says an uncatalogued framework is not reported, but a
   sign-in stack this common should be. Added: `passport-saml`,
   `@node-saml/passport-saml`, `@node-saml/node-saml`, `xml-crypto`,
   `xml-encryption`, `node-2fa`, `jwks-rsa`, `openid-client` (57 packages).
   Fixture `libraries/src/saml.js`. Wiki.js now shows the SAML signature
   (Medium) and four more libraries.
7. **The SHA-1 note overstated.** Both applications use SHA-1 only as a
   content or path identifier (a file id, a page hash), and the note said
   "replace regardless". It now says where it matters: wherever the hash
   protects something; as a plain identifier the risk is lower, and the
   reader checks what a collision would allow.

After the fixes: jose 0 libraries (was 1) and 61 findings in test code (was
40); Excalidraw unchanged apart from readable versions; Wiki.js 7
quantum-vulnerable uses (0 High, 7 Medium; was 1 High), 0 dynamic (was 2),
16 libraries (was 12); the engine 0 libraries (was 1), otherwise unchanged.

Right by the design, and worth knowing:

- Excalidraw's AES-GCM key length is "not written here": the constant comes
  from a workspace package (`@excalidraw/common`), and §8.1 follows relative
  imports only. The constant's name is in the evidence for a person to
  follow. The JSON Web Key beside it says `alg: "A128GCM"`; the scanner reads
  `length`, not a JSON Web Key's `alg`, for AES.
- jose's RSA and X25519 key pairs in its tests are High by the words
  `encrypt` and `decrypt` near them: right, since JSON Web Encryption's key
  management is sealing. Its `tap/` harness is not a test directory by any
  convention and stays unmarked.
- Wiki.js's `https.createServer` sets no groups: "unstated", with the
  OpenSSL note (§8.6), not classical-only.
- SHA-1 as an identifier is still listed: an inventory lists what is used.

### 8.13 The terminal default (2026-09-27)

Run from a terminal with no output named, the command line writes
`pqc-scan.md` and `pqc-scan.json` into the current folder and prints a
four-line summary (the verdict, the counts, where each file is and what to
read first); `--write` asks for the same from a script. Piped with nothing
named, the Markdown goes to standard output and nothing is written, so a
script that read the Markdown from a pipe is unchanged. `--test-files
<text>` (the Action input `test-files`) marks a file whose path contains
the text as test code, for projects whose tests are not named `test`,
`spec` or `__tests__`. From the founder's first run on a Windows PC, where
the whole report scrolled past in a Command Prompt (CHANGELOG 0.1.0). This
section was cited by the command line and the changelog before it was
written down; it is written here for the record.

### 8.14 The CycloneDX cryptographic bill of materials (2026-09-29)

**Why.** A cryptographic bill of materials (CBOM) is the artefact a central
inventory, a supplier questionnaire and the US memorandum M-26-15 (24 June
2026) ask for, and the form NIST and CISA must define minimum elements for
by March 2027; CycloneDX 1.6 is the published format for it. Writing one
from the scan makes the free tool useful to the person who keeps an
organisation's inventory, without changing the report or its schema. It is
the first item of the evidence pack (decision E-01 of the hosted-report
design, kept in its own repository; the scanner stays free and has no
upload, account or endpoint, §5).

**What.** `--cbom <file>` (the Action input `cbom`, default
`pqc-scan.cbom.json`) writes a CycloneDX 1.6 JSON document from the report
object alone (`src/cbom.js`, `toCbom` and `buildCbom` in the public API), as
the Markdown is written from it, so the three outputs never disagree and
the bill of materials says nothing the report does not. It is written only
when asked for; the terminal default (§8.13) is unchanged.

**The mapping.**

| In the report | In the bill of materials |
| --- | --- |
| a finding | an `occurrence` (`location` the file, `line`, `symbol` `interface:operation`, `additionalContext` the evidence line prefixed with the use's priority and reason, and "Test code." where it is) of a `cryptographic-asset` component |
| an algorithm variant: the normalised name with its key size, curve, hash and literal parameters | one component, however many uses and interfaces; AES-256-GCM through Web Crypto and through `node:crypto` is one asset with two providers |
| `class`, `kind` | properties `microtoll:pqc-scan:class` and `:kind`; `algorithmProperties.primitive` from the kind: key-agree, pke, signature, kem (combiner for a hybrid), ae, block-cipher or stream-cipher, mac, hash (xof for SHAKE), kdf, drbg; `unknown` for a key pair whose use the call does not say and for a name that could not be read |
| key size, curve, hash, parameters | `parameterSetIdentifier` (a key size, a digest length, "65", "SHA2-128s"), `curve`, `:hash`, `:parameter:<name>` |
| the algorithm's name | `mode` (gcm, cbc, ctr, ecb, ccm, cfb, ofb; other for key wrap) and `padding` (oaep; pkcs1v15) where the name says |
| the operation | `cryptoFunctions` (keygen, encrypt, decrypt, digest, tag, keyderive, sign, verify, encapsulate, decapsulate, generate) read from the call's name, then from the kind; `other`, or `unknown` for a dynamic name, when neither says |
| priority, reason, replacement | the highest priority among the asset's occurrences as `:priority` and `:replacement`; each occurrence carries its own priority and reason in its context |
| notes | `:note:<code>` |
| what a quantum computer breaks | `nistQuantumSecurityLevel` 0 for every classical public-key algorithm and for MD4, MD5 and SHA-1; 1 to 5 where the name settles it (AES-128, -192, -256; SHA-2 and SHA-3 by digest length; ML-KEM, ML-DSA, SLH-DSA and the hybrids by parameter set; ChaCha20 and Salsa20 with a 256-bit key); otherwise omitted, never guessed |
| classical strength | `classicalSecurityLevel` from NIST SP 800-57 Part 1 where tabulated (AES by key size, the NIST curves and Curve25519 and Curve448, RSA and DH at 1024, 2048, 3072, 7680 and 15360 bits, 3DES at 112, SHA-2 and SHA-3 collision resistance); otherwise omitted |
| the interfaces | `library` components "Web Crypto API" and "node:crypto"; a named constant (§8.8) has no provider |
| a catalogued dependency | a `library` component with a package URL (`pkg:npm/…`, a scope's `@` percent-encoded), the lockfile's version where it is a plain version, the catalogue's description, and `:direct`, `:dev`, `:postQuantum`, `:versions`, `:declaredIn`, `:lockfile`, `:importedAt`; a package a finding names that the manifests did not (§8.9's "library:a or b") is a component without a version, and both provide the finding |
| the graph | `dependencies[]`: the scanned tree depends on its direct dependencies and on the interfaces; each provider `provides` the assets found through it |
| a TLS configuration | a `protocol` asset (`protocolProperties.type` tls, `version` the highest version named, none for Apache's "all", `cryptoRefArray` the groups), with `:keyExchange`, `:protocols`, `:ciphers` (the raw string; no cipher suites are parsed), `:hybridGroups`, `:priority`; each group an algorithm asset named as the scanner names the same algorithm in code (X25519, X448, ECDH P-256, -384, -521, DH n-bit, the hybrid's own spelling), so a group and a call share one asset; an unrecognised group keeps its name |
| `summary`, `skipped` | `metadata.properties`: the notice, the verdict, the counts, `tls.keyExchange`, one `skipped` entry per file not read |
| `scannedAt`, `tool`, `root` | `metadata.timestamp`, `metadata.tools.components` (with the catalogue month), `metadata.component` (the scanned directory's name) |

Every asset states `executionEnvironment` software-plain-ram and
`implementationPlatform` generic, which is true of JavaScript. The
`serialNumber` is a UUID worked out from the rest of the document, its
timestamp included: RFC 9562's version 8 from SHA-256 (its Appendix B.2),
not version 5, which would mean SHA-1. Each scan's file therefore has its
own serial number, as CycloneDX recommends, and one report always gives
one file. The first version of this section left the serial number out,
since CycloneDX makes it optional; IBM's CBOMkit viewer refuses a file
without it, found while preparing the acceptance check below (2026-09-29,
the founder's choice among a serial number tied to the scan, a random one,
and none).
`bom-ref`s are deterministic (`pqc-scan:algorithm:…`, `:library:…`,
`:tls:…`, `:interface:…`), suffixed only on a collision.

**Tests** (`test/cbom.test.mjs`). Every fixture's bill of materials against
the CycloneDX 1.6 JSON schema, checked by `test/cyclonedx-check.mjs`, a
second small checker for the keywords that schema uses (the rule of
`schema-check.mjs` holds: a keyword it does not know is an error; a
`format` other than date-time or a reference into another schema file is
an error too, so nothing is passed unchecked); the checker refuses a
wrong enumeration, an unknown field, a bad timestamp and a missing
`bomFormat`. One occurrence per finding plus one per TLS group; every
reference in `cryptoRefArray` and in the graph resolves to a component;
every `bom-ref` unique; every algorithm reached through an interface or a
library is provided by it. The mapping of a known set (AES-256-GCM,
ECDH P-256, RSA-OAEP 2048, ML-DSA-65, the hybrid, PBKDF2 with its
iterations, SHA-1, the random source, AES-KW, AES-128-CBC, a dynamic name;
HMAC, PKCS#1 v1.5, 3DES, ECB, a bare RSA key pair; jose's purl, a scoped
purl, the "a or b" providers, bcrypt's cost; nine TLS configurations, the
hybrid group as a combiner, X25519 as one shared asset, Apache's absent
version). Two scans of one tree give the same bill of materials apart from
the timestamp and the serial number; the serial number is the version 8
UUID of the rest of the document; the fields the CBOMkit viewer requires
are present; no absolute path; assets sorted. The schema copy at
`test/schemas/bom-1.6.schema.json` is from the specification repository at
tag 1.6.1 (Apache-2.0) and is not part of the published package.

**Acceptance.** Running it on the engine's own repository writes a bill of
materials that validates; loading that file into IBM's CBOMkit viewer by
hand is still to be done before the release, and the design's claim is
limited to schema validity until then. When NIST and CISA publish the
minimum elements (March 2027), this section is revisited.

### 8.15 The scanner as a tool for coding agents (2026-09-29)

**Why.** A coding agent that writes cryptographic code should be able to
check what it wrote, in the same session, without a person running the
command line and pasting the report back. A finding of June 2026, cited
by the hosted-report design, is that post-quantum code written with a
large language model's help drifts from secure patterns; a scan the agent
can call is a cheap check on that.
It is decision E-07 of the hosted-report design (its own repository),
taken as option (a): inside the scanner, not a separate package.

**What.** `pqc-scan mcp` runs a Model Context Protocol (MCP) server on
standard input and output with one tool, `pqc_scan`:

| Argument | Meaning |
| --- | --- |
| `directory` (required) | the folder to scan: absolute, or relative to the folder the host started the server in |
| `exclude` | as `--exclude`, a list |
| `testFiles` | as `--test-files`, a list |

The result is the JSON report, schema version 1, exactly as `--json`
writes it except for the indentation: compact, because the report goes
into the agent's context and indentation is about a quarter of its length
(59 KB against 79 KB on this repository). A folder that cannot be scanned
and an argument of the wrong shape are tool results with `isError`, which
the host shows to the agent; an unknown tool or method is a JSON-RPC
error. The server's instructions ask the agent to call the tool after
changing cryptographic code and to consider the replacement named for
anything at high or medium priority; the tool's description and the
instructions both end with the notice.

- **Reads only.** The tool writes nothing (no report file, no bill of
  materials) and runs nothing it scans, as the command line. The report
  goes back to the host that asked for it; the scanner still sends
  nothing anywhere. What the host does with it is the host's: an agent's
  context usually reaches a model provider, and the report carries source
  lines as evidence (§8.7), lines the agent could already read.
- **Size.** The whole report comes back. A codebase large enough to pass
  a host's limit on a tool result is scanned a folder at a time, or with
  `exclude`; the tool's description says so. A summary-only result was
  not added: the design names the JSON report, and the schema is the one
  seam (§5).
- **The protocol** is the subset a tools-only server needs (`initialize`,
  `ping`, `tools/list`, `tools/call`; protocol version 2025-06-18),
  copied from `@microtoll/mcp` 0.1.2 into `src/mcp-protocol.js` rather
  than imported, so the scanner keeps zero dependencies; its header names
  the source and the one change (a log prefix). The library exports
  `createMcpServer`, `mcpTools`, `MCP_INSTRUCTIONS` and
  `MCP_PROTOCOL_VERSION`.
- **The command.** `mcp` is a command only as the first argument and
  with nothing after it; anything after it is a usage error (exit 2). A
  folder named `mcp` is scanned with `pqc-scan ./mcp` or
  `pqc-scan -- mcp`; run from a terminal, `pqc-scan mcp` says on
  standard error that it is waiting for a host and how to scan such a
  folder. The Action now passes its `path` last, after `--`, so no path
  is read as the command or as an option.
- **The registry.** `mcpName` in package.json
  (`io.github.microtoll/pqc-scan`) and `server.json` beside it, in the
  shape of the engine's accepted listing, with the package argument
  `mcp` so a host starts `npx -y @microtoll/pqc-scan mcp`. The listing
  is published after the npm release, since the registry checks the
  published package's `mcpName`.

**Tests** (`test/mcp.test.mjs`). The server over a real child process,
fed what a host sends: the handshake (protocol version, package version,
the notice); one tool, needing `directory`; the result valid against the
schema and equal to a scan through the library apart from `scannedAt`;
a relative folder, `exclude` and `testFiles` reaching the scan; six
failures as tool results; an unknown tool, an unknown method and a line
that is not JSON as protocol errors, with the session carrying on;
nothing written to disk and nothing but the protocol on standard output;
`mcp` with arguments refused, and a folder named `mcp` scanned both
ways; `server.json` in step with package.json.

**Acceptance.** Checked by hand with the MCP Inspector's command line
(`npx @modelcontextprotocol/inspector --cli node bin/pqc-scan.mjs mcp`):
it lists the tool and gets the report back. `server.json` validated
against the registry's schema of 2025-12-11. Still to do after the npm
release: the registry listing, and a first call from a coding agent in
Claude Code (`claude mcp add pqc-scan -- npx -y @microtoll/pqc-scan mcp`).
