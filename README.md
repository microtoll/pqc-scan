# pqc-scan

An inventory of the cryptography a JavaScript or TypeScript codebase uses,
and which of it a large quantum computer would break.

**An inventory and pointers, not a compliance certificate.**

`pqc-scan` reads your source files, your `package.json` and lockfile, and
any TLS (Transport Layer Security) configuration written down in the tree.
It writes a report of every cryptographic algorithm it finds: through which
interface (Web Crypto, `node:crypto`, a library), with what key size where
the code says, where in the code, and a migration priority for each use a
quantum computer would break. The report follows the discovery exercise the
UK National Cyber Security Centre (NCSC) asks for in its post-quantum
migration timeline: discovery and a plan by 2028, the highest-priority
migrations by 2031, the rest by 2035.

It only reads. It runs nothing it scans, reads no environment variables,
sends nothing anywhere, and has no telemetry. Zero dependencies; Node 20 or
later. Free, and the command line stays free: a hosted report (trends over
time, an organisation-wide view) may exist later, and would read the same
JSON file; nothing of it is built.

## Run it

Not yet published. Until it is, run it from a checkout of this repository:

```sh
node bin/pqc-scan.mjs path/to/your/app                 # the Markdown report on standard output
node bin/pqc-scan.mjs path/to/your/app --json pqc-scan.json --md pqc-scan.md
node bin/pqc-scan.mjs . --fail-on high                 # exit 1 if anything is High
```

| Option | Meaning |
| --- | --- |
| `dir` | The directory to scan (default: the current one). |
| `--json <file>` | Write the machine-readable report (schema version 1). |
| `--md <file>` | Write the human report. |
| `--fail-on high` | Exit 1 if anything is High. |
| `--fail-on medium` | Exit 1 if anything is High or Medium. |
| `--exclude <name>` | Skip a directory or file name, or a path from `dir`. Repeatable. `node_modules` and `.git` are never read. |

With neither `--json` nor `--md`, the Markdown goes to standard output and
nothing is written to disk. Exit codes: **0** done, **1** the `--fail-on`
threshold was met, **2** a usage or read error. The threshold counts
everything in the report, test code included; use `--exclude` to leave a
directory out.

## In GitHub Actions

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@<commit>
  - uses: microtoll/pqc-scan@<commit>   # pin a full commit SHA
    with:
      fail-on: high                      # optional; empty never fails
```

The action runs the scanner on the workspace, adds the Markdown report to
the job summary, uploads both reports as the `pqc-scan` artefact, and then,
if `fail-on` is set and met, fails the job. Its inputs: `path`, `fail-on`,
`exclude` (one name per line), `json`, `md`, `job-summary`, `upload`,
`artifact-name`. Its outputs: `high`, `medium`, `low`, `verdict`, `json`.
It needs Node 20 or later on the runner; GitHub's hosted runners have it.

## What it finds

- **Web Crypto**: `crypto.subtle` calls, with the algorithm read from the
  nearest literal, including the post-quantum and hybrid names
  (`ML-KEM-768`, `ML-DSA-65`, `X25519MLKEM768`, `MLKEM768-X25519`).
- **`node:crypto`**: hashes, HMACs, ciphers, key pairs, signatures, Diffie–
  Hellman, public-key encryption, PBKDF2, scrypt, HKDF and random numbers.
- **Libraries**: about fifty catalogued packages (`tweetnacl`, `libsodium`, the
  `@noble` family, `jose`, `jsonwebtoken`, `bcrypt`, `crypto-js`,
  `web-push`, `openpgp`, …), from `package.json`, `package-lock.json`,
  `yarn.lock` and `pnpm-lock.yaml`, with their calls where the catalogue
  maps them and JSON Web Token (JWT) algorithm names such as `RS256`.
- **TLS**: nginx, Apache, Caddy and Node's `tls` and `https` options;
  whether a hybrid post-quantum key-exchange group is enabled.

A value it cannot read (an algorithm name held in a variable) is reported as
**dynamic — check by hand**, never guessed.

## The priorities

Only public-key uses get a priority: a large quantum computer breaks RSA,
elliptic-curve and Diffie–Hellman cryptography, but only weakens symmetric
ciphers and hashes.

- **High**: a key agreement or public-key encryption that seals data.
  Someone can record the ciphertext now and open it later ("harvest now,
  decrypt later"). Consider a hybrid seal for new data.
- **Medium**: a signature. It can be forged only once such a computer
  exists, so the risk is to long-lived signatures. Plan; do not rush.
- **Low**: a key exchange for a session, including TLS without a hybrid
  group. The exposure is the session, not the archive.

The priority is a heuristic from the words near the call (`seal`, `encrypt`,
`store`… against `session`, `tls`, `handshake`…). A use with no telling
word is High until a person checks. Every entry says which word decided
it. A person should review each High.

## The report

- `pqc-scan.json`: the inventory, described by
  [`schema/pqc-scan.schema.json`](schema/pqc-scan.schema.json) (version 1).
  Paths are relative, with forward slashes; the scanned directory appears by
  name only; two scans of the same tree differ only in `scannedAt`.
- `pqc-scan.md`: a summary, the inventory, the priorities with a
  replacement to consider, notes on symmetric ciphers and hashes (AES-128,
  SHA-1, MD5, 3DES, ECB mode, weak PBKDF2 iteration counts), dependencies,
  TLS, next steps in the NCSC's three milestones, and what the scan cannot
  see.

## What it cannot see

- Anything that is not JavaScript, TypeScript, a lockfile or a TLS
  configuration file: other languages, binaries, the operating system, a
  cloud key service, anything behind a network call.
- Which files actually run. A library imported only by a file your service
  never loads is still reported.
- A framework's own cryptography, unless the framework is in the catalogue.
- Values that are not written down where it looks: it follows a `const` in
  the same block, or one hop to a relative import, and nothing else. A
  function parameter that shadows a module-level constant of the same name
  is the one known way this can mislead.
- **Evidence is copied as written.** A secret on the same line as a
  cryptographic call will appear in the report. Treat the report like the
  code it describes.

## Develop

```sh
npm test
```

`node:test`, no framework, no dependencies. Every false positive found
becomes a fixture under `test/fixtures/` and a line in a test. The design
and every settled detail are in [`DESIGN.md`](DESIGN.md); security reports
go by [`SECURITY.md`](SECURITY.md).

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
