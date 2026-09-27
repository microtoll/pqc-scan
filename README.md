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

## Install

`pqc-scan` is a command-line tool. You need two things on your computer:

1. **Node.js 20 or later.** Check with `node --version` in a terminal
   (Command Prompt, PowerShell or Windows Terminal on Windows; Terminal on
   macOS or Linux). If the command is not found, or prints a version below
   20, install the current "LTS" release from <https://nodejs.org>. On
   Windows the installer is a normal `.msi`; accept the defaults, then open a
   **new** terminal window so it picks up the change.
2. **The scanner's code.** It is not yet on the npm registry (the publish
   gate is closed), so for now you take it from this repository in one of
   two ways:
   - **Download**: on the repository page, *Code → Download ZIP*, then unzip
     it somewhere convenient, for example `C:\Tools\pqc-scan` on Windows or
     `~/tools/pqc-scan` elsewhere.
   - **Clone**, if you have git:
     ```sh
     git clone https://github.com/microtoll/pqc-scan.git
     ```

There is nothing else to install: the scanner has no dependencies, so there
is no `npm install` step, and it needs no configuration, no account and no
network connection.

Once it is published, this becomes one line with no download at all:

```sh
npx @microtoll/pqc-scan path/to/your/app
```

or, to install it once and then call it as `pqc-scan` from anywhere:

```sh
npm install -g @microtoll/pqc-scan
```

## Run it

Point it at the folder that holds your application's code (the one with its
`package.json`). Until the package is published, call the script in the
scanner's `bin` folder by its path.

Always name a file for the report: a real application produces hundreds of
lines, far too many to read in a terminal.

On **Windows** (PowerShell or Command Prompt), with the scanner unzipped at
`C:\Tools\pqc-scan` and your app at `C:\Code\my-app`:

```powershell
node C:\Tools\pqc-scan\bin\pqc-scan.mjs C:\Code\my-app --md pqc-scan.md
```

On **macOS or Linux**:

```sh
node ~/tools/pqc-scan/bin/pqc-scan.mjs ~/code/my-app --md pqc-scan.md
```

Open `pqc-scan.md` in any editor or Markdown viewer (Visual Studio Code
shows it with *Ctrl+Shift+V*). Start with section 1, the summary, then
section 3, the priorities, where each High or Medium says which line of your
code it points at and why. Add `--json pqc-scan.json` as well to keep the
machine-readable version for other tools.

Without `--md` or `--json` the whole report is printed to the terminal,
which is fine for a small folder and unreadable for a large one.

A scan of a medium-sized application takes a few seconds. If you are in the
scanner's own folder, `.` means "this folder", and `--help` prints every
option:

```sh
node bin/pqc-scan.mjs --help
node bin/pqc-scan.mjs . --fail-on high      # exit 1 if anything is High (for CI)
```

Things that catch people out:

- **"node is not recognized"** on Windows: Node.js is not installed, or the
  terminal was opened before the installer ran. Install it, then open a new
  terminal.
- **A path with spaces** needs quotes: `"C:\My Projects\app"`.
- **Nothing found?** The scanner reads only JavaScript and TypeScript
  (`.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx`), lockfiles
  and TLS configuration files. Code in other languages is not seen (see
  "What it cannot see").
- **It never changes your files.** It reads them and writes only the report
  files you name.

The full set of options:

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
- **Libraries**: nearly sixty catalogued packages (`tweetnacl`, `libsodium`, the
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
  the same block, or one hop to a relative import (not an import by a
  workspace package's name), and nothing else. A function parameter that
  shadows a module-level constant of the same name is the one known way this
  can mislead.
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
