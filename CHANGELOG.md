# Changelog — @microtoll/pqc-scan

All notable changes are listed here. Until 1.0, the command line and the
library API may change in any minor release, and every such change is
listed. The report's JSON schema is versioned separately (`schema` in the
report); a change to its meaning always raises that version.

## 0.3.0 — 2026-09-29

- **`pqc_scan` returns a summary by default** (DESIGN.md §8.15). On the
  first real use from Claude Code, on a 366-file application, the whole
  report was 274,218 characters, ten times Claude Code's limit on a tool
  result; Claude Code saved it to a file and showed the agent an error
  first. The summary is 12,684 characters on the same application: the
  report's counts; each use to review (a priority, a name that could not be
  read, or a note) grouped by algorithm and what to do about it, with its
  files and lines, at most 20 places a group and 400 in all, the most
  urgent first; every other use counted by algorithm; the dependencies and
  TLS configurations without source lines. The new argument `detail: "full"`
  returns the whole JSON report as 0.2.0 did. The report and its schema
  (version 1) are unchanged.
- The README and DESIGN.md add `--scope user` to `claude mcp add`: without
  it Claude Code registers the server for one folder only.

## 0.2.0 — 2026-09-29

The CycloneDX cryptographic bill of materials (DESIGN.md §8.14): the first
item of the evidence pack decided on 2026-09-29.

- `--cbom <file>` writes a CycloneDX 1.6 bill of materials from the same
  scan: one `cryptographic-asset` component per algorithm variant, with an
  occurrence (file, line, call) for every use; the interfaces and the
  catalogued libraries as components that `provide` those assets; each TLS
  configuration as a `protocol` asset referencing its key-exchange groups.
  The scanner's own vocabulary (class, kind, priority, parameters, notes)
  travels in properties named `microtoll:pqc-scan:*`. The library API gains
  `toCbom(report)` and `buildCbom(report)`. The JSON report and its schema
  (version 1) are unchanged; the bill of materials is written only when
  asked for.
- The Action writes it as well (input `cbom`, default `pqc-scan.cbom.json`,
  uploaded with the reports; output `cbom`).
- Tests: every fixture's bill of materials is checked against the CycloneDX
  1.6 JSON schema (a copy at `test/schemas/`, Apache-2.0) by a second small
  checker, `test/cyclonedx-check.mjs`; the mapping of a known set of
  algorithms; one occurrence per finding and every reference resolving; the
  same output on every machine.
- A serial number, worked out from the rest of the bill of materials and
  its timestamp (an RFC 9562 version 8 UUID from SHA-256): CycloneDX
  recommends one and IBM's CBOMkit viewer refuses a file without it.
- Checked by hand in IBM's CBOMkit viewer on 2026-09-29: the engine's
  bill of materials opens, all 76 uses of its 21 assets are read, and the
  viewer's own post-quantum policy check finds the same classical
  algorithms the report does (DESIGN.md §8.14, acceptance).

The scanner as a tool for coding agents (DESIGN.md §8.15): the second item
of the evidence pack.

- `pqc-scan mcp` runs a Model Context Protocol server on standard input and
  output with one tool, `pqc_scan({ directory, exclude?, testFiles? })`,
  which returns the JSON report (schema version 1, without indentation).
  It reads files only and writes nothing. The protocol subset is copied
  from `@microtoll/mcp` 0.1.2 (`src/mcp-protocol.js`), so the scanner keeps
  zero dependencies. The library API gains `createMcpServer`, `mcpTools`,
  `MCP_INSTRUCTIONS` and `MCP_PROTOCOL_VERSION`.
- **A change to the command line:** `pqc-scan mcp` used to scan a folder
  named `mcp`; it now starts the server. Scan such a folder with
  `pqc-scan ./mcp` or `pqc-scan -- mcp`. `mcp` followed by anything else is
  a usage error (exit 2).
- The Action passes its `path` input last, after `--`, so a path named
  `mcp`, or one beginning with a dash, is always scanned as a folder.
- For the MCP registry: `mcpName` (`io.github.microtoll/pqc-scan`) in
  package.json and `server.json` beside it. Listed in the MCP registry on
  2026-09-29, after the npm release.
- Tests (`test/mcp.test.mjs`): the server over a real child process, fed
  what a host sends; the result checked against the schema and against a
  scan through the library; failures as tool results; protocol errors;
  nothing written to disk; the command's arguments; `server.json` in step
  with package.json.

## 0.1.1 — 2026-09-27

Metadata for the npm page and for provenance: `repository`, `homepage`, `bugs` and `keywords` in package.json (0.1.0 was published by hand without a repository link). `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` added. Nothing in `src/` changed. First version published through the release workflow with provenance.

## 0.1.0 — 2026-09-27

The first release: the publish gate opened on 2026-09-27 (the engine's
`DECISIONS.md`, D-01) and M6 was accepted the same day. Everything below
is in it.

### For a first run from a terminal (2026-09-27)
From the founder's first run on a Windows PC, where the whole report scrolled
past in a Command Prompt (DESIGN.md §8.13).
- Run from a terminal with no output named, the command line now writes
  `pqc-scan.md` and `pqc-scan.json` into the current folder and prints a
  four-line summary that says where they are and what to read first.
  `--write` asks for the same from a script. Piped with nothing named, the
  Markdown still goes to standard output and nothing is written, so existing
  scripts are unchanged.
- `--test-files <text>` (repeatable; the Action input `test-files`, one per
  line): a file whose path contains the text is test code, for projects whose
  tests are not named `test`, `spec` or `__tests__`.
- `pqc-scan.cmd` at the repository root, so on Windows
  `C:\Tools\pqc-scan\pqc-scan C:\Code\my-app` works without typing `node`
  or the `bin` path.
- The messages say "folder" rather than "directory".

### From the false-positive review of three public repositories (2026-09-27)
`panva/jose`, `excalidraw/excalidraw` and `requarks/wiki`, each a shallow
clone read once. Every reported finding was a genuine use; the seven faults
below were in the report and the catalogue around them (DESIGN.md §8.12).
- Dependency versions no longer print as `\1.0.6`: an ordered-list marker is
  escaped at its punctuation (`1\.0.6`), since a backslash before a digit is
  not a CommonMark escape (§8.10).
- A package the tree itself provides (the root `package.json`'s name, or a
  workspace package's) is no longer listed as a dependency of itself when
  its own tests import it or the lockfile links it. Fixture `self/`.
- `test-d` (tsd's type tests) is test code (§8.7).
- Library members that do no cryptography are read, not pointed at:
  `jsonwebtoken.decode`, `passport-jwt`'s `ExtractJwt`, `jose`'s
  `decodeJwt`, `decodeProtectedHeader`, `base64url` and `errors`,
  `jws.decode`, `fast-jwt`'s `createDecoder` (`plain` in the catalogue).
  Fixture `libraries/src/decode.js`.
- `cert`, `certificate` and `x509` are signing words (§8.4): a server's
  token-signing RSA key pair made under "Generate certificates" is Medium,
  not High. Fixture `node-crypto/certificates.js`.
- Catalogue: `passport-saml`, `@node-saml/passport-saml`,
  `@node-saml/node-saml`, `xml-crypto`, `xml-encryption` (SAML signatures and
  encrypted assertions), `node-2fa` (one-time codes), `jwks-rsa` and
  `openid-client`; 57 packages. Fixture `libraries/src/saml.js`.
- The SHA-1 and MD5 note says where they matter: wherever they protect
  something; as a plain identifier the risk is lower. Both applications used
  SHA-1 only for identifiers.

### From the acceptance run on a second, real application (2026-09-27)
- A WebAuthn key is a signing key: `webauthn`, `passkey`, `assertion` and
  `cose` are now signing words (§8.4), so a P-256 key read from a passkey's
  COSE key is Medium, not High. Fixture `node-crypto/webauthn.js`.
- A file is binary only if a NUL appears in its first 8,000 bytes (git's
  rule). A NUL anywhere skipped a real source file, unread, because a regular
  expression far down held a raw control character (§8.7).

### Scaffold (2026-09-27)
- Repository created under the Microtoll publish gate (`"private": true`,
  no remote). Apache-2.0. Node 20 or later; no runtime dependencies.
- `DESIGN.md`: the approved design (D-42 to D-45, each option (a)), with §8
  recording how the details it left open were settled.

### Tokenizer (2026-09-27)
- `src/tokenize.js`: JavaScript and TypeScript tokens — strings (escapes
  applied), template literals with nested `${…}` tokenized as code, regular
  expression literals by the previous-token rule, numbers with separators,
  line and block comments kept apart for the priority heuristic. Resilient:
  an unterminated string ends at its line, nothing throws.
- `.gitattributes`: LF everywhere, so fixtures and reports are identical on
  every machine.

### The scanner, the report, the command line and the Action (2026-09-27)
- `src/source.js`: calls, arguments, object fields, imports and constants
  read from the token stream; a `const` followed within its block, and one
  hop across a relative import (DESIGN.md §8.1).
- Detectors (`src/detect/`): Web Crypto, `node:crypto`, the library
  catalogue (49 packages, `src/catalogue.js`) with JSON Web Token algorithm
  literals, lockfiles (`package-lock.json` v1–v3, `yarn.lock` v1 and Berry,
  `pnpm-lock.yaml` v5–v9), named PBKDF2 iteration counts, and TLS in nginx,
  Apache, Caddy and Node. The priority heuristic of §8.4.
- `src/report.js`: the JSON report (schema version 1,
  `schema/pqc-scan.schema.json`) and the Markdown report in the eight
  sections of §4, which a scanned repository cannot write links or HTML
  into (§8.10).
- `bin/pqc-scan.mjs`: `pqc-scan [dir] [--json] [--md] [--fail-on high|medium]
  [--exclude]…`; exit codes 0, 1 and 2.
- `action.yml`: the composite GitHub Action (§8.11); `.github/workflows/ci.yml`
  tests on Node 20 and 24, on Linux and Windows, and runs the action on the
  fixtures.
- A JSON Web Algorithms literal in a file that imports several JWT
  libraries names them all instead of the first (§8.9).
- Tests: every detector on fixtures of real code shapes and traps; every
  fixture report checked against the published schema; the same report on
  every machine; the command line's outputs and exit codes. 47 tests, on
  Node 20 and 24.
- Acceptance (DESIGN.md §6, first item): run on the Microtoll Engine, it
  finds AES-256-GCM, HKDF-SHA-256, PBKDF2 at 310,000 iterations, SHA-256,
  Ed25519 (Medium), the P-256 ECDH seal (High), the hybrid
  `MLKEM768-X25519` (post-quantum), the server's `node:crypto` verify and
  hash, and the nginx sample as hybrid-enabled.
