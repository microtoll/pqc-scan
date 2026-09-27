# Changelog — @microtoll/pqc-scan

All notable changes are listed here. Until 1.0, the command line and the
library API may change in any minor release, and every such change is
listed. The report's JSON schema is versioned separately (`schema` in the
report); a change to its meaning always raises that version.

## Unreleased

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
