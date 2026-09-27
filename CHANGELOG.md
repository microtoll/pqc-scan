# Changelog — @microtoll/pqc-scan

All notable changes are listed here. Until 1.0, the command line and the
library API may change in any minor release, and every such change is
listed. The report's JSON schema is versioned separately (`schema` in the
report); a change to its meaning always raises that version.

## Unreleased

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
