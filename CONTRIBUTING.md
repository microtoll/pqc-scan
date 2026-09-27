# Contributing

pqc-scan is small on purpose: a tokenizer, a catalogue and a report, with
no dependencies, so that it can be read in an afternoon and trusted to run
inside other people's continuous integration. The rules keep it that way.

## What is welcome

- **A false positive or a missed algorithm**, as an issue with a minimal
  code sample. Every one found so far became a fixture under
  `test/fixtures/` and a line in a test; a pull request that adds the
  fixture and the fix together is ideal.
- **A library for the catalogue** (`src/catalogue.js`): the package name,
  what it provides, whether it offers post-quantum algorithms, and the calls
  that map to algorithms, with a fixture showing real use.
- **Wording**: the report is read by people who are not specialists. Plainer
  is better.

## The rules

1. **Zero runtime dependencies**, and the scanner reads files only: it
   never runs, imports or evaluates what it scans, never reads the
   environment, never touches the network. A change that does any of these
   is not a pull request but a design question.
2. **Never guess.** An algorithm the scanner cannot read statically is
   reported as "check by hand". A heuristic that turns a guess into a
   finding is the one kind of change the design refuses (`DESIGN.md` §3).
3. **Tests with `node:test`**, no framework; `npm test` must pass on Node
   20 and 24, on Linux and Windows (CI runs both).
4. **Settled details go in `DESIGN.md` §8**, one paragraph each, so that an
   auditor can check the code against them.

## Sign-off

Contributions are accepted under the Apache-2.0 licence with a Developer
Certificate of Origin: add `Signed-off-by: Your Name <you@example.com>` to
each commit (`git commit -s`). There is no contributor licence agreement.

Security problems go by `SECURITY.md`, never to a public issue.
