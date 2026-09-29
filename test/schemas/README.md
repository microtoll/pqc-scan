# Schemas the tests check against

- `bom-1.6.schema.json` — the CycloneDX 1.6 JSON schema, copied unchanged
  from the CycloneDX specification repository at tag 1.6.1
  (`schema/bom-1.6.schema.json`, <https://github.com/CycloneDX/specification>),
  licensed Apache-2.0 by the OWASP Foundation. Used by `test/cbom.test.mjs`
  through `test/cyclonedx-check.mjs` to hold every bill of materials the
  scanner writes to the published schema. Not part of the published package.
