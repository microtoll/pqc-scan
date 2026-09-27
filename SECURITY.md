# Security policy

`pqc-scan` is part of the Microtoll project and follows the Microtoll
Engine's security policy:
<https://github.com/microtoll/engine/blob/main/SECURITY.md>

Write to the address that policy gives. Never open a public issue for a
security problem.

## What counts as a security problem here

- The scanner executing, importing or evaluating anything it scans.
- The scanner reading outside the directory it was given (following a
  symbolic link out of it, for instance), or writing anywhere but the report
  paths it was given.
- Any network access, telemetry or environment reading by the scanner.
- The GitHub Action (`action.yml`) running untrusted input as shell code.

A missed algorithm or a false positive is a bug, not a security problem:
please open an ordinary issue with a minimal code sample, once the
repository is public.
