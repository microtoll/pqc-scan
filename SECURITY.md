# Security policy

`pqc-scan` is part of the Microtoll project. Report a security problem by
email to **security@microtoll.dev**. Say what you found, how to reproduce it
and which version; you will get a reply within five working days, and the
fix will credit you unless you ask otherwise. There is no bounty. Never open
a public issue for a security problem.

## What counts as a security problem here

- The scanner executing, importing or evaluating anything it scans.
- The scanner reading outside the folder it was given (following a symbolic
  link out of it, for instance), or writing anywhere but the report paths
  it was given.
- Any network access, telemetry or environment reading by the scanner.
- The GitHub Action (`action.yml`) running untrusted input as shell code.

A missed algorithm or a false positive is a bug, not a security problem:
please open an ordinary issue with a minimal code sample.
