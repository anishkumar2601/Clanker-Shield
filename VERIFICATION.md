# Verification states

ClankerShield distinguishes:

- `DETECTED`: a scanner observed a pattern.
- `CONFIRMED`: a human or evidence review confirmed the finding lifecycle.
- `STATICALLY_VERIFIED`: the finding disappeared after a hash-protected patch,
  syntax validation passed, and the rescan did not introduce a critical/high
  finding.
- `TEST_VERIFIED`: reserved for an actual regression test result.
- `RUNTIME_VERIFIED`: reserved for evidence from a real isolated runtime.
- `NOT_VERIFIED`: the required evidence did not occur.
- `FIXED`: a later static scan no longer observes the prior finding.

The current verification endpoint performs syntax checks and static rescan. It
reports existing tests, security regression tests, and runtime verification as
`NOT_RUN` or `NOT_AVAILABLE`; it does not claim to execute repository code.
