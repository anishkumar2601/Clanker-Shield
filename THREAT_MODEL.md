# Threat model

## Actors and assets

Threat actors include a malicious archive author, prompt-injection content in a
repository, a malicious dependency, an authenticated low-privilege user, and a
compromised optional AI provider. Assets include source code, credentials,
scan evidence, conversations, and patch history.

## Trust boundaries

1. Browser to API: CORS and request validation, but authentication is still a
   deployment responsibility.
2. Upload bytes to repository workspace: ZIP safety checks and temporary
   workspace confinement.
3. Repository data to scanners: scanners treat content as data and do not
   execute it.
4. Repository evidence to AI provider: compact context and secret redaction;
   provider responses are advisory and evidence references are validated.
5. Patch generation to workspace: path confinement, hash checks, atomic writes,
   backups, and rollback.

## Residual risks

The current service is single-process and unauthenticated. A real sandbox for
dependency installation, builds, tests, startup, and exploit reproduction is
not present. OSV is opt-in and network-dependent. These are explicit residual
risks, not simulated capabilities.
