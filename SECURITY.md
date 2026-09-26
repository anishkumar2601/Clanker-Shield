# Security model

## Safety guarantees

- ZIP paths are checked for traversal, absolute paths, Windows drive paths,
  symlinks, duplicate paths, member count, compressed size, and extracted size.
- Members are copied in bounded chunks. Nested archives are retained as files;
  they are never recursively unpacked.
- Source files are read as text with bounded size and replacement decoding.
- No repository command is run by the web scan path or CLI.
- Secrets are masked in findings and redacted before optional AI requests.
- Patches require a confined path, original hash, temporary validation, backup,
  atomic replacement, and can be rolled back with a new-hash check.
- CORS is allow-list based and optional scanners have explicit timeout/failure
  states.
- Optional auth uses scrypt password hashes, signed HttpOnly session cookies,
  generic password-recovery responses, and server-side repository ownership
  checks. Frontend hiding is not the authorization boundary.

## Important boundary

The default development mode is single-process and auth-disabled so the demo
flow remains backwards-compatible. Protected deployments must enable
`CLANKER_AUTH_REQUIRED`. Durable database persistence, full RBAC, sandboxed
builds/runtimes, and durable job isolation are not implemented in this
distribution. Deploy it as a trusted single-user development tool until those
controls are added.
