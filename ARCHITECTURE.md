# ClankerShield architecture

ClankerShield has a static-analysis-first architecture:

`safe ZIP ingestion -> inventory -> dependency/IaC/SAST/secret scanners -> correlation -> deterministic risk -> evidence graph -> optional AI explanation -> reviewed patch -> hash-protected apply -> rescan -> report`

Repository content is data. The ingestion and scanner path never imports,
builds, installs, or starts uploaded code. Python syntax checks use `compile`
only; they are not execution or runtime verification.

The web service currently keeps repository state in process memory. Copilot
conversations use a small repository-scoped JSON store. A production deployment
must replace these with a database, authenticated ownership, job workers, and a
dedicated sandbox before accepting mutually untrusted users.

Authentication is now a separate `auth_service.py` boundary. It uses scrypt
password hashes, signed HttpOnly-cookie sessions, generic recovery responses,
and owner checks when `CLANKER_AUTH_REQUIRED=true`. It is intentionally a
small local provider so existing single-user demo behavior remains compatible;
the route contract can later be backed by Supabase or a database identity
service without moving authentication into React.

The CLI (`python -m app.cli scan`) shares the inventory and scanner modules and
does not depend on the web UI. Reports are projections of observed scanner
evidence; unavailable stages remain unavailable.
