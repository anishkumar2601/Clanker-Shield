# API surface

Core endpoints:

- `GET /api/health`
- `POST /api/auth/signup`
- `POST /api/auth/verify-email`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/repositories/demo`
- `POST /api/repositories/upload`
- `GET /api/repositories/{id}`
- `POST /api/repositories/{id}/scan`
- `GET /api/repositories/{id}/inventory`
- `GET /api/repositories/{id}/graph`
- `GET /api/repositories/{id}/reports/{json|sarif|csv|markdown|html}`
- `GET /api/repositories/{id}/findings/{finding_id}`
- `POST /api/repositories/{id}/findings/{finding_id}/status`
- `POST /api/repositories/{id}/findings/{finding_id}/fix`
- `POST /api/repositories/{id}/patches/apply`
- `POST /api/repositories/{id}/patches/{patch_id}/rollback`
- `POST /api/repositories/{id}/verify`

Conversation endpoints are under
`/api/repositories/{id}/conversations`. Long-running scans are not yet moved
to a durable asynchronous job queue; the current MVP request performs the
static scan synchronously.

Set `CLANKER_AUTH_REQUIRED=true` to require the HttpOnly session cookie on all
repository endpoints. Ownership is checked server-side; unauthorized resources
return a generic 404. The local provider does not send email or implement
OAuth until an external provider is configured.
