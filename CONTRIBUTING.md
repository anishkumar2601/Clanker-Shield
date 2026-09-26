# Contributing

Keep changes incremental and evidence-backed. New scanner rules must include a
vulnerable fixture and a safe or false-positive fixture. Never execute fixture
repositories on the host. New API fields must distinguish unavailable,
failed, skipped, and successful work. Findings must retain file/line evidence,
scanner provenance, and honest confidence.

Before submitting changes, run backend tests, the frontend build, and the CLI
on a small fixture where the local toolchain is available. Do not commit
secrets, generated archives, dependency directories, temporary workspaces, or
provider credentials.
