# Scanner coverage

Built-in rules cover common SQL/command injection, unsafe HTML, path traversal,
weak authentication, insecure configuration, hardcoded secret shapes, and
dependency-age triage. Python also receives conservative AST source-to-sink
analysis for request/input values reaching SQL, subprocess, filesystem,
deserialization, or dynamic-code sinks.

The IaC scanner adds evidence-backed text checks for Dockerfiles, Compose,
Kubernetes manifests, Terraform/HCL, GitHub Actions, and GitLab workflow paths.
Semgrep and Bandit are optional integrations and report `not_installed`,
`timeout`, `failed`, or `completed` honestly. OSV lookup is opt-in via
`CLANKER_OSV_ENABLED=true` and reports network unavailability rather than
inventing advisories.

These are not complete language or framework analyzers. Findings retain scanner
provenance and confidence, and inferred graph edges are labelled.
