# ClankerShield — build summary

## Important context

This deliverable starts from the modular ClankerShield source in the supplied
`ClankerShield.zip` and upgrades it in place. The supplied
`open-webui-main.zip` was inspected as an architectural reference only; its
product code was not merged into ClankerShield. The existing scanner, patch
workflow, verification routes, and premium dashboard remain the foundation.

## Files changed

The upgrade adds a copilot layer without replacing the existing security engine:

**Backend** (`backend/`) — FastAPI app, including the new persistent
conversation and safe-tool modules:
`models.py`, `zip_safety.py`, `demo_repo.py`, `inventory.py`,
`security_analysis.py`, `external_scanners.py`, `ai_analyst.py`,
`patches.py`, `graph.py`, `verification.py`, `main.py`, plus
`conversation_store.py`, `security_tools.py`, `requirements*.txt`,
`ast_analysis.py`, `dependency_advisories.py`, `iac_analysis.py`,
`reporting.py`, `cli.py`, `auth_service.py`,
`.env.example`, `run.py`, and six test files
(`tests/test_security_analysis.py`, `tests/test_api.py`,
`tests/test_conversations.py`, `tests/test_patch_safety.py`,
`tests/test_iac_and_cli.py`, `tests/test_auth.py`).

**Frontend** (`frontend/`) — React + Vite app: `api.js`, `App.jsx`,
`icons.jsx`, 17 components under `src/components/` (TopNav, Hero,
MetricCards, FeaturedAICard, FloatingThreatCard, LiveThreatActivity,
AIAnalysisPanel, ScanPipeline, ScanCoverage, FindingsQueue, PatchReview,
VerificationPanel, SecurityGraph, RepositoryInventory, SystemStatus,
AICommandBar, Landing, Dashboard, common), a toast hook, and three CSS
files implementing the design system (tokens, layout, components).
The upgrade adds `SecurityCopilot.jsx` and streaming/conversation API
helpers in `api.js`, plus `ReportDownloads.jsx` for real SARIF/JSON/CSV/
Markdown/HTML exports.

## Features implemented (all real, all wired to live data)

- **Demo repository scanning** — a 12-file intentionally-vulnerable demo
  service is materialized in an isolated temp workspace at scan time.
- **ZIP upload** — 25 MB / 100 MB / 5,000-file limits; rejects absolute
  paths, Windows drive paths, `..` traversal, and symlinks; verified
  members can never write outside the workspace. Extraction is chunked to
  avoid reading a declared member into memory at once; duplicate paths are
  rejected and nested archives are retained without recursive extraction.
- **Repository inventory** — languages, frameworks (FastAPI/Flask/
  Django/Express/Next.js/React), datastores, API routes, auth/config/env/
  sensitive files, entry points.
- **Static security scanning** — 8 rule categories: SQL injection
  (f-string / concatenation / format), command injection (`os.system`,
  `shell=True`), hardcoded secrets, unsafe HTML (`innerHTML`,
  `dangerouslySetInnerHTML`), path traversal, weak authentication
  (disabled signature verification, MD5 password hashing), insecure
  config (debug mode, wildcard CORS), outdated dependencies.
- **Python AST data-flow analysis** — conservative source-to-sink checks for
  request/input data reaching SQL, command, filesystem, deserialization, and
  dynamic-code sinks. Evidence is labelled potential data flow rather than a
  proven runtime exploit path.
- **Secret detection and redaction** — AWS keys, GitHub tokens, private
  key headers, DB connection strings, JWT-shaped tokens, Stripe keys,
  and generic credential assignments; only a masked fragment ever leaves
  the backend.
- **Optional Semgrep / Bandit integration** — real `subprocess` calls
  (`shell=False`, explicit args, timeout, stripped env); honestly reports
  `not_installed` / `failed` / `timeout` rather than pretending to run.
- **Optional OSV advisory lookup** — exact-version Python, npm, Go, and Cargo
  dependency queries when `CLANKER_OSV_ENABLED=true`; network failure is
  reported as unavailable. Offline age heuristics remain labelled outdated,
  never known-vulnerable.
- **Finding correlation** — overlapping findings at the same file/line/
  type are merged, combining sources and rule IDs.
- **Deterministic risk scoring** — explainable breakdown (severity,
  exploitability, exposure, data sensitivity, reachability, evidence
  strength, scanner confidence) → score → band.
- **CWE references** on every rule.
- **Attack-path analysis** and an **evidence-based security graph**
  (routes → findings → database/config/auth → impact), rendered as
  interactive inline SVG.
- **AI finding analysis** and **natural-language questions** — OpenAI-
  compatible provider with a fully-functional deterministic local
  fallback (verified working with zero API keys configured); every model
  response is schema- and evidence-validated before being trusted.
- **Persistent Security Copilot** — repository-scoped JSON conversation
  storage, streamed SSE responses, history, evidence-linked citations,
  read-only repository context tools, secret-redacted code search, tool
  traces, message editing, regeneration, local fallback, and graceful
  error events. The model receives selected context rather than the whole
  repository, and repository text is explicitly treated as untrusted data.
- **Safe patch generation** — structurally understood SQL, shell, secret, and
  debug rewrites only. Wildcard CORS and dependency-age upgrades refuse
  automatic patches because the trusted origin or compatible fixed version
  cannot be inferred safely.
- **Human patch review, atomic application, and rollback** — rejects stale
  hashes, validates temporary files, preserves file mode, atomically replaces
  the target, records new/backup hashes, and restores only when the applied
  file has not changed afterwards.
- **Security rescan and layered verification** — static scan, syntax status,
  existing tests, security regression tests, runtime verification, and new
  high-risk findings are reported separately. The strongest current result is
  `STATICALLY_VERIFIED`; runtime and regression execution remain unavailable.
- **Scan coverage and lifecycle controls** — real discovered/analyzed/skipped
  file counts, language/scanner availability, session scan history, and
  reason-required false-positive/accepted-risk suppression with reopen.
- **IaC and container analysis** — conservative evidence-backed checks for
  Dockerfiles, Compose, Kubernetes, Terraform/HCL, GitHub Actions, and GitLab
  workflow paths. Repository content is parsed as text; no build or workflow
  is executed.
- **Standalone CLI and reports** — `python -m app.cli scan` supports fail-on
  thresholds and JSON, valid SARIF 2.1.0, CSV, Markdown, and HTML output. The
  API exposes the same report projections.
- **Authentication boundary** — opt-in local signup, scrypt password hashing,
  email-verification and reset-token flows, signed HttpOnly sessions, logout,
  session lookup, protected repository routes, and server-side owner checks.
  The frontend includes login, signup, verification, recovery, reset, error,
  expired-session, loading, and account/logout states.
- **Cross-scan finding identity** — finding IDs are deterministic
  (hash of file + rule + snippet, not line number), so "neutralized"
  metrics and verification survive a rescan instead of resetting every
  time.
- **Responsive layout** — 980px/640px/520px breakpoints, mobile nav,
  reduced-motion support, visible focus states.
- Premium light dashboard matching the brief (white/off-white surfaces,
  rounded/layered cards, restrained red/amber/green/cyan/purple accent
  system, floating critical-threat card, featured AI card, live threat
  activity, AI command bar) plus an intentionally-dark landing page.

## Verification status for this upgrade

- Added backend tests covering conversation persistence and streaming,
  AST source-to-sink evidence, IaC checks, report/SARIF shape, CLI fail
  thresholds, atomic patch rollback, ZIP safety, and refusal of fabricated
  CORS/dependency patches.
- The current host has `py.exe` but no installed Python runtime, so the
  backend suite could not be executed in this session.
- The frontend source was updated. In this environment `npm install` was
  blocked by a Windows npm-cache permission/hanging install state and
  `npm run build` consequently failed because Vite was unavailable; this is
  recorded rather than called a passing build.
- The source package carried a prior baseline report of 36 backend tests and
  a passing Vite build; that baseline was not relabeled as a fresh run for
  this upgrade.

## Known limitations (honest, not hidden)

- **No frontend automated tests.** Manual/visual verification wasn't
  possible in this environment, and the frontend build was not completed
  because the host lacked a usable Vite installation.
- **In-memory storage, single process** — repositories, findings, and
  patches vanish on backend restart. Auth-enabled owner checks are real, but
  a durable multi-user database and migrations are not yet included.
- **Conversation persistence is JSON-file based** — it survives backend
  restarts but is not yet a multi-user database with authentication,
  concurrency controls, or retention policies.
- **OSV lookup is opt-in and network-dependent** — with the default offline
  setting, old-version findings remain triage-only. Exact advisory findings
  require `CLANKER_OSV_ENABLED=true` and reachable OSV service access.
- **Semgrep/Bandit are not installed in this build environment** — the
  integration code is real and tested for the "not installed" path, but
  the "findings actually parsed from real output" path is exercised by
  code review rather than a live run. Install `requirements-optional.txt`
  locally to exercise it.
- **Patch generator remains intentionally narrow** — unsupported shapes get
  remediation guidance but no automatic diff, by design. CORS and dependency
  upgrades are deliberately refused without trustworthy project context.
- **Scan history is session-scoped** — actual history is no longer synthetic,
  but repository and scan records still vanish when the backend restarts.
- **No PDF export, Git branch workflow, external email/OAuth, or production
  database** — these require a broader deployment architecture. Local auth,
  SARIF/CSV,
  JSON/Markdown/HTML reporting and a UI-independent CLI are implemented.
- **No sandboxed build/runtime verification** — runtime, dependency install,
  application startup, and exploit reproduction remain explicitly
  `NOT_AVAILABLE` / `NOT_RUN` until a container/VM boundary is deployed.
- **Python AST analysis is conservative and intra-file** — it does not yet
  prove interprocedural reachability, understand every sanitizer, or execute
  code to demonstrate exploitability.
- **Top nav is single-page anchor scrolling**, not separate routed
  pages — matches the product's current described behavior; separate
  pages were listed as future work in the blueprint.
- Runtime code execution is deliberately never implemented (Python
  files are only syntax-checked via `compile()`), matching the safety
  boundary described in the brief.
