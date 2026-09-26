# ClankerShield

AI-powered repository security platform. Find threats, explain risk,
generate safe fixes, and prove remediation — on a real scan of a real
repository.

```
Demo repository or ZIP upload
  → safe extraction
  → repository inventory
  → static security scanning
  → secret detection
  → optional Semgrep / Bandit
  → finding correlation
  → deterministic risk scoring
  → attack-path mapping
  → AI explanation (model-backed or local fallback)
  → persistent evidence-linked Security Copilot conversations
  → streamed answers with read-only repository context tools
  → safe patch generation
  → human review
  → hash-protected patch application
  → rescan
  → verification
```

## Project structure

```
ClankerShield/
├── backend/            FastAPI application (see backend/app/)
│   ├── app/             scanner, AI analyst, conversation store, safe tools
│   ├── tests/
│   └── requirements*.txt
└── frontend/            React + Vite dashboard
    └── src/
```

## Running it

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python run.py
```

The API runs at `http://127.0.0.1:8000`. Check `http://127.0.0.1:8000/api/health`.

### Authentication

Authentication is available through the local provider and is opt-in for
backwards-compatible demo use. For a protected deployment, set
`CLANKER_AUTH_REQUIRED=true`, provide a long random `CLANKER_AUTH_SECRET`,
and use HTTPS with `CLANKER_SECURE_COOKIES=true`. The UI then exposes signup,
email verification, login, forgot-password, reset-password, session expiry,
and logout states. Email delivery and OAuth providers are not configured by
default; local development tokens are only returned when
`CLANKER_DEV_AUTH_TOKENS=true` (the supplied `.env.example` enables this for
local development only).

Optional external scanners (the product works fully without them — their
pipeline stages just honestly report "not installed"):

```bash
pip install -r requirements-optional.txt   # semgrep, bandit
```

Optional AI provider (the product works fully without this — it falls back
to deterministic local analysis grounded in the scan evidence):

```bash
cp .env.example .env
# fill in CLANKER_AI_API_KEY / CLANKER_AI_BASE_URL / CLANKER_AI_MODEL
```

Run the backend test suite:

```bash
cd backend
pytest tests/ -v
```

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Click **Launch demo scan** on the landing
page, or upload a repository ZIP.

To point the frontend at a different backend URL, set `VITE_API_BASE`
(defaults to `http://127.0.0.1:8000/api`).

### 3. CLI and reports

The scanner also works without the web UI and never executes the target
repository:

```bash
cd backend
python -m app.cli scan ../demo-repository --format sarif --output report.sarif --fail-on high
```

Supported report formats are `json`, `sarif`, `csv`, `markdown`, and `html`.
The API exposes the same formats at
`/api/repositories/{id}/reports/{format}`.

### Security Copilot

The dashboard includes a persistent repository-scoped copilot inspired by
useful architectural patterns in Open WebUI: conversation history, streamed
SSE responses, evidence-linked citations, message editing, regeneration, and
small read-only context tools. Open WebUI is used as a reference only; its
product code is not merged into ClankerShield.

Conversations are stored in `backend/.clankershield-data/conversations.json`
by default. Set `CLANKER_CONVERSATIONS_PATH` to move that file. Repository
content remains untrusted data: the copilot has no arbitrary shell tool,
paths are confined to the scanned repository, and code context is
secret-redacted before optional model calls.

The scan UI now distinguishes detected findings, suppressed findings, static
rescan results, syntax validation, and unavailable runtime verification. The
dashboard score is a deterministic **Security Risk Score**, not an AI claim.
Python scans include a conservative Abstract Syntax Tree (AST) source-to-sink
pass for common request/input flows. Relationships in the attack graph are
labelled `OBSERVED`, `INFERRED`, or `POTENTIAL` and expose their file/line
evidence.

## What's implemented

The current MVP wires demo scanning, ZIP upload (with traversal/size/symlink/duplicate-path protection and bounded extraction), 8
categories of built-in static rules, secret detection with redaction,
optional Semgrep/Bandit integration, optional OSV advisory lookup, a
conservative Python AST data-flow layer, finding correlation, a deterministic
explainable risk engine, CWE references, attack-path mapping, an
evidence-based security graph, Docker/Compose/Kubernetes/Terraform/CI text
checks, standalone CLI scanning with SARIF/JSON/CSV/Markdown/HTML reports, an AI analyst with a fully-functional local
fallback (no API key required), safe patch generation for a small set of
structurally understood rewrite patterns, hash-protected atomic patch application with backups and
rollback, rescanning, scan coverage, finding suppression, and layered
verification with a syntax check. See
`PROJECT_SUMMARY.md` for the full build report, test results, and known
limitations.

The upgraded dashboard also includes a persistent Security Copilot with
repository-scoped chat history, SSE streaming, evidence citations, read-only
retrieval tools, tool traces, message editing, regeneration, and a local
fallback when no AI provider is configured.

Automatic patching intentionally refuses wildcard Cross-Origin Resource
Sharing (CORS) and dependency-age upgrades because a trusted origin or
compatible fixed version cannot be inferred safely. Supported patches use
workspace-bound paths, original-file hash checks, temporary-file validation,
atomic replacement, preserved file mode, backup metadata, and rollback with a
post-apply hash check.

## Security notes

- Nothing here executes repository code. Python files are only
  `compile()`-checked for syntax during verification.
- Repository and scan state is still in-memory and single-process. Copilot
  conversations persist to a local JSON file, but there is no auth-enabled
  multi-user database yet. When `CLANKER_AUTH_REQUIRED=true`, repository
  access is authenticated and owner-scoped; durable database migrations and
  external email/OAuth providers remain deployment work.
- Build, dependency installation, application startup, exploit reproduction,
  and runtime verification are intentionally unavailable until a dedicated
  container/VM sandbox is configured. The product reports those states instead
  of pretending they ran.
- Secrets are redacted before they ever reach the frontend or an AI
  provider.
