# CI integration

The UI is not required for CI. From `backend/`:

```bash
python -m app.cli scan path/to/repository --format sarif --output clankershield.sarif --fail-on high
```

The command returns zero when the threshold is clear, one when an active
finding meets the threshold, and two for an invalid scan invocation. SARIF is
usable as a GitHub code-scanning artifact; JSON, CSV, Markdown, and HTML are
also available. A workflow still needs to install the pinned Python
requirements and upload the chosen artifact.

No CI status is fabricated by the dashboard. External workflow scanning is
static text analysis only.
