# Development

Backend setup:

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python run.py
```

Frontend setup:

```bash
cd frontend
npm install
npm run dev
```

Run backend tests with `pytest tests/ -v`. The CLI can scan a directory without
the web UI:

```bash
cd backend
python -m app.cli scan ../demo-repository --format sarif --output report.sarif --fail-on high
```

Do not add `node_modules`, virtual environments, caches, extracted workspaces,
or generated reports to the source distribution.
