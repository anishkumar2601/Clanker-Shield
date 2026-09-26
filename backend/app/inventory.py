"""
Repository inventory.

Walks a workspace directory once and builds a structural map of the project:
file/language breakdown, detected frameworks and datastores, API routes,
and files that matter for security context (auth, config, env, tests).

This inventory feeds risk scoring, the security graph, and AI context - it
never invents technologies that weren't actually detected in the files.
"""
from __future__ import annotations

import os
import re

IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".clankershield"}
MAX_FILE_BYTES_FOR_TEXT_SCAN = int(1.5 * 1024 * 1024)
SECURITY_ANALYZED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml", ".cfg", ".txt", ".tf", ".hcl"}
TEXT_EXTENSIONS = SECURITY_ANALYZED_EXTENSIONS | {".md", ".html", ".css", ".sql", ".go", ".rb", ".java", ".php", ".rs", ".cs", ".sh", ".env"}

LANGUAGE_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript (React)",
    ".ts": "TypeScript", ".tsx": "TypeScript (React)", ".json": "JSON",
    ".yml": "YAML", ".yaml": "YAML", ".md": "Markdown", ".html": "HTML",
    ".css": "CSS", ".sql": "SQL", ".go": "Go", ".rb": "Ruby", ".java": "Java",
    ".php": "PHP", ".rs": "Rust", ".cs": "C#", ".sh": "Shell",
}

FRAMEWORK_SIGNATURES = [
    ("FastAPI", re.compile(r"from\s+fastapi\s+import|import\s+fastapi")),
    ("Flask", re.compile(r"from\s+flask\s+import|Flask\(__name__\)")),
    ("Django", re.compile(r"from\s+django|DJANGO_SETTINGS_MODULE")),
    ("Express", re.compile(r"require\(['\"]express['\"]\)|from ['\"]express['\"]")),
    ("Next.js", re.compile(r"next\.config\.(js|mjs|ts)$")),
    ("React", re.compile(r"from ['\"]react['\"]|import React")),
]

DATASTORE_SIGNATURES = [
    ("SQLite", re.compile(r"sqlite3|\.sqlite3?\b")),
    ("PostgreSQL", re.compile(r"psycopg2|postgres(ql)?://")),
    ("MySQL", re.compile(r"pymysql|mysql\+|mysql://")),
    ("MongoDB", re.compile(r"pymongo|mongodb(\+srv)?://")),
    ("Redis", re.compile(r"\bredis\b")),
]

ROUTE_PATTERNS = [
    re.compile(r"@app\.(get|post|put|delete|patch|route)\(\s*['\"]([^'\"]+)"),
    re.compile(r"@router\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)"),
    re.compile(r"app\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)"),
    re.compile(r"router\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)"),
]

AUTH_HINTS = re.compile(r"auth|login|session|jwt|oauth", re.IGNORECASE)
SENSITIVE_FILE_HINTS = re.compile(r"\.env(\.|$)|secret|credential|\.pem$|\.key$", re.IGNORECASE)
CONFIG_HINTS = re.compile(r"config|settings", re.IGNORECASE)


def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude the Git object database, but retain .github workflows as
        # first-class security inputs.
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and d != ".git"]
        for name in filenames:
            yield os.path.join(dirpath, name)


def list_relative_files(root: str) -> list[str]:
    """Public helper shared by the scanners so every stage walks the same file set."""
    return [os.path.relpath(p, root) for p in _iter_files(root)]


def build_inventory(root: str) -> dict:
    files_meta = []
    language_counts: dict[str, int] = {}
    frameworks: set[str] = set()
    datastores: set[str] = set()
    api_routes: list[dict] = []
    auth_files: list[str] = []
    database_files: list[str] = []
    config_files: list[str] = []
    env_files: list[str] = []
    sensitive_files: list[str] = []
    test_dirs: set[str] = set()
    dependency_files: list[str] = []
    total_bytes = 0
    files_analyzed = 0
    binary_files: list[str] = []
    unsupported_files: list[str] = []
    oversized_files: list[str] = []
    languages_analyzed: dict[str, int] = {}

    for path in _iter_files(root):
        rel = os.path.relpath(path, root)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        total_bytes += size
        ext = os.path.splitext(path)[1].lower()
        language = LANGUAGE_BY_EXT.get(ext)
        base = os.path.basename(rel).lower()
        if base.startswith("dockerfile"):
            language = "Dockerfile"
        elif ext in {".tf", ".hcl"}:
            language = "Terraform/HCL"
        if language:
            language_counts[language] = language_counts.get(language, 0) + 1
        files_meta.append({"path": rel, "size": size, "language": language})

        base = os.path.basename(rel)
        if base in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml", "Pipfile", "Pipfile.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "composer.json", "composer.lock"):
            dependency_files.append(rel)
        if base.startswith(".env"):
            env_files.append(rel)
        if "test" in rel.lower().split(os.sep)[0:1] or rel.lower().startswith("tests/"):
            test_dirs.add(rel.split(os.sep)[0])
        if CONFIG_HINTS.search(base):
            config_files.append(rel)
        if AUTH_HINTS.search(rel):
            auth_files.append(rel)
        if SENSITIVE_FILE_HINTS.search(rel):
            sensitive_files.append(rel)

        if size > MAX_FILE_BYTES_FOR_TEXT_SCAN:
            oversized_files.append(rel)
            continue
        try:
            with open(path, "rb") as handle:
                raw = handle.read(4096)
        except OSError:
            unsupported_files.append(rel)
            continue
        if b"\x00" in raw:
            binary_files.append(rel)
            continue
        is_named_text_file = base.lower().startswith("dockerfile") or base.lower() in {"makefile", "jenkinsfile", ".gitlab-ci.yml"}
        if ext not in TEXT_EXTENSIONS and not is_named_text_file:
            unsupported_files.append(rel)
            continue

        files_analyzed += 1
        if language and ext in SECURITY_ANALYZED_EXTENSIONS:
            languages_analyzed[language] = languages_analyzed.get(language, 0) + 1
        if ext in (
            ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".cfg", ".toml", ".tf", ".hcl"
        ) or is_named_text_file:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            except OSError:
                continue

            for name, pattern in FRAMEWORK_SIGNATURES:
                if name == "Next.js":
                    if pattern.search(base):
                        frameworks.add(name)
                elif pattern.search(text):
                    frameworks.add(name)

            for name, pattern in DATASTORE_SIGNATURES:
                if pattern.search(text):
                    datastores.add(name)
                    database_files.append(rel) if rel not in database_files else None

            for pattern in ROUTE_PATTERNS:
                for match in pattern.finditer(text):
                    method = match.group(1).upper()
                    route_path = match.group(2)
                    api_routes.append({"method": method, "path": route_path, "file": rel})

    return {
        "total_files": len(files_meta),
        "files_discovered": len(files_meta),
        "files_analyzed": files_analyzed,
        "files_skipped": len(set(binary_files + unsupported_files + oversized_files)),
        "binary_files": binary_files,
        "unsupported_files": unsupported_files,
        "oversized_files": oversized_files,
        "total_bytes": total_bytes,
        "languages": language_counts,
        "languages_detected": sorted(language_counts),
        "languages_analyzed": languages_analyzed,
        "frameworks": sorted(frameworks),
        "datastores": sorted(datastores),
        "api_routes": api_routes,
        "auth_files": sorted(set(auth_files)),
        "database_files": sorted(set(database_files)),
        "config_files": sorted(set(config_files)),
        "env_files": sorted(set(env_files)),
        "sensitive_files": sorted(set(sensitive_files)),
        "test_directories": sorted(test_dirs),
        "dependency_files": sorted(set(dependency_files)),
        "entry_points": [f["path"] for f in files_meta if os.path.basename(f["path"]) in
                          ("main.py", "app.py", "index.js", "server.js", "manage.py", "run.py")],
    }
