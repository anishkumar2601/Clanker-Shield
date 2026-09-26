"""Optional Open Source Vulnerabilities (OSV) advisory integration.

The built-in dependency check remains a clearly-labelled age heuristic for
offline scans. When CLANKER_OSV_ENABLED=true, this module queries OSV for
exact package versions and emits confirmed advisory findings. Network failure
is reported as unavailable; it never becomes a false vulnerability result.
"""
from __future__ import annotations

import json
import os
import re
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    import tomllib
except ImportError:  # Python 3.10 deployments can still use the other formats.
    tomllib = None

from .models import Finding, stable_finding_id

OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"


def _enabled() -> bool:
    return os.environ.get("CLANKER_OSV_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


def osv_enabled() -> bool:
    return _enabled()


def _severity(vulnerability: dict) -> tuple[str, float | None]:
    raw = str(vulnerability.get("database_specific", {}).get("severity", "")).upper()
    score = None
    for entry in vulnerability.get("severity", []) or []:
        try:
            score = float(str(entry.get("score", "")).split("/")[0])
        except (AttributeError, TypeError, ValueError):
            continue
    if score is not None:
        return ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low", score)
    return ({"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(raw, "medium"), score)


def _fixed_version(vulnerability: dict) -> str | None:
    versions = []
    for affected in vulnerability.get("affected", []) or []:
        for item in affected.get("ranges", []) or []:
            for event in item.get("events", []) or []:
                if event.get("fixed"):
                    versions.append(event["fixed"])
    return sorted(versions)[0] if versions else None


def _parse_dependencies(root: str, files: list[str]) -> list[dict]:
    dependencies = []
    for rel in files:
        full = os.path.join(root, rel)
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError:
            continue
        base = os.path.basename(rel)
        if base in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
            for line_number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)", line)
                if match:
                    dependencies.append({"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI", "file": rel, "line": line_number})
        elif base == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, spec in (data.get(section, {}) or {}).items():
                    match = re.search(r"(\d+(?:\.\d+){1,2}(?:[-+][0-9A-Za-z.-]+)?)", str(spec))
                    if match:
                        dependencies.append({"name": name, "version": match.group(1), "ecosystem": "npm", "file": rel, "line": 1})
        elif base == "package-lock.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            packages = data.get("packages", {}) or {}
            for package_path, package in packages.items():
                if not package_path or not isinstance(package, dict) or not package.get("version"):
                    continue
                name = package_path.split("node_modules/")[-1]
                dependencies.append({"name": name, "version": package["version"], "ecosystem": "npm", "file": rel, "line": 1})
        elif base == "go.mod":
            for line_number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"\s*([\w./-]+)\s+(v\d[^\s]+)", line)
                if match:
                    dependencies.append({"name": match.group(1), "version": match.group(2).lstrip("v"), "ecosystem": "Go", "file": rel, "line": line_number})
        elif base == "Cargo.toml":
            if tomllib is None:
                continue
            try:
                data = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, ValueError):
                continue
            for section in ("dependencies", "dev-dependencies"):
                for name, spec in (data.get(section, {}) or {}).items():
                    version = spec if isinstance(spec, str) else (spec or {}).get("version")
                    if version:
                        match = re.search(r"\d+(?:\.\d+){1,2}", str(version))
                        if match:
                            dependencies.append({"name": name, "version": match.group(0), "ecosystem": "crates.io", "file": rel, "line": 1})
    return dependencies


def scan_osv(root: str, files: list[str]) -> dict:
    dependencies = _parse_dependencies(root, files)
    if not _enabled():
        return {"status": "not_enabled", "findings": [], "detail": "OSV advisory lookup is disabled; no network request was made.", "dependency_count": len(dependencies)}
    if not dependencies:
        return {"status": "completed", "findings": [], "detail": "No exact dependency versions were found for OSV lookup.", "dependency_count": 0}

    queries = [{"package": {"name": item["name"], "ecosystem": item["ecosystem"]}, "version": item["version"]} for item in dependencies]
    try:
        payload = json.dumps({"queries": queries}).encode("utf-8")
        request = Request(OSV_ENDPOINT, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=6) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "findings": [], "detail": f"OSV advisory lookup unavailable: {type(exc).__name__}.", "dependency_count": len(dependencies)}

    findings = []
    for item, response in zip(dependencies, result.get("results", []) or []):
        for vulnerability in response.get("vulns", []) or []:
            severity, cvss = _severity(vulnerability)
            advisory_id = vulnerability.get("id", "OSV-unknown")
            aliases = vulnerability.get("aliases", []) or []
            fixed = _fixed_version(vulnerability)
            summary = vulnerability.get("summary") or vulnerability.get("details") or "OSV reported a vulnerability for this exact dependency version."
            findings.append(Finding(
                id=stable_finding_id(item["file"], "dependency_vulnerability", advisory_id, f"{item['name']}=={item['version']}"),
                type="dependency_vulnerability", title=f"Known vulnerability: {item['name']} {item['version']}",
                severity=severity, cwe="N/A", file=item["file"], line=item["line"], end_line=item["line"],
                snippet=f"{item['name']}=={item['version']}", explanation=summary[:1200],
                impact="This exact dependency version is linked to a published advisory. Review the affected range and application exposure before upgrading.",
                remediation=f"Upgrade {item['name']} to {fixed} or later if compatible." if fixed else f"Review the OSV advisory and upgrade {item['name']} to a supported fixed release.",
                sources=["osv"], rule_ids=[advisory_id], confidence=0.97, classification="dependency_vulnerability",
                advisory_ids=[advisory_id, *aliases], advisory_urls=[f"https://osv.dev/vulnerability/{advisory_id}"], cvss=cvss,
            ))
    return {"status": "completed", "findings": findings, "detail": f"OSV checked {len(dependencies)} exact dependency version(s); {len(findings)} advisory finding(s).", "dependency_count": len(dependencies)}
