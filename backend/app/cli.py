"""Command-line scan entry point.

Usage from backend/: ``python -m app.cli scan ../repo --format sarif``.
The CLI is independent of the web UI and only performs static analysis. It
does not install dependencies, import the target project, or execute it.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import external_scanners, graph, iac_analysis, inventory, reporting, security_analysis
from .models import Repository, compute_metrics, new_id, now_iso


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _read_dependency_findings(root: str, inv: dict) -> list:
    findings = []
    for rel in inv.get("dependency_files", []):
        path = os.path.join(root, rel)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                findings.extend(security_analysis.scan_dependency_file(rel, handle.read()))
        except OSError:
            continue
    return findings


def scan_directory(root: str) -> Repository:
    root = os.path.realpath(root)
    if not os.path.isdir(root):
        raise ValueError(f"Scan target is not a directory: {root}")
    repo = Repository(id=new_id("cli_scan"), name=os.path.basename(root) or root, source_type="directory", workspace_path=root)
    inv = inventory.build_inventory(root)
    files = inventory.list_relative_files(root)
    raw = _read_dependency_findings(root, inv)
    raw.extend(security_analysis.run_builtin_scanner(root, files))
    raw.extend(iac_analysis.scan_iac_files(root, files))
    raw.extend(security_analysis.run_secret_scanner(root, files))
    semgrep = external_scanners.run_semgrep(root)
    bandit = external_scanners.run_bandit(root)
    raw.extend(semgrep.get("findings", []))
    raw.extend(bandit.get("findings", []))
    findings = security_analysis.correlate_findings(raw)
    for finding in findings:
        security_analysis.score_finding(finding, inv)
    repo.inventory = inv
    repo.files_analyzed = inv.get("files_analyzed", 0)
    repo.frameworks = inv.get("frameworks", [])
    repo.findings = {finding.id: finding for finding in findings}
    repo.graph = graph.build_security_graph([finding.to_dict() for finding in findings], inv)
    repo.scan_count = 1
    repo.last_scanned_at = now_iso()
    repo.coverage = {
        "files_discovered": inv.get("files_discovered", 0),
        "files_analyzed": inv.get("files_analyzed", 0),
        "files_skipped": inv.get("files_skipped", 0),
        "languages_detected": inv.get("languages_detected", []),
        "languages_analyzed": sorted(inv.get("languages_analyzed", {})),
        "runtime_verification": "NOT_AVAILABLE",
        "scanners": [
            {"name": "Built-in static analysis", "status": "completed", "detail": "Transparent local rules."},
            {"name": "IaC and container analysis", "status": "completed", "detail": "Conservative text rules."},
            {"name": "Semgrep", "status": semgrep.get("status", "failed"), "detail": semgrep.get("detail", "")},
            {"name": "Bandit", "status": bandit.get("status", "failed"), "detail": bandit.get("detail", "")},
            {"name": "Runtime verification", "status": "not_available", "detail": "The CLI never executes repository code."},
        ],
    }
    repo.scan_history = [{"scan_id": repo.id, "scan_number": 1, "timestamp": repo.last_scanned_at,
                          "findings": compute_metrics(findings), "risk_score": compute_metrics(findings).get("security_risk_score"),
                          "coverage": repo.coverage}]
    return repo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clankershield", description="Evidence-based static security scan")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a repository directory without executing it")
    scan.add_argument("path")
    scan.add_argument("--format", choices=("json", "sarif", "csv", "markdown", "html"), default="json")
    scan.add_argument("--output", help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="return exit code 1 at this severity")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    try:
        repo = scan_directory(args.path)
    except (OSError, ValueError) as exc:
        print(f"ClankerShield scan failed: {exc}", file=sys.stderr)
        return 2
    renderers = {"json": reporting.to_json, "sarif": reporting.to_sarif, "csv": reporting.to_csv,
                 "markdown": reporting.to_markdown, "html": reporting.to_html}
    output = renderers[args.format](repo)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as handle:
            handle.write(output)
    else:
        print(output)
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(f.severity, 0) >= threshold and not f.resolved for f in repo.findings.values()):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
