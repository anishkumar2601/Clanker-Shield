"""Machine-readable and human-readable scan reports.

Reports are projections of the current in-memory repository state. They do
not manufacture test, runtime, or verification results; unavailable stages
are emitted exactly as recorded by the verification pipeline.
"""
from __future__ import annotations

import csv
import html
import io
import json


def _findings(repo) -> list[dict]:
    return [finding.to_dict() for finding in repo.findings.values()]


def report_dict(repo) -> dict:
    return {
        "schema_version": "1.0",
        "product": "ClankerShield",
        "repository": {
            "id": repo.id,
            "name": repo.name,
            "source_type": repo.source_type,
            "created_at": repo.created_at,
            "scan_count": repo.scan_count,
            "last_scanned_at": repo.last_scanned_at,
        },
        "metrics": repo.summary_dict()["metrics"],
        "coverage": repo.coverage,
        "inventory": repo.inventory,
        "pipeline": repo.pipeline,
        "findings": _findings(repo),
        "attack_paths": repo.graph,
        "verification": repo.verification_history,
        "scan_history": repo.scan_history,
    }


def to_json(repo) -> str:
    return json.dumps(report_dict(repo), indent=2, ensure_ascii=False)


def to_csv(repo) -> str:
    fields = ["id", "type", "title", "severity", "risk_score", "risk_band", "confidence",
              "lifecycle_status", "verification_status", "file", "line", "cwe", "sources", "remediation"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in _findings(repo):
        row = dict(finding)
        row["sources"] = ";".join(row.get("sources") or [])
        writer.writerow(row)
    return output.getvalue()


def to_markdown(repo) -> str:
    data = report_dict(repo)
    metrics = data["metrics"]
    lines = [
        f"# ClankerShield report: {repo.name}",
        "",
        f"- Scan count: {repo.scan_count}",
        f"- Last scanned: {repo.last_scanned_at or 'not scanned'}",
        f"- Security risk score: {metrics.get('security_risk_score', 'N/A')}",
        f"- Active findings: {metrics.get('active_vulnerabilities', 0)}",
        f"- Files analyzed: {data['coverage'].get('files_analyzed', 0)} / {data['coverage'].get('files_discovered', 0)}",
        "",
        "## Findings",
        "",
    ]
    if not data["findings"]:
        lines.append("No findings were recorded.")
    else:
        for finding in sorted(data["findings"], key=lambda item: (-item.get("risk_score", 0), item.get("file", ""))):
            lines.extend([
                f"### {finding['title']}",
                f"- ID: `{finding['id']}`",
                f"- Location: `{finding['file']}:{finding['line']}`",
                f"- Severity/risk: **{finding['severity']}** / {finding['risk_score']} ({finding['risk_band']})",
                f"- Lifecycle: `{finding['lifecycle_status']}`; verification: `{finding['verification_status']}`",
                f"- Sources: {', '.join(finding.get('sources') or [])}",
                f"- Remediation: {finding['remediation']}",
                "",
            ])
    lines.extend(["## Verification", "", "```json", json.dumps(data["verification"], indent=2), "```", ""])
    return "\n".join(lines)


def to_html(repo) -> str:
    data = report_dict(repo)
    rows = []
    for finding in sorted(data["findings"], key=lambda item: -item.get("risk_score", 0)):
        rows.append(
            "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
                finding["severity"], finding["risk_score"], finding["title"],
                f"{finding['file']}:{finding['line']}", finding["lifecycle_status"],
                finding["verification_status"], finding["remediation"])) + "</tr>"
        )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ClankerShield report</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem;color:#18211d}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #d5ded9;padding:.55rem;text-align:left;vertical-align:top}th{background:#edf5f0}</style>
</head><body><h1>ClankerShield report</h1>
<p><strong>Repository:</strong> %s<br><strong>Risk score:</strong> %s<br><strong>Scan count:</strong> %s</p>
<table><thead><tr><th>Severity</th><th>Risk</th><th>Finding</th><th>Location</th><th>Lifecycle</th><th>Verification</th><th>Remediation</th></tr></thead>
<tbody>%s</tbody></table></body></html>""" % (html.escape(repo.name), data["metrics"].get("security_risk_score", "N/A"), repo.scan_count, "".join(rows))


def to_sarif(repo) -> str:
    findings = _findings(repo)
    rules = {}
    results = []
    for finding in findings:
        rule_id = (finding.get("rule_ids") or [finding["type"]])[0]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding["title"],
            "shortDescription": {"text": finding["title"]},
            "help": {"text": finding["remediation"]},
            "properties": {"cwe": finding.get("cwe"), "confidence": finding.get("confidence")},
        })
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(finding["severity"], "warning")
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": finding["explanation"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["file"]}, "region": {"startLine": finding["line"], "endLine": finding.get("end_line", finding["line"])}}}],
            "partialFingerprints": {"clankershieldFindingId": finding["id"]},
            "properties": {"severity": finding["severity"], "riskScore": finding["risk_score"], "lifecycleStatus": finding["lifecycle_status"], "verificationStatus": finding["verification_status"], "sources": finding.get("sources", [])},
        }
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ClankerShield", "version": "1.0.0", "rules": list(rules.values())}}, "results": results, "properties": {"scan": {"id": repo.id, "lastScannedAt": repo.last_scanned_at}, "verification": repo.verification_history}}],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
