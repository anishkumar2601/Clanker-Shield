"""Security graph and attack-path construction.

Relationships inferred from co-location or vulnerability category are marked
``INFERRED``. Source-to-sink references produced by the Python AST analysis
are marked ``OBSERVED`` as scanner evidence, not proof of runtime execution.
"""
from __future__ import annotations

DB_ADJACENT_TYPES = {"sql_injection"}
CONFIG_ADJACENT_TYPES = {"hardcoded_secret", "insecure_configuration"}
FS_ADJACENT_TYPES = {"path_traversal", "command_injection"}
AUTH_ADJACENT_TYPES = {"weak_authentication"}


def build_attack_path(finding: dict, inventory: dict) -> list[dict]:
    routes_in_file = [r for r in inventory.get("api_routes", []) if r["file"] == finding["file"]]
    entry_label = (f"{routes_in_file[0]['method']} {routes_in_file[0]['path']}"
                   if routes_in_file else "Unauthenticated request reaches this file")

    path = [{
        "step": 1, "node": "Entry point",
        "description": entry_label,
        "file": finding["file"], "line": finding["line"],
        "evidence_status": "INFERRED" if routes_in_file else "POTENTIAL",
    }, {
        "step": 2, "node": "Vulnerable code",
        "description": finding["title"],
        "file": finding["file"], "line": finding["line"],
        "evidence_status": "OBSERVED",
    }]

    if finding["type"] in DB_ADJACENT_TYPES:
        path.append({"step": 3, "node": "Database", "description": "The finding category suggests database impact; the route-to-database edge is inferred.",
                      "file": finding["file"], "line": finding["line"], "evidence_status": "INFERRED"})
    elif finding["type"] in FS_ADJACENT_TYPES:
        path.append({"step": 3, "node": "Filesystem / OS", "description": "The finding category suggests filesystem or OS impact; the asset edge is inferred.",
                      "file": finding["file"], "line": finding["line"], "evidence_status": "INFERRED"})
    elif finding["type"] in CONFIG_ADJACENT_TYPES:
        path.append({"step": 3, "node": "Configuration exposure", "description": "The finding category suggests configuration exposure; the asset edge is inferred.",
                      "file": finding["file"], "line": finding["line"], "evidence_status": "INFERRED"})
    elif finding["type"] in AUTH_ADJACENT_TYPES:
        path.append({"step": 3, "node": "Authentication boundary", "description": "The finding category suggests an authentication impact; the boundary edge is inferred.",
                      "file": finding["file"], "line": finding["line"], "evidence_status": "INFERRED"})

    path.append({"step": len(path) + 1, "node": "Impact", "description": impact_label(finding),
                 "file": finding["file"], "line": finding["line"], "evidence_status": "POTENTIAL"})
    return path


def impact_label(finding: dict) -> str:
    return {
        "critical": "Full compromise of data or system integrity is plausible.",
        "high": "Significant unauthorized access or data exposure is plausible.",
        "medium": "Limited exposure that could assist a broader attack.",
        "low": "Minor hardening gap with limited standalone impact.",
    }.get(finding["severity"], "Impact depends on how this component is deployed.")


def build_security_graph(findings: list[dict], inventory: dict) -> dict:
    nodes = []
    edges = []
    seen_node_ids = set()

    def add_node(node_id: str, label: str, kind: str, **extra):
        if node_id in seen_node_ids:
            return
        seen_node_ids.add(node_id)
        nodes.append({"id": node_id, "label": label, "kind": kind, **extra})

    for route in inventory.get("api_routes", []):
        node_id = f"route::{route['method']}::{route['path']}"
        add_node(node_id, f"{route['method']} {route['path']}", "route", file=route["file"])

    if inventory.get("auth_files"):
        add_node("auth", "Authentication", "auth", files=inventory["auth_files"])
    if inventory.get("database_files") or inventory.get("datastores"):
        add_node("database", "Database", "database", datastores=inventory.get("datastores", []))
    if inventory.get("config_files") or inventory.get("env_files"):
        add_node("configuration", "Configuration", "configuration", files=inventory.get("config_files", []))
    add_node("external_impact", "External impact", "impact")

    for f in findings:
        node_id = f"finding::{f['id']}"
        add_node(node_id, f["title"], "finding", severity=f["severity"], file=f["file"], line=f["line"])

        matching_routes = [r for r in inventory.get("api_routes", []) if r["file"] == f["file"]]
        for route in matching_routes:
            route_node = f"route::{route['method']}::{route['path']}"
            edges.append({"from": route_node, "to": node_id, "label": "reaches", "evidence_status": "INFERRED", "file": f["file"], "line": f["line"], "reason": "Route and finding share a file; execution flow was not proven."})

        for evidence in f.get("evidence_refs", []) or []:
            if evidence.get("role") not in {"SOURCE", "SINK"}:
                continue
            evidence_id = f"evidence::{f['id']}::{evidence.get('role')}::{evidence.get('line')}"
            add_node(evidence_id, evidence.get("label", evidence.get("role", "Evidence")), "evidence", file=evidence.get("file"), line=evidence.get("line"), evidence_status="OBSERVED")
            edges.append({"from": evidence_id, "to": node_id, "label": evidence.get("role", "evidence").lower(), "evidence_status": "OBSERVED", "file": evidence.get("file"), "line": evidence.get("line"), "reason": "Reference emitted by the scanner."})

        if f["type"] in DB_ADJACENT_TYPES and "database" in seen_node_ids:
            edges.append({"from": node_id, "to": "database", "label": "queries", "evidence_status": "INFERRED", "file": f["file"], "line": f["line"], "reason": "Vulnerability category indicates database adjacency."})
        if f["type"] in CONFIG_ADJACENT_TYPES and "configuration" in seen_node_ids:
            edges.append({"from": "configuration", "to": node_id, "label": "contains", "evidence_status": "INFERRED", "file": f["file"], "line": f["line"], "reason": "Configuration file context indicates adjacency."})
        if f["type"] in AUTH_ADJACENT_TYPES and "auth" in seen_node_ids:
            edges.append({"from": "auth", "to": node_id, "label": "protects", "evidence_status": "INFERRED", "file": f["file"], "line": f["line"], "reason": "Authentication file context indicates adjacency."})
        if f["severity"] in ("critical", "high"):
            edges.append({"from": node_id, "to": "external_impact", "label": "potential impact", "evidence_status": "POTENTIAL", "file": f["file"], "line": f["line"], "reason": "Impact is an estimate, not an exploit demonstration."})

    return {"nodes": nodes, "edges": edges}
