"""Deterministic IaC and container checks.

This module intentionally uses conservative, evidence-producing text rules.
It does not parse or execute Dockerfiles, Terraform, Kubernetes manifests, or
CI workflows. Heuristic findings say so explicitly and retain the exact file
and line that triggered them.
"""
from __future__ import annotations

import os
import re

from .models import Finding, stable_finding_id


def _finding(rel_path: str, line: int, rule: str, title: str, severity: str,
             cwe: str, snippet: str, explanation: str, impact: str,
             remediation: str, confidence: float = 0.82) -> Finding:
    return Finding(
        id=stable_finding_id(rel_path, "iac_misconfiguration", rule, snippet),
        type="iac_misconfiguration",
        title=title,
        severity=severity,
        cwe=cwe,
        file=rel_path,
        line=line,
        end_line=line,
        snippet=snippet.strip()[:240],
        explanation=explanation,
        impact=impact,
        remediation=remediation,
        sources=["iac-rules"],
        rule_ids=[rule],
        confidence=confidence,
        classification="misconfiguration",
        evidence_refs=[{"file": rel_path, "line": line, "role": "CONFIGURATION"}],
    )


def _line_hits(rel_path: str, lines: list[str], pattern: re.Pattern, rule: str,
               title: str, severity: str, cwe: str, explanation: str,
               impact: str, remediation: str, confidence: float = 0.82) -> list[Finding]:
    findings = []
    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            findings.append(_finding(rel_path, number, rule, title, severity, cwe, line,
                                     explanation, impact, remediation, confidence))
    return findings


def _is_dockerfile(path: str) -> bool:
    return os.path.basename(path).lower() in {"dockerfile", "dockerfile.dev", "dockerfile.prod"} or "dockerfile." in os.path.basename(path).lower()


def _is_workflow(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return normalized.startswith(".github/workflows/") or normalized.startswith(".gitlab/")


def scan_iac_files(root: str, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel_path in files:
        lower = rel_path.replace("\\", "/").lower()
        base = os.path.basename(lower)
        ext = os.path.splitext(base)[1]
        if not (_is_dockerfile(rel_path) or base in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
                or ext in {".tf", ".yaml", ".yml", ".json"} or _is_workflow(rel_path)):
            continue
        full = os.path.join(root, rel_path)
        try:
            if os.path.getsize(full) > 2 * 1024 * 1024:
                continue
            with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except OSError:
            continue

        if _is_dockerfile(rel_path):
            if not any(re.match(r"\s*USER\s+\S+", line, re.I) for line in lines):
                findings.append(_finding(rel_path, 1, "docker.no-non-root-user", "Docker image has no explicit non-root USER", "medium", "CWE-250", "FROM ...",
                    "The Dockerfile does not declare a runtime user. Docker commonly defaults to root unless the base image or entrypoint changes it.",
                    "A container compromise would begin with the image's default privileges, which may be root.",
                    "Add an explicit least-privilege USER after creating the required application directories.", 0.68))
            findings.extend(_line_hits(rel_path, lines, re.compile(r"--privileged\b|\bprivileged\s*[:=]\s*true", re.I),
                "docker.privileged", "Privileged container configuration", "high", "CWE-250",
                "The container is configured with privileged execution, which disables important isolation boundaries.",
                "A container escape or application compromise can gain access to host-level capabilities.",
                "Remove privileged execution and grant only the specific capability required by the workload."))
            findings.extend(_line_hits(rel_path, lines, re.compile(r"\bADD\s+https?://", re.I),
                "docker.remote-add", "Dockerfile downloads a remote ADD source", "medium", "CWE-829",
                "The Dockerfile adds content directly from a remote URL, reducing build reproducibility and reviewability.",
                "A changed remote artifact can introduce unreviewed code into every image build.",
                "Download and verify a pinned artifact in a controlled build step, or copy a reviewed local file."))

        if base in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            checks = [
                (r"^\s*privileged\s*:\s*true\b", "compose.privileged", "Privileged Compose service", "high", "CWE-250", "A Compose service requests privileged mode.", "The service can access host-level capabilities beyond normal container isolation.", "Remove privileged mode and use narrowly scoped capabilities."),
                (r"^\s*network_mode\s*:\s*host\b", "compose.host-network", "Compose service uses host networking", "high", "CWE-668", "The service shares the host network namespace.", "Network isolation is reduced and host services may become reachable from the container.", "Use a private Compose network and explicitly publish only required ports."),
                (r"^\s*pid\s*:\s*host\b", "compose.host-pid", "Compose service uses the host PID namespace", "high", "CWE-250", "The service can observe host process identifiers.", "Host process visibility increases the impact of a container compromise.", "Remove host PID mode unless there is a documented, reviewed requirement."),
                (r"(/|[A-Za-z]:[\\/])\s*:\s*/(host|var/run/docker.sock)\b", "compose.host-mount", "Compose service mounts a host-sensitive path", "high", "CWE-22", "A volume maps a host root or Docker socket into the service.", "The service may read or control host resources outside its intended workspace.", "Remove the host-sensitive mount or replace it with a narrowly scoped read-only volume."),
                (r"^\s*cap_add\s*:\s*(?:\[?\s*)?(?:ALL|SYS_ADMIN)\b", "compose.excessive-capability", "Compose service requests excessive Linux capabilities", "high", "CWE-250", "The service requests ALL or SYS_ADMIN capabilities.", "Excessive capabilities weaken container isolation.", "Drop all capabilities by default and add only a documented minimum."),
            ]
            for pattern, rule, title, severity, cwe, explanation, impact, remediation in checks:
                findings.extend(_line_hits(rel_path, lines, re.compile(pattern, re.I), rule, title, severity, cwe, explanation, impact, remediation))

        if ext in {".yaml", ".yml"} and ("k8s" in lower or "kubernetes" in lower or "/manifests/" in lower or "kind:" in "".join(lines[:20]).lower()):
            checks = [
                (r"^\s*hostPID\s*:\s*true\b", "kubernetes.host-pid", "Kubernetes pod uses hostPID", "high", "CWE-250", "The pod shares the host process namespace.", "A compromised workload can inspect host processes.", "Remove hostPID unless the workload has a reviewed host-level requirement."),
                (r"^\s*hostNetwork\s*:\s*true\b", "kubernetes.host-network", "Kubernetes pod uses hostNetwork", "high", "CWE-668", "The pod shares the host network namespace.", "Network isolation is reduced and host services may become reachable.", "Use normal pod networking and explicit Services or NetworkPolicies."),
                (r"^\s*hostPath\s*:", "kubernetes.host-path", "Kubernetes workload mounts a hostPath", "high", "CWE-22", "The workload mounts a path from the node filesystem.", "Host filesystem access increases the impact of a workload compromise.", "Use a PersistentVolume with a constrained path instead of hostPath."),
                (r"^\s*privileged\s*:\s*true\b", "kubernetes.privileged", "Kubernetes container is privileged", "critical", "CWE-250", "The container requests privileged execution.", "A compromised container may access host devices and escape isolation.", "Set privileged: false and remove unnecessary capabilities."),
                (r"\bcapabilities\s*:\s*(?:\n|.*)\b(?:SYS_ADMIN|ALL)\b", "kubernetes.excessive-capability", "Kubernetes workload requests excessive capabilities", "high", "CWE-250", "The manifest requests SYS_ADMIN or ALL capabilities.", "Excessive capabilities weaken pod isolation.", "Drop ALL capabilities and add only the minimum required capability."),
            ]
            for pattern, rule, title, severity, cwe, explanation, impact, remediation in checks:
                findings.extend(_line_hits(rel_path, lines, re.compile(pattern, re.I), rule, title, severity, cwe, explanation, impact, remediation))

        if ext == ".tf":
            checks = [
                (r"\b0\.0\.0\.0/0\b", "terraform.open-network", "Terraform rule allows traffic from the entire internet", "high", "CWE-284", "A network rule contains 0.0.0.0/0.", "Internet-wide exposure can make administrative or sensitive services reachable.", "Restrict ingress to documented CIDRs and required ports."),
                (r"\bpublicly_accessible\s*=\s*true\b|\bpublic\s*=\s*true\b", "terraform.public-resource", "Terraform resource is explicitly public", "high", "CWE-284", "The resource is configured as publicly accessible.", "Public exposure increases the attack surface and may expose sensitive data.", "Set the resource private and expose it through a reviewed boundary."),
                (r"\bencrypted\s*=\s*false\b|\bencryption\s*=\s*false\b", "terraform.unencrypted-storage", "Terraform resource disables encryption", "high", "CWE-311", "The configuration explicitly disables encryption.", "Data at rest may be readable if storage or snapshots are accessed.", "Enable provider-managed encryption and manage keys according to policy."),
            ]
            for pattern, rule, title, severity, cwe, explanation, impact, remediation in checks:
                findings.extend(_line_hits(rel_path, lines, re.compile(pattern, re.I), rule, title, severity, cwe, explanation, impact, remediation))

        if _is_workflow(rel_path):
            checks = [
                (r"^\s*pull_request_target\s*:", "actions.pull-request-target", "GitHub Actions uses pull_request_target", "high", "CWE-668", "The workflow runs with the base repository trust context for pull requests.", "Untrusted pull-request content can reach a privileged workflow if checkout or shell inputs are unsafe.", "Avoid checking out or executing pull-request code in pull_request_target; use a restricted pull_request workflow."),
                (r"^\s*permissions\s*:\s*write-all\b|^\s*contents\s*:\s*write\b", "actions.write-permissions", "CI workflow grants write permissions", "medium", "CWE-250", "The workflow grants write-capable token permissions.", "A workflow compromise can modify repository or release state.", "Set permissions to read-only by default and grant a single write permission only where required."),
                (r"\buses\s*:\s*[^\n@]+@(master|main|latest)\b", "actions.mutable-reference", "CI action uses a mutable reference", "medium", "CWE-829", "The workflow references an action branch or mutable tag instead of an immutable commit.", "The action code can change without a review of this repository.", "Pin third-party actions to a full commit SHA and review upgrades."),
                (r"\brun\s*:.*\$\{\{\s*github\.event\.(pull_request|issue)\b", "actions.untrusted-shell-input", "Workflow interpolates event data into a shell command", "high", "CWE-78", "Untrusted event fields are interpolated directly into a shell command.", "Shell metacharacters in an issue or pull request can alter the command.", "Pass event data through environment variables and quote it, or avoid shell interpretation."),
            ]
            for pattern, rule, title, severity, cwe, explanation, impact, remediation in checks:
                findings.extend(_line_hits(rel_path, lines, re.compile(pattern, re.I), rule, title, severity, cwe, explanation, impact, remediation))

    return findings
