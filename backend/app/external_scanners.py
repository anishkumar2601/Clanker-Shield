"""
Optional external scanner integrations (Semgrep, Bandit).

Design rules:
- Never use shell=True; always pass an explicit argument list.
- Always set a timeout.
- Strip the subprocess environment down to the minimum needed.
- If a tool is not installed, or fails, or times out, report that honestly
  instead of silently continuing as if it ran.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .models import Finding, stable_finding_id

SUBPROCESS_TIMEOUT_SECONDS = 60


def _minimal_env() -> dict:
    keep = ("PATH", "HOME", "LANG", "LC_ALL")
    return {k: os.environ[k] for k in keep if k in os.environ}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def bandit_available() -> bool:
    return shutil.which("bandit") is not None


def run_semgrep(root: str) -> dict:
    """Returns {status, findings, detail}. status in completed|not_installed|failed|timeout."""
    if not semgrep_available():
        return {"status": "not_installed", "findings": [], "detail": "Semgrep is not installed in this environment."}

    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", root],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=_minimal_env(),
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "findings": [], "detail": f"Semgrep exceeded the {SUBPROCESS_TIMEOUT_SECONDS}s timeout."}
    except OSError as exc:
        return {"status": "failed", "findings": [], "detail": f"Semgrep could not be started: {exc}"}

    if proc.returncode not in (0, 1):  # semgrep returns 1 when findings exist
        return {"status": "failed", "findings": [], "detail": (proc.stderr or "Semgrep exited with an error.")[:400]}

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "failed", "findings": [], "detail": "Semgrep output could not be parsed."}

    findings = []
    for result in payload.get("results", []):
        rel_file = os.path.relpath(result.get("path", ""), root)
        severity_raw = (result.get("extra", {}).get("severity") or "medium").lower()
        severity = {"error": "high", "warning": "medium", "info": "low"}.get(severity_raw, "medium")
        check_id = result.get("check_id", "semgrep")
        snippet = (result.get("extra", {}).get("lines", "") or "")[:240]
        findings.append(Finding(
            id=stable_finding_id(rel_file, "semgrep_finding", check_id, snippet),
            type="semgrep_finding",
            title=result.get("check_id", "Semgrep finding").split(".")[-1].replace("-", " ").title(),
            severity=severity,
            cwe=", ".join(result.get("extra", {}).get("metadata", {}).get("cwe", []) or ["N/A"]) if isinstance(
                result.get("extra", {}).get("metadata", {}).get("cwe"), list
            ) else str(result.get("extra", {}).get("metadata", {}).get("cwe", "N/A")),
            file=rel_file,
            line=result.get("start", {}).get("line", 1),
            end_line=result.get("end", {}).get("line", result.get("start", {}).get("line", 1)),
            snippet=snippet,
            explanation=result.get("extra", {}).get("message", "Semgrep flagged this pattern."),
            impact="See Semgrep rule metadata for the specific risk this pattern represents.",
            remediation="Review the Semgrep rule documentation linked in the finding for the recommended fix.",
            sources=["semgrep"],
            rule_ids=[result.get("check_id", "semgrep")],
            confidence=0.75,
        ))
    return {"status": "completed", "findings": findings, "detail": f"{len(findings)} finding(s)."}


def run_bandit(root: str) -> dict:
    if not bandit_available():
        return {"status": "not_installed", "findings": [], "detail": "Bandit is not installed in this environment."}

    try:
        proc = subprocess.run(
            ["bandit", "-r", root, "-f", "json", "-q"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=_minimal_env(),
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "findings": [], "detail": f"Bandit exceeded the {SUBPROCESS_TIMEOUT_SECONDS}s timeout."}
    except OSError as exc:
        return {"status": "failed", "findings": [], "detail": f"Bandit could not be started: {exc}"}

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "failed", "findings": [], "detail": "Bandit output could not be parsed."}

    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for result in payload.get("results", []):
        rel_file = os.path.relpath(result.get("filename", ""), root)
        test_id = result.get("test_id", "bandit")
        snippet = (result.get("code", "") or "")[:240]
        findings.append(Finding(
            id=stable_finding_id(rel_file, "bandit_finding", test_id, snippet),
            type="bandit_finding",
            title=result.get("test_name", "Bandit finding"),
            severity=severity_map.get(result.get("issue_severity", "MEDIUM"), "medium"),
            cwe=f"CWE-{result.get('issue_cwe', {}).get('id')}" if isinstance(result.get("issue_cwe"), dict) else "N/A",
            file=rel_file,
            line=result.get("line_number", 1),
            end_line=result.get("line_number", 1),
            snippet=snippet,
            explanation=result.get("issue_text", "Bandit flagged this pattern."),
            impact="See Bandit's documentation for this test ID for the specific risk.",
            remediation="Review Bandit's recommended remediation for this test ID.",
            sources=["bandit"],
            rule_ids=[result.get("test_id", "bandit")],
            confidence=0.8,
        ))
    return {"status": "completed", "findings": findings, "detail": f"{len(findings)} finding(s)."}
