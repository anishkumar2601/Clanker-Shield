"""
Post-patch verification.

Verification never re-runs application code. Python files are compiled
in-memory for a syntax check only (`compile()`), and the result is compared
against the pre-patch scan by (file, type) - the narrowest identity that
survives a targeted single-line patch shifting nothing else in the file.

Runtime tests are intentionally not executed here; that status is always
reported as NOT_RUN, matching the product's stated safety boundary.
"""
from __future__ import annotations

import os


def check_python_syntax(root: str, files: list[str]) -> dict:
    errors = []
    checked = 0
    for rel_path in files:
        if not rel_path.endswith(".py"):
            continue
        full_path = os.path.join(root, rel_path)
        if not os.path.isfile(full_path):
            continue
        checked += 1
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            compile(source, rel_path, "exec")
        except SyntaxError as exc:
            errors.append({"file": rel_path, "error": str(exc)})
    return {"files_checked": checked, "errors": errors, "passed": not errors}


def compare_scans(before_findings: list[dict], after_findings: list[dict]) -> dict:
    def key(f):
        return (f["file"], f["type"], f.get("rule_ids", [None])[0])

    before_keys = {key(f): f for f in before_findings}
    after_keys = {key(f): f for f in after_findings}

    resolved = [f for k, f in before_keys.items() if k not in after_keys]
    remaining = [f for k, f in before_keys.items() if k in after_keys]
    new = [f for k, f in after_keys.items() if k not in before_keys]
    new_critical_high = [f for f in new if f.get("severity") in {"critical", "high"}]

    def severity_counts(items):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in items:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    before_score = sum(f["risk_score"] for f in before_findings)
    after_score = sum(f["risk_score"] for f in after_findings)

    return {
        "resolved_count": len(resolved),
        "resolved": [{"id": f["id"], "title": f["title"], "file": f["file"], "line": f["line"]} for f in resolved],
        "remaining_count": len(remaining),
        "new_findings_count": len(new),
        "new_critical_high_count": len(new_critical_high),
        "before_severity_counts": severity_counts(before_findings),
        "after_severity_counts": severity_counts(after_findings),
        "before_total_risk": before_score,
        "after_total_risk": after_score,
        "risk_delta": after_score - before_score,
    }


def determine_verdict(target_finding_key, before_findings: list[dict], after_findings: list[dict],
                       syntax_result: dict, diff_summary: dict | None = None) -> str:
    if not syntax_result["passed"]:
        return "FAILED"

    def key(f):
        return (f["file"], f["type"], f.get("rule_ids", [None])[0])

    after_keys = {key(f) for f in after_findings}
    if target_finding_key not in after_keys:
        if (diff_summary or {}).get("new_critical_high_count", 0) > 0:
            return "FAILED_NEW_FINDINGS"
        return "STATICALLY_VERIFIED"

    # Same rule at the same file is still present post-patch - the fix didn't take.
    return "NOT_VERIFIED"
