import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.main import app, REPOS

client = TestClient(app)


def setup_function(_):
    REPOS.clear()


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "ai_configured" in body


def test_demo_repository_creates_findings_across_categories():
    r = client.post("/api/repositories/demo")
    assert r.status_code == 200
    data = r.json()
    assert data["files_analyzed"] > 0
    assert "Flask" in data["frameworks"]
    types = {f["type"] for f in data["findings"]}
    for expected in ("sql_injection", "command_injection", "hardcoded_secret",
                     "unsafe_html", "path_traversal", "weak_authentication",
                     "insecure_configuration", "outdated_dependency"):
        assert expected in types, f"missing {expected} in demo scan"
    assert data["metrics"]["threats_detected"] == len(data["findings"])
    assert data["coverage"]["files_discovered"] >= data["coverage"]["files_analyzed"]
    assert data["coverage"]["files_skipped"] >= 0
    assert len(data["scan_history"]) == 1
    stage_ids = [s["id"] for s in data["pipeline"]]
    assert stage_ids == [
        "inventory", "dependency_analysis", "semgrep", "bandit",
        "static_analysis", "iac_analysis", "secrets", "correlation", "risk", "ai_reasoning", "attack_paths",
    ]


def test_get_repository_roundtrip():
    r = client.post("/api/repositories/demo")
    repo_id = r.json()["id"]
    r2 = client.get(f"/api/repositories/{repo_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == repo_id


def test_get_unknown_repository_404():
    r = client.get("/api/repositories/repo_does_not_exist")
    assert r.status_code == 404


def test_finding_analyze_and_question_use_local_fallback_without_api_key():
    os.environ.pop("CLANKER_AI_API_KEY", None)
    r = client.post("/api/repositories/demo")
    data = r.json()
    repo_id = data["id"]
    finding_id = data["findings"][0]["id"]

    r = client.post(f"/api/repositories/{repo_id}/findings/{finding_id}/analyze")
    assert r.status_code == 200
    assert r.json()["mode"] == "local"

    r = client.post(f"/api/repositories/{repo_id}/questions", json={"question": "What should I fix first?"})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "local"
    assert body["answer"]


def test_question_requires_non_empty_body():
    r = client.post("/api/repositories/demo")
    repo_id = r.json()["id"]
    r = client.post(f"/api/repositories/{repo_id}/questions", json={"question": "   "})
    assert r.status_code == 400


def test_fix_apply_verify_workflow_resolves_finding():
    r = client.post("/api/repositories/demo")
    data = r.json()
    repo_id = data["id"]
    target = next(f for f in data["findings"] if f["type"] == "command_injection" and f["line"] == 10)

    r = client.post(f"/api/repositories/{repo_id}/findings/{target['id']}/fix")
    assert r.status_code == 200
    patch = r.json()
    assert patch["status"] == "draft"
    assert "diff" in patch and patch["diff"]

    r = client.post(f"/api/repositories/{repo_id}/patches/apply", json={"patch_id": patch["id"]})
    assert r.status_code == 200
    assert r.json()["patch"]["status"] == "applied"

    r = client.post(f"/api/repositories/{repo_id}/verify")
    assert r.status_code == 200
    v = r.json()
    assert v["verdict"] == "STATICALLY_VERIFIED"
    assert v["syntax_check"]["passed"] is True
    assert v["runtime_verification"] == "NOT_AVAILABLE"
    assert v["security_regression_test"] == "NOT_RUN"
    assert v["repository"]["metrics"]["threats_neutralized"] >= 1


def test_finding_suppression_requires_reason_and_can_reopen():
    data = client.post("/api/repositories/demo").json()
    repo_id = data["id"]
    finding_id = data["findings"][0]["id"]
    short = client.post(f"/api/repositories/{repo_id}/findings/{finding_id}/status", json={"status": "FALSE_POSITIVE", "reason": "no"})
    assert short.status_code == 400
    suppressed = client.post(f"/api/repositories/{repo_id}/findings/{finding_id}/status", json={"status": "ACCEPTED_RISK", "reason": "Reviewed and accepted for this demo"})
    assert suppressed.status_code == 200
    assert suppressed.json()["lifecycle_status"] == "ACCEPTED_RISK"
    reopened = client.post(f"/api/repositories/{repo_id}/findings/{finding_id}/status", json={"status": "REOPENED"})
    assert reopened.status_code == 200
    assert reopened.json()["lifecycle_status"] == "OPEN"


def test_apply_same_patch_twice_is_rejected():
    r = client.post("/api/repositories/demo")
    data = r.json()
    repo_id = data["id"]
    target = next(f for f in data["findings"] if f["type"] == "command_injection" and f["line"] == 10)
    patch = client.post(f"/api/repositories/{repo_id}/findings/{target['id']}/fix").json()
    r1 = client.post(f"/api/repositories/{repo_id}/patches/apply", json={"patch_id": patch["id"]})
    assert r1.status_code == 200
    r2 = client.post(f"/api/repositories/{repo_id}/patches/apply", json={"patch_id": patch["id"]})
    assert r2.status_code == 409


def test_apply_patch_rejects_stale_hash():
    r = client.post("/api/repositories/demo")
    data = r.json()
    repo_id = data["id"]
    workspace = REPOS[repo_id].workspace_path
    target = next(f for f in data["findings"] if f["type"] == "command_injection" and f["line"] == 10)
    patch = client.post(f"/api/repositories/{repo_id}/findings/{target['id']}/fix").json()

    # Simulate the file changing on disk after the patch was generated.
    target_path = os.path.join(workspace, target["file"])
    with open(target_path, "a") as fh:
        fh.write("\n# manual edit after patch generation\n")

    r = client.post(f"/api/repositories/{repo_id}/patches/apply", json={"patch_id": patch["id"]})
    assert r.status_code == 409
    assert "changed" in r.json()["detail"].lower()


def test_fix_unpatchable_finding_returns_422():
    r = client.post("/api/repositories/demo")
    data = r.json()
    repo_id = data["id"]
    unpatchable = next(f for f in data["findings"] if f["type"] == "weak_authentication")
    r = client.post(f"/api/repositories/{repo_id}/findings/{unpatchable['id']}/fix")
    assert r.status_code == 422


def test_inventory_and_graph_endpoints():
    r = client.post("/api/repositories/demo")
    repo_id = r.json()["id"]
    inv = client.get(f"/api/repositories/{repo_id}/inventory").json()
    assert inv["total_files"] > 0
    graph = client.get(f"/api/repositories/{repo_id}/graph").json()
    assert "nodes" in graph and "edges" in graph
    assert len(graph["nodes"]) > 0


def test_structure_endpoint():
    r = client.post("/api/repositories/demo")
    repo_id = r.json()["id"]
    structure = client.get(f"/api/repositories/{repo_id}/structure").json()
    assert structure["total_files"] > 0
    assert "app" in structure["tree"]


def test_report_formats_are_evidence_based_and_sarif_shaped():
    data = client.post("/api/repositories/demo").json()
    repo_id = data["id"]
    for fmt in ("json", "csv", "markdown", "html", "sarif"):
        response = client.get(f"/api/repositories/{repo_id}/reports/{fmt}")
        assert response.status_code == 200
        assert response.content
    sarif = client.get(f"/api/repositories/{repo_id}/reports/sarif").json()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "ClankerShield"
    assert sarif["runs"][0]["properties"]["verification"] == []


def test_upload_zip_rejects_traversal_and_still_scans_safe_files():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", 'DEBUG = True\n')
        zf.writestr("../evil.py", "print('escaped')\n")
    buf.seek(0)

    r = client.post(
        "/api/repositories/upload",
        files={"file": ("project.zip", buf.getvalue(), "application/zip")},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["files_analyzed"] == 1
    assert data["upload_notice"]["files_extracted"] == 1
    assert len(data["upload_notice"]["skipped_members"]) == 1


def test_upload_rejects_oversized_zip():
    from app import zip_safety
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.txt", "x" * 100)
    content = buf.getvalue() + b"\x00" * (zip_safety.MAX_UPLOAD_BYTES + 1)

    r = client.post(
        "/api/repositories/upload",
        files={"file": ("big.zip", content, "application/zip")},
    )
    assert r.status_code == 400


def test_upload_rejects_invalid_zip():
    r = client.post(
        "/api/repositories/upload",
        files={"file": ("notazip.zip", b"this is not a zip file", "application/zip")},
    )
    assert r.status_code == 400
