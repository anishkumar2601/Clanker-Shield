import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import iac_analysis
from app.cli import main, scan_directory


def _write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def test_iac_rules_detect_docker_and_workflow_risks(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM python:3.12\nADD https://example.invalid/app.tar.gz /app/\n")
    _write(tmp_path, ".github/workflows/test.yml", "on:\n  pull_request_target:\npermissions: write-all\njobs:\n  test:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
    findings = iac_analysis.scan_iac_files(str(tmp_path), ["Dockerfile", ".github/workflows/test.yml"])
    rules = {rule for finding in findings for rule in finding.rule_ids}
    assert "docker.no-non-root-user" in rules
    assert "docker.remote-add" in rules
    assert "actions.pull-request-target" in rules
    assert "actions.write-permissions" in rules


def test_cli_scan_writes_valid_sarif_and_fail_threshold(tmp_path):
    _write(tmp_path, "app.py", "DEBUG = True\n")
    repo = scan_directory(str(tmp_path))
    assert repo.scan_count == 1
    assert repo.coverage["runtime_verification"] == "NOT_AVAILABLE"
    output = tmp_path / "result.sarif"
    exit_code = main(["scan", str(tmp_path), "--format", "sarif", "--output", str(output), "--fail-on", "medium"])
    assert exit_code == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
