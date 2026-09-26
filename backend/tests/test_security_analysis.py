import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security_analysis as sa
from app import ai_analyst
from app.ast_analysis import analyze_python_file
from app import zip_safety
from app.models import compute_metrics, stable_finding_id


def _write(tmpdir, rel_path, content):
    full = os.path.join(tmpdir, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(content)
    return rel_path


def test_sql_injection_fstring_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "db.py", 'query = f"SELECT * FROM users WHERE name = \'{name}\'"\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "sql_injection" for f in findings)


def test_ast_data_flow_links_request_source_to_sql_sink():
    source = (
        "from flask import request\n"
        "username = request.args.get('username')\n"
        "query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "cursor.execute(query)\n"
    )
    findings = analyze_python_file("db.py", source)
    finding = next(f for f in findings if f.type == "sql_injection")
    assert finding.line == 4
    assert {item["role"] for item in finding.evidence_refs} == {"SOURCE", "SINK"}
    assert "Potential data flow" in finding.explanation


def test_ast_data_flow_does_not_flag_recognized_sanitizer_as_sink_flow():
    source = (
        "from flask import request\n"
        "username = request.args.get('username')\n"
        "clean = sanitize(username)\n"
        "query = f\"SELECT * FROM users WHERE name = '{clean}'\"\n"
        "cursor.execute(query)\n"
    )
    assert not any(f.type == "sql_injection" for f in analyze_python_file("db.py", source))


def test_sql_injection_concatenation_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "db.py", 'query = "SELECT * FROM t WHERE x = \'" + val + "\'"\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "sql_injection" for f in findings)


def test_command_injection_os_system_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "u.py", 'os.system("echo " + user_input)\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "command_injection" for f in findings)


def test_command_injection_shell_true_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "u.py", 'subprocess.call(cmd, shell=True)\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "command_injection" for f in findings)


def test_hardcoded_secret_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "cfg.py", 'api_key = "sk_live_abcdefghijklmnop"\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "hardcoded_secret" for f in findings)


def test_unsafe_html_innerhtml_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "r.js", 'el.innerHTML = data;\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "unsafe_html" for f in findings)


def test_path_traversal_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "f.py", 'full = os.path.join(base, requested_path)\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "path_traversal" for f in findings)


def test_weak_auth_md5_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "a.py", 'hashlib.md5(password.encode()).hexdigest()\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "weak_authentication" for f in findings)


def test_debug_true_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "config.py", 'DEBUG = True\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        assert any(f.type == "insecure_configuration" for f in findings)


def test_outdated_dependency_detected():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "requirements.txt", 'flask==0.12\ndjango==4.2.13\n')
        findings = sa.run_builtin_scanner(tmp, [rel])
        titles = [f.title for f in findings]
        assert any("flask" in t for t in titles)
        assert not any("django" in t for t in titles)  # modern version should not trigger


def test_secret_scanner_redacts_value():
    with tempfile.TemporaryDirectory() as tmp:
        rel = _write(tmp, "cfg.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        findings = sa.run_secret_scanner(tmp, [rel])
        assert len(findings) == 1
        assert "AKIAABCDEFGHIJKLMNOP" not in findings[0].snippet
        assert "AKIA" in findings[0].snippet  # a recognizable fragment remains


def test_secret_scanner_does_not_leak_full_github_token():
    with tempfile.TemporaryDirectory() as tmp:
        token = "ghp_" + "a" * 36
        rel = _write(tmp, "auth.py", f'GITHUB_TOKEN = "{token}"\n')
        findings = sa.run_secret_scanner(tmp, [rel])
        assert findings
        assert token not in findings[0].snippet


def test_external_ai_payload_is_redacted_and_fails_closed_for_secret_shapes():
    token = "ghp_" + "b" * 36
    sanitized = ai_analyst._sanitize_for_model({"snippet": f'GITHUB_TOKEN = "{token}"'})
    assert token not in sanitized["snippet"]
    assert not ai_analyst._contains_secret(str(sanitized))


def test_correlate_merges_same_file_line_type():
    a = sa._make_finding(
        type_="hardcoded_secret", title="A", severity="high", cwe="CWE-798",
        file="x.py", line=1, end_line=1, snippet="s", explanation="e", impact="i",
        remediation="r", sources=["builtin"], rule_id="rule.a",
    )
    b = sa._make_finding(
        type_="hardcoded_secret", title="A", severity="high", cwe="CWE-798",
        file="x.py", line=1, end_line=1, snippet="s", explanation="e", impact="i",
        remediation="r", sources=["secret-scanner"], rule_id="rule.b",
    )
    merged = sa.correlate_findings([a, b])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"builtin", "secret-scanner"}


def test_risk_scoring_bands_critical_above_high():
    finding_critical = sa._make_finding(
        type_="sql_injection", title="t", severity="critical", cwe="CWE-89",
        file="a.py", line=1, end_line=1, snippet="s", explanation="e", impact="i",
        remediation="r", sources=["builtin"], rule_id="rule.sql",
    )
    finding_low = sa._make_finding(
        type_="outdated_dependency", title="t", severity="low", cwe="CWE-1104",
        file="requirements.txt", line=1, end_line=1, snippet="s", explanation="e", impact="i",
        remediation="r", sources=["builtin"], rule_id="rule.dep", confidence=0.5,
    )
    sa.score_finding(finding_critical, {"api_routes": [], "entry_points": []})
    sa.score_finding(finding_low, {"api_routes": [], "entry_points": []})
    assert finding_critical.risk_score > finding_low.risk_score
    assert finding_critical.risk_band in ("critical", "high")
    assert finding_low.risk_band in ("low", "medium")


def test_stable_finding_id_is_deterministic():
    id1 = stable_finding_id("a.py", "sql_injection", "rule.x", "snippet text")
    id2 = stable_finding_id("a.py", "sql_injection", "rule.x", "snippet text")
    id3 = stable_finding_id("a.py", "sql_injection", "rule.x", "different snippet")
    assert id1 == id2
    assert id1 != id3


def test_compute_metrics_neutralized_vs_active():
    critical = sa._make_finding(
        type_="sql_injection", title="t", severity="critical", cwe="CWE-89",
        file="a.py", line=1, end_line=1, snippet="s", explanation="e", impact="i",
        remediation="r", sources=["builtin"], rule_id="r1",
    )
    critical.risk_score = 90
    resolved_one = sa._make_finding(
        type_="command_injection", title="t2", severity="high", cwe="CWE-78",
        file="b.py", line=1, end_line=1, snippet="s2", explanation="e", impact="i",
        remediation="r", sources=["builtin"], rule_id="r2",
    )
    resolved_one.risk_score = 70
    resolved_one.resolved = True

    metrics = compute_metrics([critical, resolved_one])
    assert metrics["threats_detected"] == 2
    assert metrics["threats_neutralized"] == 1
    assert metrics["active_vulnerabilities"] == 1
    assert metrics["critical_count"] == 1


# ---------------------------------------------------------------------------
# ZIP safety
# ---------------------------------------------------------------------------

def _make_zip_bytes(entries: dict) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_zip_extracts_normal_archive():
    data = _make_zip_bytes({"a.py": "print(1)\n", "sub/b.py": "print(2)\n"})
    with tempfile.TemporaryDirectory() as dest:
        result = zip_safety.safe_extract_zip(data, dest)
        assert result.files_extracted == 2
        assert os.path.isfile(os.path.join(dest, "a.py"))
        assert os.path.isfile(os.path.join(dest, "sub", "b.py"))


def test_zip_rejects_path_traversal_member():
    data = _make_zip_bytes({"a.py": "print(1)\n", "../evil.py": "print('escaped')\n"})
    with tempfile.TemporaryDirectory() as dest:
        result = zip_safety.safe_extract_zip(data, dest)
        # the malicious member is skipped; only the safe member is extracted
        assert result.files_extracted == 1
        assert any("traversal" in s for s in result.skipped_members)
        assert not os.path.exists(os.path.join(os.path.dirname(dest), "evil.py"))


def test_zip_rejects_absolute_path_member():
    data = _make_zip_bytes({"/etc/evil.py": "print('escaped')\n"})
    with tempfile.TemporaryDirectory() as dest:
        try:
            result = zip_safety.safe_extract_zip(data, dest)
            assert result.files_extracted == 0
        except zip_safety.ZipSafetyError:
            pass  # also acceptable: rejected the whole archive


def test_zip_rejects_oversized_upload():
    big = b"x" * (zip_safety.MAX_UPLOAD_BYTES + 1)
    with tempfile.TemporaryDirectory() as dest:
        try:
            zip_safety.safe_extract_zip(big, dest)
            assert False, "expected ZipSafetyError"
        except zip_safety.ZipSafetyError:
            pass


def test_zip_rejects_too_many_members():
    entries = {f"file_{i}.txt": "x" for i in range(zip_safety.MAX_MEMBERS + 1)}
    data = _make_zip_bytes(entries)
    with tempfile.TemporaryDirectory() as dest:
        try:
            zip_safety.safe_extract_zip(data, dest)
            assert False, "expected ZipSafetyError"
        except zip_safety.ZipSafetyError:
            pass
