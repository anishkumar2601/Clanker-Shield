"""
Deterministic security analysis.

Three responsibilities live here on purpose, kept separate from the AI layer:

1. Built-in pattern scanner - regex rules over source text, no model involved.
2. Secret scanner - finds and redacts credential-shaped strings.
3. Risk engine - turns raw findings into a scored, banded, explainable result.

Everything the AI later reasons about is grounded in what this module found.
The model can explain a finding; it can never invent one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .ast_analysis import analyze_python_file
from .models import Finding, RiskBreakdown, stable_finding_id

SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml", ".cfg", ".txt"}
MAX_FILE_BYTES = int(1.5 * 1024 * 1024)


# ---------------------------------------------------------------------------
# Built-in pattern rules
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    type: str
    title: str
    severity: str
    cwe: str
    pattern: re.Pattern
    remediation: str
    explanation: str
    impact: str
    extensions: tuple = (".py",)


BUILTIN_RULES: list[Rule] = [
    Rule(
        id="builtin.sql-injection.fstring",
        type="sql_injection",
        title="SQL query built with an f-string",
        severity="critical",
        cwe="CWE-89",
        pattern=re.compile(r"""(?=.*f['"])(?=.*\{[^}]+\})(?=.*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)""", re.IGNORECASE),
        explanation="A SQL statement is assembled with an f-string that interpolates a variable directly into the query text, rather than using a parameterized placeholder.",
        impact="An attacker who controls the interpolated value can alter the query's logic, read unauthorized rows, or modify data.",
        remediation="Use parameterized queries (placeholders like `?` or `%s`) and pass user input as bound parameters instead of formatting it into the SQL string.",
    ),
    Rule(
        id="builtin.sql-injection.concat",
        type="sql_injection",
        title="SQL query built with string concatenation",
        severity="critical",
        cwe="CWE-89",
        pattern=re.compile(r"""(?=.*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)(?=.*['"]\s*\+\s*\w+)""", re.IGNORECASE),
        explanation="A SQL statement is built by concatenating a variable into the query string instead of using a bound parameter.",
        impact="Untrusted input concatenated into SQL can change the query's meaning and expose or corrupt data outside the intended scope.",
        remediation="Replace string concatenation with parameterized queries; never build SQL by joining strings with untrusted values.",
    ),
    Rule(
        id="builtin.sql-injection.format",
        type="sql_injection",
        title="SQL query built with .format() or % interpolation",
        severity="critical",
        cwe="CWE-89",
        pattern=re.compile(r"""(?=.*\b(?:SELECT|INSERT|UPDATE|DELETE)\b)(?=.*(?:\.format\(|['"]\s*%\s*\())""", re.IGNORECASE),
        explanation="A SQL statement uses `.format()` or `%` string interpolation to insert a value into the query text.",
        impact="Values interpolated this way are not escaped for SQL, allowing query structure to be altered by attacker-controlled input.",
        remediation="Use parameterized queries with placeholders bound by the database driver instead of string interpolation.",
    ),
    Rule(
        id="builtin.command-injection.os-system",
        type="command_injection",
        title="Shell command built from a variable via os.system",
        severity="critical",
        cwe="CWE-78",
        pattern=re.compile(r"""os\.system\s*\(.*\+"""),
        explanation="A shell command is assembled by concatenating a variable into an `os.system()` call.",
        impact="If the concatenated value is influenced by user input, an attacker can inject additional shell commands that execute with the application's privileges.",
        remediation="Avoid `os.system`. Use `subprocess.run([...])` with an explicit argument list (no `shell=True`) so arguments cannot be reinterpreted by a shell.",
    ),
    Rule(
        id="builtin.command-injection.shell-true",
        type="command_injection",
        title="Subprocess call uses shell=True",
        severity="critical",
        cwe="CWE-78",
        pattern=re.compile(r"""shell\s*=\s*True"""),
        explanation="A subprocess call is invoked with `shell=True`, which passes the command through a shell interpreter.",
        impact="If any part of the command string is influenced by external input, an attacker can inject additional shell syntax to run arbitrary commands.",
        remediation="Call subprocess with an explicit list of arguments and `shell=False` (the default), avoiding shell interpretation entirely.",
    ),
    Rule(
        id="builtin.secret.hardcoded",
        type="hardcoded_secret",
        title="Hardcoded credential-like value",
        severity="high",
        cwe="CWE-798",
        pattern=re.compile(r"""(?i)\b(api[_-]?key|secret|password|passwd|token)\s*=\s*['"][^'"\s]{6,}['"]"""),
        explanation="A variable that looks like an API key, password, or token is assigned a literal string value directly in source code.",
        impact="Anyone with read access to the repository (including forks, CI logs, or a leaked archive) gains this credential.",
        remediation="Move the value to an environment variable or secret manager and read it at runtime, e.g. `os.environ.get(\"API_KEY\")`.",
    ),
    Rule(
        id="builtin.xss.innerhtml",
        type="unsafe_html",
        title="Untrusted content assigned to innerHTML",
        severity="high",
        cwe="CWE-79",
        pattern=re.compile(r"""\.innerHTML\s*="""),
        explanation="Content is written directly into `innerHTML`, which the browser parses and executes as HTML/JS.",
        impact="If the assigned content includes attacker-controlled data, this results in a cross-site scripting (XSS) vulnerability.",
        remediation="Use `textContent` for plain text, or sanitize HTML with a trusted library (e.g. DOMPurify) before rendering it.",
        extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    Rule(
        id="builtin.xss.dangerously-set",
        type="unsafe_html",
        title="React dangerouslySetInnerHTML used with dynamic content",
        severity="high",
        cwe="CWE-79",
        pattern=re.compile(r"""dangerouslySetInnerHTML"""),
        explanation="A React component uses `dangerouslySetInnerHTML`, bypassing React's default output escaping.",
        impact="If the HTML source includes attacker-controlled data, this results in cross-site scripting.",
        remediation="Avoid rendering raw HTML from user data. If unavoidable, sanitize with a trusted library such as DOMPurify first.",
        extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    Rule(
        id="builtin.path-traversal.join",
        type="path_traversal",
        title="Request-derived path joined without validation",
        severity="high",
        cwe="CWE-22",
        pattern=re.compile(r"""os\.path\.join\([^)]*\b(?:request|req|params|args|requested|user_)"""),
        explanation="A file path is built with `os.path.join` using a value that appears to originate from a request.",
        impact="Without validation, a value like `../../etc/passwd` lets an attacker read files outside the intended directory.",
        remediation="Resolve the final path and verify it stays inside the intended base directory (e.g. compare with `os.path.realpath`) before opening it, and reject any path containing `..`.",
    ),
    Rule(
        id="builtin.weak-auth.verify-false",
        type="weak_authentication",
        title="Token signature verification disabled",
        severity="high",
        cwe="CWE-287",
        pattern=re.compile(r"""verify_signature['"]?\s*:\s*False|verify\s*=\s*False"""),
        explanation="A JWT or token is decoded with signature verification explicitly disabled.",
        impact="Any caller can forge a token with arbitrary claims (including elevated roles) since the signature is never checked.",
        remediation="Always verify token signatures against a known key/algorithm; never disable verification outside of isolated tests.",
    ),
    Rule(
        id="builtin.weak-auth.md5",
        type="weak_authentication",
        title="MD5 used for password hashing",
        severity="high",
        cwe="CWE-287",
        pattern=re.compile(r"""hashlib\.md5\(.*password|hashlib\.md5\(.*passwd""", re.IGNORECASE),
        explanation="Passwords are hashed with MD5, a fast, unsalted hash that is not designed for password storage.",
        impact="MD5 hashes can be brute-forced or reversed via rainbow tables at high speed, exposing user passwords if the database leaks.",
        remediation="Use a password-hashing algorithm designed to be slow, such as bcrypt, scrypt, or Argon2.",
    ),
    Rule(
        id="builtin.config.debug-true",
        type="insecure_configuration",
        title="Debug mode enabled",
        severity="medium",
        cwe="CWE-16",
        pattern=re.compile(r"""^\s*DEBUG\s*=\s*True\s*$"""),
        explanation="The application has `DEBUG` set to `True`.",
        impact="Debug mode can leak stack traces, environment details, and internal paths to end users, aiding an attacker's reconnaissance.",
        remediation="Set `DEBUG = False` in any environment reachable from the internet, and control it via an environment variable.",
    ),
    Rule(
        id="builtin.config.cors-wildcard",
        type="insecure_configuration",
        title="Wildcard CORS origin",
        severity="medium",
        cwe="CWE-16",
        pattern=re.compile(r"""ALLOWED_ORIGINS\s*=\s*['"]\*['"]|allow_origins\s*=\s*\[?['"]\*['"]"""),
        explanation="Cross-origin requests are allowed from any origin (`*`).",
        impact="Any website can make authenticated cross-origin requests against this API if credentials are also allowed, widening the attack surface for CSRF-style abuse.",
        remediation="Restrict `ALLOWED_ORIGINS` / `allow_origins` to an explicit list of trusted origins.",
    ),
]

DEPENDENCY_OLD_VERSIONS = {
    "flask": (1, 0),
    "django": (2, 0),
    "requests": (2, 20),
    "pyyaml": (5, 0),
}


def _parse_version(v: str) -> tuple:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:2]) if parts else (0, 0)


def scan_dependency_file(rel_path: str, text: str) -> list[Finding]:
    findings = []
    if rel_path.endswith("requirements.txt") or rel_path.endswith("Pipfile"):
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)", line)
            if not m:
                continue
            pkg, version = m.group(1).lower(), m.group(2)
            floor = DEPENDENCY_OLD_VERSIONS.get(pkg)
            if floor and _parse_version(version) < floor:
                findings.append(_make_finding(
                    type_="outdated_dependency",
                    title=f"Outdated dependency: {pkg}=={version}",
                    severity="medium",
                    cwe="CWE-1104",
                    file=rel_path, line=lineno, end_line=lineno,
                    snippet=line.strip(),
                    explanation=f"{pkg} is pinned to version {version}, an old release line for this project.",
                    impact="Older dependency versions may be missing security fixes present in later releases. This is dependency triage, not a confirmed CVE.",
                    remediation=f"Review {pkg}'s changelog and upgrade to a maintained version compatible with this project.",
                    sources=["builtin"], rule_id="builtin.dependency.outdated",
                ))
    return findings


def _make_finding(*, type_, title, severity, cwe, file, line, end_line, snippet,
                   explanation, impact, remediation, sources, rule_id, confidence=0.85) -> Finding:
    classification = {
        "hardcoded_secret": "secret",
        "insecure_configuration": "misconfiguration",
        "outdated_dependency": "dependency_risk",
    }.get(type_, "vulnerability")
    return Finding(
        id=stable_finding_id(file, type_, rule_id, snippet),
        type=type_, title=title, severity=severity, cwe=cwe,
        file=file, line=line, end_line=end_line, snippet=snippet,
        explanation=explanation, impact=impact, remediation=remediation,
        sources=list(sources), rule_ids=[rule_id], confidence=confidence,
        classification=classification,
    )


def run_builtin_scanner(root: str, files: list[str]) -> list[Finding]:
    import os
    findings: list[Finding] = []
    for rel_path in files:
        full_path = os.path.join(root, rel_path)
        ext = os.path.splitext(rel_path)[1].lower()
        try:
            if os.path.getsize(full_path) > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if os.path.basename(rel_path) in ("requirements.txt", "Pipfile"):
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            findings.extend(scan_dependency_file(rel_path, text))
            continue

        if ext not in SCAN_EXTENSIONS:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        if ext == ".py":
            # AST analysis supplements, rather than replaces, the transparent
            # line rules. It only reports when an input source reaches a sink.
            findings.extend(analyze_python_file(rel_path, "".join(lines)))

        for rule in BUILTIN_RULES:
            if ext not in rule.extensions:
                continue
            for lineno, line in enumerate(lines, start=1):
                if rule.pattern.search(line):
                    findings.append(_make_finding(
                        type_=rule.type, title=rule.title, severity=rule.severity, cwe=rule.cwe,
                        file=rel_path, line=lineno, end_line=lineno, snippet=line.strip()[:240],
                        explanation=rule.explanation, impact=rule.impact, remediation=rule.remediation,
                        sources=["builtin"], rule_id=rule.id,
                    ))
    return findings


# ---------------------------------------------------------------------------
# Secret scanner + redaction
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("postgres_url", re.compile(r"postgres(?:ql)?://[^\s'\"]+")),
    ("mysql_url", re.compile(r"mysql(?:\+\w+)?://[^\s'\"]+")),
    ("mongodb_url", re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+")),
    ("jwt_like", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|password|passwd|token|client[_-]?secret)\s*=\s*['\"]([^'\"\s]{6,})['\"]"
    )),
    ("stripe_key", re.compile(r"sk_(live|test)_[A-Za-z0-9]{16,}")),
]


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * max(4, len(value) - 8)}{value[-4:]}"


def run_secret_scanner(root: str, files: list[str]) -> list[Finding]:
    import os
    findings: list[Finding] = []
    for rel_path in files:
        full_path = os.path.join(root, rel_path)
        ext = os.path.splitext(rel_path)[1].lower()
        if ext not in SCAN_EXTENSIONS and not rel_path.endswith((".env", ".pem", ".key")):
            continue
        try:
            if os.path.getsize(full_path) > MAX_FILE_BYTES:
                continue
            with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, start=1):
            for kind, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                secret_value = match.group(2) if match.groups() and len(match.groups()) >= 2 else match.group(0)
                redacted_line = line.replace(secret_value, redact_secret(secret_value)).strip()[:240]
                findings.append(_make_finding(
                    type_="hardcoded_secret",
                    title=f"Exposed secret detected ({kind.replace('_', ' ')})",
                    severity="high", cwe="CWE-798",
                    file=rel_path, line=lineno, end_line=lineno,
                    snippet=redacted_line,
                    explanation=f"A value matching the shape of a {kind.replace('_', ' ')} was found in source.",
                    impact="Anyone with repository access obtains a working credential, which may grant access to production systems.",
                    remediation="Rotate this credential immediately, remove it from source control history, and load it from an environment variable or secret manager instead.",
                    sources=["secret-scanner"], rule_id=f"secret.{kind}", confidence=0.9,
                ))
                break  # one match per line is enough signal; avoid duplicate noise
    return findings


# ---------------------------------------------------------------------------
# Correlation - merge overlapping findings at the same file+line
# ---------------------------------------------------------------------------

def correlate_findings(all_findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for f in all_findings:
        key = (f.file, f.line, f.type)
        if key in merged:
            existing = merged[key]
            for src in f.sources:
                if src not in existing.sources:
                    existing.sources.append(src)
            for rid in f.rule_ids:
                if rid not in existing.rule_ids:
                    existing.rule_ids.append(rid)
            existing.confidence = min(0.99, existing.confidence + 0.05)
        else:
            merged[key] = f
    return list(merged.values())


# ---------------------------------------------------------------------------
# Deterministic risk engine
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"critical": 40, "high": 28, "medium": 15, "low": 6}

EXPLOITABILITY_BY_TYPE = {
    "sql_injection": 9, "command_injection": 10, "hardcoded_secret": 6,
    "unsafe_html": 7, "path_traversal": 7, "weak_authentication": 8,
    "unsafe_deserialization": 9, "dynamic_code_execution": 10,
    "dependency_vulnerability": 7,
    "insecure_configuration": 4, "outdated_dependency": 3,
}

DATA_SENSITIVITY_BY_TYPE = {
    "sql_injection": 9, "hardcoded_secret": 9, "weak_authentication": 8,
    "path_traversal": 6, "command_injection": 7, "unsafe_html": 5,
    "unsafe_deserialization": 8, "dynamic_code_execution": 8,
    "dependency_vulnerability": 6,
    "insecure_configuration": 3, "outdated_dependency": 3,
}


def _route_files(inventory: dict) -> set:
    return {r["file"] for r in inventory.get("api_routes", [])}


def score_finding(finding: Finding, inventory: dict) -> None:
    severity_weight = SEVERITY_WEIGHT.get(finding.severity, 10)
    exploitability = EXPLOITABILITY_BY_TYPE.get(finding.type, 5)
    data_sensitivity = DATA_SENSITIVITY_BY_TYPE.get(finding.type, 4)

    routed_files = _route_files(inventory)
    reachable = finding.file in routed_files or finding.file in inventory.get("entry_points", [])
    reachability = 9 if reachable else 4

    exposure = 8 if finding.type in ("sql_injection", "command_injection", "path_traversal") and reachable else 5
    evidence_strength = 8 if len(finding.sources) > 1 else 6
    scanner_confidence = round(finding.confidence * 10)

    breakdown = RiskBreakdown(
        severity_weight=severity_weight,
        exploitability=exploitability,
        exposure=exposure,
        data_sensitivity=data_sensitivity,
        reachability=reachability,
        evidence_strength=evidence_strength,
        scanner_confidence=scanner_confidence,
    )

    raw = (
        severity_weight * 1.0
        + exploitability * 2.0
        + exposure * 1.5
        + data_sensitivity * 1.5
        + reachability * 1.2
        + evidence_strength * 1.0
        + scanner_confidence * 0.8
    )
    score = max(1, min(100, round(raw)))

    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 35:
        band = "medium"
    else:
        band = "low"

    finding.risk_score = score
    finding.risk_band = band
    finding.risk_breakdown = breakdown.to_dict()
    if not finding.evidence_refs:
        finding.evidence_refs = [{"file": finding.file, "line": finding.line}]
