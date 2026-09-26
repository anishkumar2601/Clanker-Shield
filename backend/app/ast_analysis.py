"""Conservative Python Abstract Syntax Tree (AST) data-flow checks.

This is intentionally a small, evidence-preserving analysis rather than a
claim of complete interprocedural analysis. It follows obvious assignments
from common request/input sources to dangerous sinks and refuses to describe
the relationship as a proven runtime path.
"""
from __future__ import annotations

import ast

from .models import Finding, stable_finding_id


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _line(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:240] if 0 < line <= len(lines) else ""


def _source_label(node: ast.AST) -> str | None:
    name = _name(node)
    if name in {"input", "sys.argv", "os.environ", "os.getenv", "os.environ.get"}:
        return name
    if name.startswith(("request.", "req.", "flask.request.")):
        return name
    if isinstance(node, ast.Subscript):
        base = _name(node.value)
        if base in {"request.args", "request.form", "request.json", "request.headers", "request.cookies", "request.files", "req.body", "req.query"}:
            return base
    if isinstance(node, ast.Call):
        return _source_label(node.func)
    return None


def _is_sanitizer(node: ast.AST) -> bool:
    name = _name(node)
    return any(token in name.lower() for token in ("sanitize", "escape", "validate", "allowlist", "parameterize", "quote", "realpath"))


def _taint(node: ast.AST, tainted: dict[str, dict], file: str) -> dict | None:
    source = _source_label(node)
    if source:
        return {"source": source, "file": file, "line": getattr(node, "lineno", 1)}
    if isinstance(node, ast.Name) and node.id in tainted:
        return tainted[node.id]
    if isinstance(node, ast.Call) and _is_sanitizer(node.func):
        return None
    for child in ast.iter_child_nodes(node):
        result = _taint(child, tainted, file)
        if result:
            return result
    return None


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names = []
        for item in node.elts:
            names.extend(_target_names(item))
        return names
    return []


def _sql_parts(node: ast.AST) -> tuple[str, list[str]] | None:
    if not isinstance(node, ast.JoinedStr):
        return None
    parts: list[str] = []
    variables: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name) and value.conversion == -1 and value.format_spec is None:
            parts.append("?")
            variables.append(value.value.id)
        else:
            return None
    return "".join(parts), variables


def _finding(file: str, text: str, call: ast.Call, type_: str, title: str, severity: str, cwe: str,
             source: dict, explanation: str, impact: str, remediation: str, rule_id: str) -> Finding:
    sink_line = getattr(call, "lineno", 1)
    snippet = _line(text, sink_line)
    evidence = [
        {"file": file, "line": source.get("line", sink_line), "role": "SOURCE", "label": source.get("source", "input")},
        {"file": file, "line": sink_line, "role": "SINK", "label": title},
    ]
    return Finding(
        id=stable_finding_id(file, type_, rule_id, f"{sink_line}:{snippet}"),
        type=type_, title=title, severity=severity, cwe=cwe,
        file=file, line=sink_line, end_line=getattr(call, "end_lineno", sink_line),
        snippet=snippet, explanation=explanation, impact=impact, remediation=remediation,
        sources=["ast-dataflow"], rule_ids=[rule_id], confidence=0.78,
        evidence_refs=evidence,
        classification="vulnerability",
    )


def analyze_python_file(file: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=file)
    except (SyntaxError, ValueError):
        return []

    tainted: dict[str, dict] = {}
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    nodes = sorted(ast.walk(tree), key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)))

    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            result = _taint(value, tainted, file) if value else None
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                for target_name in _target_names(target):
                    if result and not (isinstance(value, ast.Call) and _is_sanitizer(value.func)):
                        tainted[target_name] = result
                    else:
                        tainted.pop(target_name, None)
            continue

        if not isinstance(node, ast.Call):
            continue

        call_name = _name(node.func)
        args = list(node.args)
        taint = _taint(args[0], tainted, file) if args else None
        if not taint:
            taint = _taint(node, tainted, file)
        if not taint:
            continue

        result: tuple[str, str, str, str, str, str, str] | None = None
        if call_name.endswith((".execute", ".executemany")):
            result = (
                "sql_injection", "User-controlled input reaches SQL execution (AST data flow)", "critical", "CWE-89",
                "Potential data flow from a request/input source reaches a database execution sink without a recognized sanitizer. This AST pass does not prove runtime reachability.",
                "An attacker-controlled value may alter a query if it is interpolated rather than bound as a parameter.",
                "Use a parameterized query and pass the value as a separate bound parameter.",
            )
        elif call_name in {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}:
            result = (
                "command_injection", "User-controlled input reaches command execution (AST data flow)", "critical", "CWE-78",
                "Potential data flow from a request/input source reaches a process execution sink without a recognized sanitizer. This AST pass does not prove runtime reachability.",
                "An attacker-controlled command or argument may execute with the application's privileges.",
                "Use an explicit argument list, shell=False, and strict validation of every argument.",
            )
        elif call_name in {"open", "os.open", "pathlib.Path.open", "pathlib.Path.read_text", "pathlib.Path.write_text"}:
            result = (
                "path_traversal", "User-controlled input reaches filesystem access (AST data flow)", "high", "CWE-22",
                "Potential data flow from a request/input source reaches a filesystem path sink without a recognized path validator. This AST pass does not prove runtime reachability.",
                "An attacker may read or write outside the intended directory if traversal is possible.",
                "Resolve the path and enforce a strict repository/base-directory boundary before opening it.",
            )
        elif call_name in {"pickle.loads", "pickle.load", "marshal.loads", "yaml.load", "yaml.unsafe_load"}:
            result = (
                "unsafe_deserialization", "User-controlled input reaches unsafe deserialization (AST data flow)", "critical", "CWE-502",
                "Potential data flow from a request/input source reaches a deserialization sink that can construct executable objects. This AST pass does not prove runtime reachability.",
                "Crafted serialized data may execute code or construct unexpected objects.",
                "Use a safe data format and an explicitly restricted loader for untrusted input.",
            )
        elif call_name in {"eval", "exec", "compile"}:
            result = (
                "dynamic_code_execution", "User-controlled input reaches dynamic code execution (AST data flow)", "critical", "CWE-95",
                "Potential data flow from a request/input source reaches eval/exec-style dynamic code execution. This AST pass does not prove runtime reachability.",
                "Attacker-controlled expressions can execute arbitrary application code.",
                "Remove dynamic execution or replace it with a constrained parser and an allowlisted operation set.",
            )

        if not result:
            continue
        type_, title, severity, cwe, explanation, impact, remediation = result
        key = (type_, getattr(node, "lineno", 1))
        if key in seen:
            continue
        seen.add(key)
        findings.append(_finding(file, text, node, type_, title, severity, cwe, taint, explanation, impact, remediation, f"ast.dataflow.{type_}"))

    return findings
