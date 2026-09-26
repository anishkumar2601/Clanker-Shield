"""
Safe patch generation and hash-protected application.

Only a small set of known-safe rewrite patterns are supported. Every other
finding still gets remediation guidance, but no automatic patch - guessing at
an unfamiliar code shape is how a "security" tool introduces new bugs.
"""
from __future__ import annotations

import difflib
import ast
import hashlib
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from .models import Patch, new_id


class PatchError(ValueError):
    """Safe to show to the user."""


def file_hash(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _diff(original: str, patched: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{filename}", tofile=f"b/{filename}",
    ))


# Each generator takes (original_text, finding) -> (new_text, explanation) or None if it can't confidently patch.

def _patch_sql_fstring(text: str, finding: dict) -> tuple[str, str] | None:
    try:
        tree = ast.parse(text, filename=finding["file"])
    except SyntaxError:
        return None

    def parts(node):
        if not isinstance(node, ast.JoinedStr):
            return None
        sql_parts, variables = [], []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                sql_parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name) and value.conversion == -1 and value.format_spec is None:
                sql_parts.append("?")
                variables.append(value.value.id)
            else:
                return None
        sql = "".join(sql_parts)
        if not variables or not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", sql, re.IGNORECASE):
            return None
        return sql, variables

    def params(variables):
        return f"({', '.join(variables)},)" if len(variables) == 1 else f"({', '.join(variables)})"

    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}]
    for call in sorted(calls, key=lambda item: getattr(item, "lineno", 0)):
        if len(call.args) != 1 or call.keywords:
            continue
        query_node = call.args[0]
        assignment = None
        if isinstance(query_node, ast.Name):
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == query_node.id for target in node.targets):
                    if isinstance(node.value, ast.JoinedStr) and getattr(node, "lineno", 0) == finding["line"]:
                        if getattr(call, "lineno", 0) < getattr(node, "lineno", 0):
                            continue
                        assignment = node
                        query_node = node.value
                        break
        if not isinstance(query_node, ast.JoinedStr) or (getattr(query_node, "lineno", 0) != finding["line"] and not assignment):
            continue
        rendered = parts(query_node)
        if not rendered:
            continue
        sql, variables = rendered
        old_query = ast.get_source_segment(text, query_node)
        call_source = ast.get_source_segment(text, call)
        func_source = ast.get_source_segment(text, call.func)
        if not old_query or not call_source or not func_source:
            continue
        if assignment:
            query_name = ast.get_source_segment(text, assignment.targets[0])
            if not query_name:
                continue
            new_call = f"{func_source}({query_name}, {params(variables)})"
            patched = text.replace(old_query, repr(sql), 1).replace(call_source, new_call, 1)
        else:
            new_call = f"{func_source}({repr(sql)}, {params(variables)})"
            patched = text.replace(call_source, new_call, 1)
        if patched == text:
            continue
        return patched, (
            f"Rewrote the structurally understood SQL f-string on line {finding['line']} to use bound `?` "
            f"parameters for {', '.join(variables)}. The patch was refused unless the query and execute call "
            "could be matched by the Python AST."
        )
    return None


def _patch_command_injection_shell_true(text: str, finding: dict) -> tuple[str, str] | None:
    lineno = finding["line"] - 1
    lines = text.splitlines(keepends=True)
    if lineno >= len(lines):
        return None
    line = lines[lineno]
    if "shell=True" not in line:
        return None
    new_line = line.replace(", shell=True", "").replace("shell=True, ", "").replace("shell=True", "")
    lines[lineno] = new_line
    return "".join(lines), (
        f"Removed `shell=True` on line {finding['line']}. The command now runs without a shell, "
        f"so shell metacharacters in its arguments cannot be reinterpreted as additional commands."
    )


def _patch_hardcoded_secret(text: str, finding: dict) -> tuple[str, str] | None:
    lineno = finding["line"] - 1
    lines = text.splitlines(keepends=True)
    if lineno >= len(lines):
        return None
    line = lines[lineno]
    m = re.match(r"^(\s*)([A-Z_][A-Z0-9_]*)\s*=\s*['\"][^'\"]+['\"]\s*$", line.rstrip("\n"))
    if not m:
        return None
    indent, var_name = m.groups()
    new_line = f'{indent}{var_name} = os.environ.get("{var_name}", "")\n'
    lines[lineno] = new_line
    needs_import = "import os" not in text
    new_text = "".join(lines)
    if needs_import:
        new_text = "import os\n" + new_text
    return new_text, (
        f"Replaced the hardcoded value of `{var_name}` on line {finding['line']} with a lookup from the "
        f"`{var_name}` environment variable. Set it in your deployment environment or a local `.env` file "
        f"(never commit the real value)."
    )


def _patch_debug_true(text: str, finding: dict) -> tuple[str, str] | None:
    lineno = finding["line"] - 1
    lines = text.splitlines(keepends=True)
    if lineno >= len(lines) or "DEBUG" not in lines[lineno]:
        return None
    lines[lineno] = re.sub(r"True", "False", lines[lineno])
    return "".join(lines), f"Set `DEBUG = False` on line {finding['line']}."


PATCH_GENERATORS = {
    "sql_injection": [_patch_sql_fstring],
    "command_injection": [_patch_command_injection_shell_true],
    "hardcoded_secret": [_patch_hardcoded_secret],
    "insecure_configuration": [_patch_debug_true],
}


def can_generate_patch(finding: dict) -> bool:
    if finding["type"] not in PATCH_GENERATORS:
        return False
    if "cors" in finding.get("title", "").lower() or "wildcard" in finding.get("title", "").lower():
        return False
    return True


def generate_patch(root: str, repo_id: str, finding: dict) -> Patch:
    generators = PATCH_GENERATORS.get(finding["type"])
    if not generators:
        raise PatchError("No safe automatic patch pattern is available for this finding type.")

    root_path = Path(root).resolve()
    full_path = (root_path / finding["file"].replace("\\", "/")).resolve()
    if full_path == root_path or root_path not in full_path.parents:
        raise PatchError("The patch target is outside the repository workspace.")
    if not os.path.isfile(full_path):
        raise PatchError("The target file no longer exists in the repository workspace.")

    with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
        original_text = fh.read()

    for generator in generators:
        result = generator(original_text, finding)
        if result is not None:
            new_text, explanation = result
            diff = _diff(original_text, new_text, finding["file"])
            if not diff.strip():
                continue
            return Patch(
                id=new_id("patch"),
                repo_id=repo_id,
                finding_id=finding["id"],
                file=finding["file"],
                diff=diff,
                explanation=explanation,
                base_file_hash=file_hash(full_path),
                changed_files=[finding["file"]],
                changed_lines=sum(1 for l in diff.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))),
                safety_checks=[
                    "Single-file change only",
                    "Base file hash recorded to detect concurrent edits",
                    "Target path resolved inside repository workspace",
                    "Original file backed up before atomic replacement",
                    "Temporary file validated before replacement",
                    "Python syntax verified after apply" if finding["file"].endswith(".py") else "Syntax check not applicable",
                ],
                new_content=new_text,
                patch_type="deterministic",
                patch_source=finding.get("rule_ids", ["builtin-rule"])[0],
            )

    raise PatchError("The matched code did not fit a known-safe rewrite shape closely enough to patch automatically.")


def apply_patch(root: str, patch: Patch) -> None:
    root_path = Path(root).resolve()
    full_path = (root_path / patch.file.replace("\\", "/")).resolve()
    if full_path == root_path or root_path not in full_path.parents:
        raise PatchError("The patch target is outside the repository workspace.")
    if not os.path.isfile(full_path):
        raise PatchError("The target file no longer exists in the repository workspace.")

    current_hash = file_hash(full_path)
    if current_hash != patch.base_file_hash:
        raise PatchError(
            "The file changed since this patch was generated (hash mismatch). "
            "Regenerate the patch against the current file before applying."
        )

    backup_dir = root_path / ".clankershield" / "backups"
    os.makedirs(backup_dir, exist_ok=True)
    backup_name = f"{patch.id}.{patch.file.replace(os.sep, '__').replace('/', '__')}.bak"
    backup_path = backup_dir / backup_name
    shutil.copy2(full_path, backup_path)
    mode = full_path.stat().st_mode
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=full_path.parent, prefix=f".{full_path.name}.", suffix=".clanker-temp", delete=False) as handle:
            temporary_name = handle.name
            handle.write(patch.new_content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode)
        if str(full_path).endswith(".py"):
            compile(patch.new_content, patch.file, "exec")
        elif str(full_path).endswith(".json"):
            import json
            json.loads(patch.new_content)
        os.replace(temporary_name, full_path)
    except SyntaxError as exc:
        raise PatchError(f"The patched Python file failed syntax validation: {exc}")
    except (OSError, ValueError) as exc:
        raise PatchError(f"The patched file failed validation or atomic replacement: {exc}")
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    patch.new_hash = file_hash(str(full_path))
    patch.backup_path = os.path.relpath(backup_path, root_path)


def rollback_patch(root: str, patch: Patch) -> None:
    if patch.status != "applied":
        raise PatchError("Only an applied patch can be rolled back.")
    root_path = Path(root).resolve()
    full_path = (root_path / patch.file.replace("\\", "/")).resolve()
    backup_path = (root_path / patch.backup_path.replace("\\", "/")).resolve() if patch.backup_path else None
    if full_path == root_path or root_path not in full_path.parents or not backup_path or root_path not in backup_path.parents:
        raise PatchError("The rollback target is outside the repository workspace.")
    if not backup_path.is_file():
        raise PatchError("The patch backup is unavailable; rollback cannot be performed safely.")
    if not full_path.is_file() or file_hash(str(full_path)) != patch.new_hash:
        raise PatchError("The file changed after the patch was applied; refusing to overwrite later edits.")
    mode = full_path.stat().st_mode
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=full_path.parent, prefix=f".{full_path.name}.", suffix=".rollback-temp", delete=False) as handle:
            temporary_name = handle.name
            handle.write(backup_path.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, full_path)
    except OSError as exc:
        raise PatchError(f"Rollback could not atomically restore the original file: {exc}")
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    patch.status = "rolled_back"
    patch.verification_status = "NOT_RUN"
