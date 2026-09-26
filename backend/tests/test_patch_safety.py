import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import patches


def test_patch_apply_is_atomic_and_rollback_restores_exact_content():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "worker.py")
        original = "import subprocess\nsubprocess.call(cmd, shell=True)\n"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(original)
        finding = {
            "id": "finding_test",
            "type": "command_injection",
            "file": "worker.py",
            "line": 2,
            "title": "Subprocess call uses shell=True",
        }
        patch = patches.generate_patch(root, "repo_test", finding)
        patches.apply_patch(root, patch)
        assert patch.new_hash
        assert patch.backup_path
        with open(path, encoding="utf-8") as handle:
            assert "shell=True" not in handle.read()
        patch.status = "applied"
        patches.rollback_patch(root, patch)
        with open(path, encoding="utf-8") as handle:
            assert handle.read() == original


def test_cors_and_dependency_patches_are_not_fabricated():
    cors = {"type": "insecure_configuration", "title": "Wildcard CORS origin"}
    dependency = {"type": "outdated_dependency", "title": "Outdated dependency"}
    assert not patches.can_generate_patch(cors)
    assert not patches.can_generate_patch(dependency)
