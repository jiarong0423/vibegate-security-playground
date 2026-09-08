import importlib.util
import os
from pathlib import Path
import shutil
# Isolated local Git integration test only.
import subprocess  # nosec B404
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_guard", ROOT / "tools/release_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ReleaseGuardTests(unittest.TestCase):
    def entries(self):
        return [("100644", "blob", "a" * 40, 10, name) for name in guard.REQUIRED]

    def test_required_tree_is_accepted_for_scanning(self):
        guard.validate_tree(self.entries())

    def test_private_paths_block(self):
        for name in (".env", "logs/private.md", ".aws/credentials", "output/raw.json", "other.py"):
            with self.subTest(name=name), self.assertRaises(guard.Blocked):
                guard.validate_tree(self.entries() + [("100644", "blob", "a" * 40, 10, name)])

    def test_missing_evidence_blocks(self):
        with self.assertRaises(guard.Blocked):
            guard.validate_tree(self.entries()[1:])

    def test_symlink_blocks(self):
        with self.assertRaises(guard.Blocked):
            guard.validate_tree(self.entries() + [("120000", "blob", "a" * 40, 10, "README.md")])

    def test_oversized_file_blocks(self):
        with self.assertRaises(guard.Blocked):
            guard.validate_tree(self.entries() + [("100644", "blob", "a" * 40, 250001, "README.md")])

    def test_malformed_push_blocks(self):
        with self.assertRaises(guard.Blocked):
            guard.revisions_for_push(ROOT, ["bad input"])

    def test_tags_block(self):
        with self.assertRaises(guard.Blocked):
            guard.revisions_for_push(ROOT, [f"refs/tags/v1 {'a'*40} refs/tags/v1 {'0'*40}"])

    def test_all_history_is_scanned(self):
        with patch.object(guard, "run", return_value=b"old\nnew\n") as run:
            result = guard.revisions_for_push(ROOT, [f"refs/heads/main {'a'*40} refs/heads/main {'b'*40}"])
        self.assertEqual(result, ["new", "old"])
        self.assertEqual(run.call_args.args[0], ["git", "rev-list", "a"*40])

    def test_failed_scanner_blocks_without_printing_raw_output(self):
        response = subprocess.CompletedProcess([], 1, b"private", b"private")
        with patch.object(guard.subprocess, "run", return_value=response), patch.object(guard.shutil, "which", return_value="/scanner"):
            with self.assertRaises(guard.Blocked) as caught:
                guard.run(["scanner"], cwd=ROOT)
        self.assertNotIn("private", str(caught.exception))

    def test_real_push_to_local_bare_repo_is_blocked(self):
        with TemporaryDirectory(prefix="vibegate-hook-test-") as temp:
            source = Path(temp) / "source"
            remote = Path(temp) / "remote.git"
            source.mkdir()

            def git(*args, cwd=source, check=True, env=None):
                executable = shutil.which("git")
                self.assertIsNotNone(executable)
                # Fixed test arguments, only disposable repositories, no shell.
                return subprocess.run([executable, *args], cwd=cwd, capture_output=True,  # nosec B603
                                      check=check, env=env)

            git("init", "-b", "main")
            git("init", "--bare", str(remote))
            git("config", "user.name", "Local Test")
            git("config", "user.email", "test@example.invalid")
            (source / "README.md").write_text("Synthetic test only\n")
            git("add", "README.md")
            git("commit", "-m", "Synthetic test")
            for name in (".githooks/pre-push", "tools/python.sh", "tools/release_guard.py"):
                dest = source / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dest)
            (source / ".githooks/pre-push").chmod(0o755)
            git("config", "core.hooksPath", ".githooks")
            env = os.environ.copy()
            env["VIBEGATE_PLAYGROUND_PYTHON_BIN"] = sys.executable
            result = git("push", str(remote), "main", check=False, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"publication BLOCKED", result.stderr)
            self.assertEqual(git("for-each-ref", cwd=remote).stdout, b"")


if __name__ == "__main__":
    unittest.main()
