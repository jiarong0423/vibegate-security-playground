"""Minimum-version syntax guard; not proof of Python 3.11 runtime support."""

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CompatibilityTests(unittest.TestCase):
    def test_project_python_uses_python311_grammar(self):
        paths = sorted(
            path
            for directory in ("src", "tests", "tools")
            for path in (ROOT / directory).rglob("*.py")
        )
        self.assertTrue(paths, "No project Python files found")
        for path in paths:
            with self.subTest(path=str(path.relative_to(ROOT))):
                ast.parse(
                    path.read_bytes(),
                    filename=str(path),
                    feature_version=(3, 11),
                )

    def test_runner_locks_aws_to_ignored_project_local_paths(self):
        runner = (ROOT / "tools/python.sh").read_text()
        for setting in (
            'AWS_CONFIG_FILE="$ROOT/.aws/config"',
            'AWS_SHARED_CREDENTIALS_FILE="$ROOT/.aws/credentials"',
            'AWS_LOGIN_CACHE_DIRECTORY="$ROOT/.aws/login/cache"',
            'AWS_PROFILE="vibegate-dev"',
            'AWS_EC2_METADATA_DISABLED="true"',
            "AWS_ACCESS_KEY_ID-",
            "AWS_WEB_IDENTITY_TOKEN_FILE-",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI-",
        ):
            self.assertIn(setting, runner)
        ignored = (ROOT / ".gitignore").read_text().splitlines()
        for pattern in (".aws/", "credentials", "*.pem", "*.key", "*.p12", "*.pfx"):
            self.assertIn(pattern, ignored)
