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
