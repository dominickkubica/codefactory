"""Measured coverage from lcov, Istanbul and coverage.py reports decides which functions tests ran."""

import json
import tempfile
import unittest
from pathlib import Path

from codefactory.coverage import measured

FUNCS = [
    {"id": "app/a.py::ran", "file": "app/a.py", "kind": "function", "line": 1, "end": 3},
    {"id": "app/a.py::defined_only", "file": "app/a.py", "kind": "function", "line": 5, "end": 7},
    {"id": "app/a.py::one_liner", "file": "app/a.py", "kind": "function", "line": 9, "end": 9},
]


class CoverageTest(unittest.TestCase):
    def check(self, name: str, text: str) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text.replace("ROOT", d.replace("\\", "/")), encoding="utf-8")
            cov = measured(root, FUNCS)
        self.assertEqual(cov.source, name)
        # the def line of defined_only ran (import), its body didn't: not covered
        self.assertEqual(cov.covered, {"app/a.py::ran", "app/a.py::one_liner"})
        self.assertIn("app/a.py", cov.seen)

    def test_lcov(self):
        self.check("coverage/lcov.info", "SF:ROOT/app/a.py\nDA:1,1\nDA:2,4\nDA:5,1\nDA:6,0\nDA:9,2\nend_of_record\n")

    def test_istanbul(self):
        stmt = lambda a, b: {"start": {"line": a}, "end": {"line": b}}  # noqa: E731
        data = {"ROOT/app/a.py": {"path": "ROOT/app/a.py", "statementMap": {"0": stmt(2, 2), "1": stmt(6, 6), "2": stmt(9, 9)},
                                  "s": {"0": 3, "1": 0, "2": 1}}}  # fmt: skip
        self.check("coverage/coverage-final.json", json.dumps(data))

    def test_coverage_py(self):
        data = {"meta": {"version": "7"}, "files": {"app/a.py": {"executed_lines": [1, 2, 5, 9]}}}
        self.check("coverage.json", json.dumps(data))

    def test_no_report(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(measured(Path(d), FUNCS))


if __name__ == "__main__":
    unittest.main()
