"""`codefactory accept` records an intended finding in factory.toml; every command, the review included, honours it."""

import contextlib
import io
import tempfile
import tomllib
import unittest
from pathlib import Path

from codefactory.cli import build, main
from codefactory.review import review_markdown


def run(*argv: str) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(list(argv))


class AcceptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text(
            'def tables(conn, t):\n    return conn.execute(f"SELECT * FROM {t}")\n\n\ndef helper():\n    return 1\n',
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_review_finding(self):
        self.assertIn("SQL assembled from strings", review_markdown(build(self.root, cache=False).to_dict(), self.root))
        self.assertEqual(run("accept", str(self.root), "sql_built", "app.py:2", "--why", 'checked "t" against TABLES'), 0)
        rules = tomllib.loads((self.root / "factory.toml").read_text(encoding="utf-8"))["silence"]
        self.assertEqual(rules, [{"kind": "sql_built", "where": "app.py", "reason": 'checked "t" against TABLES'}])
        self.assertNotIn("SQL assembled from strings", review_markdown(build(self.root, cache=False).to_dict(), self.root))

    def test_a_plan_task(self):
        self.assertIn(("unused", "app.py::helper"), {(f.kind, f.target) for f in build(self.root, cache=False).flags})
        self.assertEqual(run("accept", str(self.root), "1", "--why", "kept for the plugin API"), 0)
        g = build(self.root, cache=False)
        self.assertNotIn(("unused", "app.py::helper"), {(f.kind, f.target) for f in g.flags})
        # the task covers every unused function in the file: each is silenced, with the reason
        self.assertEqual({f.reason for f in g.silenced if f.kind == "unused"}, {"kept for the plugin API"})
        self.assertIn("app.py::helper", {f.target for f in g.silenced})

    def test_typos_are_refused(self):
        self.assertEqual(run("accept", str(self.root), "sql_bulit", "app.py", "--why", "x"), 2)
        self.assertFalse((self.root / "factory.toml").exists())


if __name__ == "__main__":
    unittest.main()
