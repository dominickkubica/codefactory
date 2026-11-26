"""`codefactory export`: every finding as one audit file for an AI to triage into fixes, and the viewer's button."""

import contextlib
import io
import json
import re
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.cli import build, main
from codefactory.export import SEVERITIES, export

KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def project() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "app.py").write_text(
        textwrap.dedent(f'''
        import sqlite3
        import requests

        STRIPE = "{KEY}"


        def find(conn, name):
            return conn.execute(f"SELECT * FROM users WHERE name = '{{name}}'").fetchall()


        def remove(conn, ids):
            for i in ids:
                conn.execute("DELETE FROM users WHERE id = ?", (i,))
        '''),
        encoding="utf-8",
    )
    for n in range(9):  # more loops than the report lists (6): the export lists them all
        (root / f"job{n}.py").write_text(
            f"import requests\n\n\ndef fetch{n}(urls):\n    for u in urls:\n        requests.get(u, timeout=5)\n",
            encoding="utf-8",
        )
    (root / "scripts").mkdir()
    (root / "scripts" / "backfill.py").write_text(
        "import requests\n\n\ndef backfill(urls):\n    for u in urls:\n        requests.get(u, timeout=5)\n", encoding="utf-8"
    )
    return root


class ExportTest(unittest.TestCase):
    def test_each_location_shows_its_code_and_what_it_is(self):  # from a trial triage: every location opened by hand
        root = project()
        text = export(build(root, cache=False).to_dict(), root)
        self.assertIn("`job0.py:6` fetch0", text)
        self.assertRegex(text, r"`job0\.py:6` fetch0[^\n]* — `requests\.get\(u, timeout=5\)`")
        self.assertIn("`scripts/backfill.py:4` backfill *(script)* — `def backfill(urls):`", text)
        self.assertIn('`app.py:5` STRIPE = "sk_l…"\n', text)  # the line once, not again as its "code"
        self.assertRegex(text, r"(?m)^- `[0-9a-f]{6}` Batch the queries in fetch0: `job0\.py:6`$")  # one line per fix
        conf = set(re.findall(r"\| (exact|likely|lead) \|", text))
        self.assertTrue(conf <= {"exact", "likely", "lead"} and "exact" in conf and "lead" in conf)

    def test_markdown_audit_is_complete_and_sorted(self):
        root = project()
        text = export(build(root, cache=False).to_dict(), root)
        for part in ("# Code audit:", "## Instructions for the reader", "Triage the confirmed ones", "## Summary", "## Findings",
                     "**Verify:**", "**Suggested fix:**", "## What this audit didn't check"):  # fmt: skip
            self.assertIn(part, text)
        rows = re.findall(r"^\| (CF-\w+-\w{4}) \| (\w+) \| ([SML]) \|", text, re.M)
        self.assertTrue(rows)
        keys = [(SEVERITIES.index(sev), "SML".index(c)) for _, sev, c in rows]
        self.assertEqual(keys, sorted(keys))  # severity, then complexity
        self.assertEqual(len({i for i, _, _ in rows}), len(rows))  # ids are unique
        self.assertNotIn("4eC39Hq", text)  # a secret, cut to 4 characters like everywhere else
        section = text.split("· Queries or requests inside loops", 1)[1].split("\n### ", 1)[0]
        n1 = section.split("**Impact:**", 1)[0]
        self.assertEqual(sum(f"job{n}.py:" in n1 for n in range(9)), 9)  # every location, not the first six
        self.assertNotIn("more", n1)
        self.assertNotIn("Batch the writes", section)  # filed under the writes finding, not the N+1 one
        self.assertIn("Batch the writes in remove", text.split("· Writes inside loops in 1 place", 1)[1])

    def test_json_and_stable_ids(self):
        root = project()
        doc = json.loads(export(build(root, cache=False).to_dict(), root, as_json=True))
        self.assertEqual(set(doc) >= {"findings", "profile", "scope", "limits", "other_fixes"}, True)
        f = doc["findings"][0]
        self.assertEqual(set(f) >= {"id", "severity", "complexity", "area", "confidence", "locations", "fix", "verify"}, True)
        (root / "job9.py").write_text((root / "job0.py").read_text().replace("fetch0", "fetch9"), encoding="utf-8")
        again = json.loads(export(build(root, cache=False).to_dict(), root, as_json=True))
        loops = lambda d: next(x["id"] for x in d["findings"] if "inside loops" in x["title"])  # noqa: E731
        self.assertEqual(loops(doc), loops(again))  # 9 places or 10: the same finding, the same id

    def test_default_files_are_named_and_dated(self):
        import os
        from unittest import mock

        root, cwd = project(), os.getcwd()
        here = tempfile.mkdtemp()
        os.chdir(here)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as printed, contextlib.redirect_stderr(io.StringIO()):
                main(["export", str(root)])
                with mock.patch("sys.stdout.isatty", return_value=True):
                    main(["review", str(root)])
            names = sorted(os.listdir(here))
            self.assertRegex(names[0], r"^codefactory-audit-\d{4}-\d{2}-\d{2}-\d{4}\.md$")
            self.assertRegex(names[1], r"^codefactory-review-\d{4}-\d{2}-\d{2}-\d{4}\.md$")
            self.assertNotIn(":", "".join(names))  # Windows can't have one in a file name
            self.assertIn("Wrote codefactory-review-", printed.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as piped, contextlib.redirect_stderr(io.StringIO()):
                main(["review", str(root)])  # not a terminal (a pipe, Claude Code): the text, as before
            self.assertTrue(piped.getvalue().startswith("# Technical review"))
            with contextlib.redirect_stdout(io.StringIO()) as start:
                self.assertEqual(main([]), 0)
            self.assertIn("codefactory review", start.getvalue())
        finally:
            os.chdir(cwd)

    def test_cli_and_viewer_button(self):
        root = project()
        out = Path(tempfile.mkdtemp()) / "audit.md"
        with contextlib.redirect_stdout(io.StringIO()) as printed, contextlib.redirect_stderr(io.StringIO()):
            main(["export", str(root), "-o", str(out)])
        self.assertIn("triage", printed.getvalue())
        self.assertTrue(out.read_text(encoding="utf-8").startswith("# Code audit:"))
        page = Path(tempfile.mkdtemp()) / "factory.html"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            main(["view", str(root), "-o", str(page), "--no-open"])
        html = page.read_text(encoding="utf-8")
        self.assertIn('id="export"', html)
        self.assertIn('window.AUDIT = "# Code audit:', html)
        self.assertNotIn("</script>\\n", html.split("window.AUDIT", 1)[1].split("</script>", 1)[0])


if __name__ == "__main__":
    unittest.main()
