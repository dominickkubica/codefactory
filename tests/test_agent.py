"""The commands an AI coding agent uses: brief, context, flags --json, the skill installer, and the cache."""

import io
import json
import os
import shutil
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from codefactory.brief import brief_markdown, context_data, context_markdown
from codefactory.cache import fingerprint, load_cached
from codefactory.cli import build, load_graph, main

SHOP = Path(__file__).parent / "fixtures" / "shop"


def run(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class AgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = build(SHOP).to_dict()

    def test_brief(self):
        text = brief_markdown(self.graph)
        for part in (
            "# Code map: shop",
            "## Layers",
            "| api |",
            "## Import loops and layer violations",
            "## Database, file or network calls inside loops",
            "## Copied code",
            "`shop/api/reports.py:6`",
            "codefactory context",
        ):
            self.assertIn(part, text)
        self.assertIn("~", text.split("## Copied code")[1])  # lines saved by merging

    def test_context_function(self):
        c = context_data(self.graph, "total")
        self.assertEqual(c["kind"], "function")
        self.assertEqual(c["file"], "shop/core/pricing.py")
        self.assertEqual({x["id"] for x in c["callers"]}, {"shop/api/routes.py::checkout", "shop/core/tax.py::preview"})
        self.assertGreaterEqual(c["impact"]["functions"], 2)
        self.assertIn("## Called by (2)", context_markdown(self.graph, "total"))

    def test_context_file_and_errors(self):
        c = context_data(self.graph, "shop/db/sql.py")
        self.assertEqual(c["kind"], "file")
        self.assertEqual([f["name"] for f in c["functions"]], ["connect", "get_order", "save_line"])
        self.assertIn("shop/api/reports.py", c["imported_by"])
        self.assertIn("error", context_data(self.graph, "no_such_thing"))
        self.assertIn("matches", context_data(self.graph, "__init__.py"))  # ambiguous: lists the options

    def test_flags_json_has_file_and_line(self):
        code, out = run("flags", str(SHOP), "--json", "--kind", "io_in_loop", "--no-cache")
        items = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(items and all(i["kind"] == "io_in_loop" and i["file"] and i["line"] for i in items))

    def test_names_without_a_repo_path_use_the_current_folder(self):
        cwd = os.getcwd()
        try:
            os.chdir(SHOP)
            code, out = run("context", "get_order", "--json", "--no-cache")
        finally:
            os.chdir(cwd)
        self.assertEqual(json.loads(out)["file"], "shop/db/sql.py")

    def test_skill_installs(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = run("skill", d)
            text = (Path(d) / ".claude" / "skills" / "codefactory" / "SKILL.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith("---\nname: codefactory\ndescription: "))
        self.assertIn("codefactory context", text)

    def test_cache_reused_until_a_file_changes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "shop"
            shutil.copytree(SHOP, root, ignore=shutil.ignore_patterns(".codefactory"))
            first = load_graph(root)
            self.assertIsNotNone(load_cached(root, [".codefactory"]))
            self.assertTrue((root / ".codefactory" / ".gitignore").is_file())
            before = fingerprint(root, [".codefactory"])
            time.sleep(0.01)
            (root / "shop" / "core" / "tax.py").write_text("def tax_for(a):\n    return a\n", encoding="utf-8")
            self.assertNotEqual(before, fingerprint(root, [".codefactory"]))
            self.assertIsNone(load_cached(root, [".codefactory"]))
            second = load_graph(root)
            self.assertNotEqual(len(first["flags"]), len(second["flags"]))  # the loop through tax.py is gone


if __name__ == "__main__":
    unittest.main()
