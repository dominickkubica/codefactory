"""Silencing, the baseline ratchet, and the plan with its fix prompts."""
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from codefactory.cli import build, main
from codefactory.plan import make_plan
from tests.test_rules import project

SHOP = Path(__file__).parent / "fixtures" / "shop"


def run(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class SilenceTest(unittest.TestCase):
    def test_comment_forms_and_toml(self):
        root = project({
            "factory.toml": '[[silence]]\nkind = "unused"\nwhere = "app/legacy.py"\nreason = "kept for the old API"\n',
            "app/a.py": """
                def dead_one():  # codefactory: ignore unused — called by the plugin loader
                    return 1

                # codefactory: ignore unused: by name from config
                def dead_two():
                    return 2

                def dead_three():
                    return 3

                # codefactory: ignore duplicate
                def dead_four():
                    return 4
            """,
            "app/legacy.py": "def old():\n    return 0\n",
            "app/gen.py": "# codefactory: ignore-file — generated\ndef made():\n    return 5\n",
        })
        g = build(root)
        live = {f.target for f in g.flags if f.kind == "unused"}
        quiet = {f.target: f.reason for f in g.silenced}
        self.assertEqual(live, {"app/a.py::dead_three", "app/a.py::dead_four"})  # wrong kind doesn't silence
        self.assertEqual(quiet["app/a.py::dead_one"], "called by the plugin loader")
        self.assertEqual(quiet["app/a.py::dead_two"], "by name from config")
        self.assertEqual(quiet["app/legacy.py::old"], "kept for the old API")
        self.assertEqual(quiet["app/gen.py::made"], "generated")
        code, out = run("flags", str(root), "--silenced", "--no-cache")
        self.assertIn("silenced: called by the plugin loader", out)


class BaselineTest(unittest.TestCase):
    def test_ratchet(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "shop"
            shutil.copytree(SHOP, root, ignore=shutil.ignore_patterns(".codefactory"))
            self.assertEqual(run("check", str(root))[0], 1)  # no baseline: the import loop (high) fails
            code, out = run("baseline", str(root))
            self.assertEqual(code, 0)
            self.assertTrue((root / "codefactory-baseline.json").is_file())
            code, out = run("check", str(root))
            self.assertEqual(code, 0, out)
            self.assertIn("OK: 0 new", out)
            # a new copy-pasted N+1 appears
            (root / "shop" / "api" / "more.py").write_text(
                "from shop.db.sql import get_order\n\n\ndef again(conn, ids):\n    return [get_order(conn, i) for i in ids]\n",
                encoding="utf-8")
            code, out = run("check", str(root))
            self.assertEqual(code, 1)
            self.assertIn("shop/api/more.py:5", out)
            self.assertIn("io_in_loop", run("flags", str(root), "--new")[1])
            # fixing an old issue is reported, not failed
            (root / "shop" / "api" / "more.py").unlink()
            (root / "shop" / "api" / "routes.py").write_text(
                (root / "shop" / "api" / "routes.py").read_text().replace('def legacy_export():\n    return "never called"\n', ""),
                encoding="utf-8")
            code, out = run("check", str(root))
            self.assertEqual(code, 0, out)
            self.assertIn("1 fixed since the baseline", out)


class PlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = make_plan(build(SHOP).to_dict())

    def test_ranked_and_grouped(self):
        kinds = [t["kind"] for t in self.tasks]
        self.assertEqual(kinds[0], "cycle")  # the import loop first
        self.assertEqual(kinds.count("cycle"), 1)  # one loop of two files = one task
        merge = next(t for t in self.tasks if t["kind"] == "duplicate")
        self.assertIn("Merge 2 copies", merge["title"])
        self.assertEqual(len(merge["where"]), 2)
        batch = next(t for t in self.tasks if t["kind"] == "io_in_loop" and "order_report" in t["title"])
        self.assertTrue(any("get_orderMany" in s for s in batch["steps"]))  # batching advice names the function
        self.assertEqual(sum(1 for t in self.tasks if t["kind"] == "unused"), 1)  # dead code is one cleanup task

    def test_prompt_is_self_contained(self):
        t = next(t for t in self.tasks if t["kind"] == "duplicate")
        for part in ("Task (codefactory plan", "Why:", "Where:", "Steps:", "Constraints:", "Done when:",
                     "`shop/core/pricing.py:"):
            self.assertIn(part, t["prompt"])

    def test_cli(self):
        code, out = run("plan", str(SHOP), "--top", "3", "--no-cache")
        self.assertIn("## 1. Break the import loop", out)
        task_id = out.split("`")[3]  # the first task's id
        self.assertEqual(run("prompt", str(SHOP), task_id)[1], run("prompt", str(SHOP), "1")[1])
        self.assertEqual(len(json.loads(run("plan", str(SHOP), "--json", "--top", "2")[1])), 2)
        with self.assertRaises(SystemExit):
            run("prompt", str(SHOP), "zzzzzz")


if __name__ == "__main__":
    unittest.main()
