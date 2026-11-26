"""Test code in the results: copies between tests are a lead, not a task, and `--no-tests` / `tests = false` leaves
test code out of findings, the plan and the map (still counted for coverage). From a Go repository whose early,
not yet table-driven tests filled the plan with "share one body" tasks."""

import contextlib
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.cli import build, main
from codefactory.plan import make_plan
from codefactory.review import Review
from codefactory.scope import without_tests

BODY = """
    store = make_store()
    store.put("a", 1)
    store.put("b", 2)
    blobs = store.list()
    if len(blobs) != 2:
        raise AssertionError(blobs)
    store.sweep(keep={"a"})
    if store.list() != ["a"]:
        raise AssertionError(store.list())
    return store
"""


def project() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "gc").mkdir()
    (root / "gc" / "store.py").write_text(
        textwrap.dedent("""
        class Store:
            def __init__(self):
                self.items = {}

            def put(self, k, v):
                self.items[k] = v

            def list(self):
                return sorted(self.items)

            def sweep(self, keep):
                self.items = {k: v for k, v in self.items.items() if k in keep}


        def make_store():
            return Store()
        """),
        encoding="utf-8",
    )
    tests = "from gc.store import make_store\n\n"
    for name in ("test_sweep_unreferenced", "test_no_locker_skips_validation", "test_lock_validation_allows_sweep"):
        tests += f"\ndef {name}():{BODY}\n"
    (root / "tests").mkdir()
    (root / "tests" / "test_gc.py").write_text(tests, encoding="utf-8")
    return root


def run(*args: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        main(list(args))
    return out.getvalue()


class TestCopiesTest(unittest.TestCase):
    def test_copies_between_tests_are_info_and_not_plan_tasks(self):
        g = build(project(), cache=False).to_dict()
        copies = [f for f in g["flags"] if f["kind"] in ("duplicate", "similar")]
        self.assertTrue(copies)  # still found: a lead worth knowing about
        self.assertTrue(all(f["severity"] == "info" for f in copies))
        self.assertIn("table-driven", copies[0]["message"])
        self.assertFalse([t for t in make_plan(g) if "Share one body" in t["title"] or "Merge" in t["title"]])

    def test_no_tests_leaves_test_code_out_but_keeps_coverage(self):
        root = project()
        flags = json.loads(run("flags", str(root), "--json", "--no-tests"))
        self.assertFalse([f for f in flags if "tests/" in f.get("file", f.get("target", ""))])
        g = without_tests(build(root, cache=False).to_dict())
        self.assertFalse([f for f in g["files"] if f["id"].startswith("tests/")])
        self.assertTrue(g["tests"]["files"])
        r = Review(g, root)
        r.run()
        self.assertIsNone(next((f for f in r.findings if f.title == "No automated tests"), None))
        self.assertGreater(r.test_pct, 0)  # what the hidden tests reach still counts

    def test_factory_toml_can_turn_tests_off(self):
        root = project()
        (root / "factory.toml").write_text("tests = false\n", encoding="utf-8")
        flags = json.loads(run("flags", str(root), "--json"))
        self.assertFalse([f for f in flags if "tests/" in json.dumps(f)])
        (root / "factory.toml").write_text('tests = "no"\n', encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(main(["flags", str(root)]), 0)  # a typo is said, not ignored


if __name__ == "__main__":
    unittest.main()
