"""The measurement tools measure the code they're told to: tools/corpus.py's export_with, and phase timings."""

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


class ExportWithTest(unittest.TestCase):
    def test_a_folder_without_codefactory_is_refused(self):
        # `python -c` imports from the folder it runs in, ahead of PYTHONPATH: heldout.py once measured the working
        # tree instead of the commit it was given. export_with asserts which codefactory was imported.
        from corpus import export_with

        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
            done = export_with(Path(d), repo, Path(d) / "out.json", Path(d) / "out.prof", timeout=120)
            self.assertNotEqual(done.returncode, 0)
            self.assertFalse((Path(d) / "out.json").exists())

    def test_this_checkout_is_accepted(self):
        from corpus import export_with

        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            done = export_with(ROOT, repo, Path(d) / "out.json", Path(d) / "out.prof", timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr[-400:])
            self.assertIn("timings", (Path(d) / "out.prof").read_text(encoding="utf-8"))


class TimingTest(unittest.TestCase):
    def test_phases_add_up_and_sort_slowest_first(self):
        from codefactory import timing

        timing.reset()
        with timing.phase("fast"):
            pass
        for _ in range(2):
            with timing.phase("slow"):
                time.sleep(0.01)
        got = timing.report()
        self.assertEqual(list(got), ["slow", "fast"])
        self.assertGreaterEqual(got["slow"], 0.02)
        timing.reset()


if __name__ == "__main__":
    unittest.main()
