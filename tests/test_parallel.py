"""Per-file analysis gives the same graph on many processes, from the per-file cache, and in one process."""

import shutil
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from codefactory.analyzers import parallel
from codefactory.analyzers.python import analyze_python

SHOP = Path(__file__).parent / "fixtures" / "shop"


def snapshot(g) -> dict:
    d = asdict(g)
    return {k: sorted(map(str, d[k])) for k in ("files", "functions", "edges", "sites")}


class ParallelTest(unittest.TestCase):
    def test_pool_cache_and_single_process_agree(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "shop"
            shutil.copytree(SHOP, root)
            single = snapshot(analyze_python(root, [], cache=False))
            with mock.patch.object(parallel, "MIN_PARALLEL", 1), mock.patch.object(parallel, "workers", return_value=2):
                pooled = snapshot(analyze_python(root, []))
            cached = snapshot(analyze_python(root, []))
            self.assertEqual(single, pooled)
            self.assertEqual(single, cached)
            self.assertTrue((root / ".codefactory" / "files-python.json").is_file())

    def test_jobs_setting(self):
        with mock.patch.dict("os.environ", {"CODEFACTORY_JOBS": "3"}):
            self.assertEqual(parallel.workers(), 3)


if __name__ == "__main__":
    unittest.main()
