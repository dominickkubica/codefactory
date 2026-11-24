"""The accuracy benchmark as a gate: no check may get worse on the labeled corpus (see tests/bench.py)."""

import json
import shutil
import unittest

from codefactory.analyzers.generic import available
from tests.bench import CORPUS, findings, score


@unittest.skipUnless(available() and shutil.which("node"), "needs the tree-sitter language pack and Node")
class BenchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.got = findings()
        cls.floors = json.loads((CORPUS / "floors.json").read_text(encoding="utf-8"))

    def test_no_check_gets_worse(self):
        for part in ("tuning", "holdout"):
            rows = score(part, self.got)
            tp = sum(r["tp"] for r in rows.values())
            fp = sum(r["fp"] for r in rows.values())
            fn = sum(r["fn"] for r in rows.values())
            wrong = [f"{w} {k}" for k, r in rows.items() for w in r["wrong"]]
            missed = [f"{w} {k}" for k, r in rows.items() for w in r["missed"] if f"{w} {k}" not in self.floors["known_misses"]]
            with self.subTest(part=part):
                self.assertEqual(wrong, [], "new false alarms")
                self.assertEqual(missed, [], "new misses")
                self.assertGreaterEqual(tp / (tp + fp), self.floors[part]["precision"])
                self.assertGreaterEqual(tp / (tp + fn), self.floors[part]["recall"])


if __name__ == "__main__":
    unittest.main()
