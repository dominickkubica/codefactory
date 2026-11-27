"""The golden-repository diff (tools/golden.py): what a change added, removed or moved on the pinned repositories."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import golden  # noqa: E402


class GoldenTest(unittest.TestCase):
    def test_locations_keep_findings_and_hints_and_skip_counts(self):
        export = {
            "findings": [{"title": "Swallowed errors (2)", "severity": "Medium", "locations": ["`a.py:3` x", "…and 4 more"]}],
            "hints": [{"title": "SQL assembled from strings (1)", "severity": "Low", "locations": ["`b.py:9` y"]}],
        }
        got = golden.locations(export)
        self.assertEqual(sorted(v["tier"] for v in got.values()), ["findings", "hints"])
        self.assertTrue(all(not v["location"].startswith("…") for v in got.values()))

    def test_compare_reports_added_removed_and_moved(self):
        import json
        import tempfile

        before = {"k1": {"tier": "findings", "severity": "High"}, "k2": {"tier": "findings", "severity": "Low"}}
        with tempfile.TemporaryDirectory() as d:
            snap = Path(d) / "s.json"
            snap.write_text(json.dumps({"locations": before}), encoding="utf-8")
            now = {"k1": {"tier": "hints", "severity": "Medium"}, "k3": {"tier": "findings", "severity": "Low"}}
            got = golden.compare("r", {"snapshot": snap}, now)
        self.assertEqual((got["added"], got["removed"], got["moved"]), (["k3"], ["k2"], ["k1"]))


if __name__ == "__main__":
    unittest.main()
