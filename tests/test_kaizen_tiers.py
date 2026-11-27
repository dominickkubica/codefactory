"""Confidence tiers: a check's lower-confidence locations move to a hint of the same title, the rest stay counted."""

import unittest

from codefactory import tiers
from codefactory.review import Finding


def finding(title, evidence, more=0):
    return Finding(title, "High", "Security", evidence, "impact", "fix", "S", more)


class TiersTest(unittest.TestCase):
    def test_lower_confidence_locations_become_a_hint(self):
        f = finding("Raw HTML injected into pages", [
            "`a.py:1` mark_safe(x)  (no endpoint reaches it)",
            "`views.py:9` mark_safe(page.body)  ← reached from `GET /p → page`",
        ])  # fmt: skip
        keep, lower = tiers.split([f])
        self.assertEqual([k.evidence for k in keep], [["`views.py:9` mark_safe(page.body)  ← reached from `GET /p → page`"]])
        self.assertEqual(len(lower), 1)
        self.assertEqual((lower[0].title, lower[0].severity), ("Raw HTML injected into pages", "Medium"))
        self.assertEqual(lower[0].data["tier"], "lower")

    def test_all_lower_leaves_no_finding_and_other_checks_are_untouched(self):
        keep, lower = tiers.split([
            finding("Raw HTML injected into pages", ["`a.py:1` x  (no endpoint reaches it)"]),
            finding("SQL assembled from strings", ["`b.py:2` q  (no endpoint reaches it)"]),
        ])  # fmt: skip
        self.assertEqual([k.title for k in keep], ["SQL assembled from strings"])
        self.assertEqual([h.title for h in lower], ["Raw HTML injected into pages"])

    def test_a_finding_with_more_locations_than_shown_keeps_them(self):
        keep, lower = tiers.split([finding("Raw HTML injected into pages", ["`a.py:1` x  (no endpoint reaches it)"], more=4)])
        self.assertEqual((len(keep), keep[0].evidence, keep[0].more), (1, [], 4))


if __name__ == "__main__":
    unittest.main()
