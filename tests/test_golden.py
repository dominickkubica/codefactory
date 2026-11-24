"""Every finding on the fixture apps, compared with a saved snapshot (tests/golden/*.txt).

A change to what codefactory reports, however small, fails here until it's looked at: run
    CODEFACTORY_UPDATE_GOLDEN=1 python -m unittest tests.test_golden
and review the diff of tests/golden/ like any other change. Most of codefactory's bugs were findings that moved
silently; this makes them visible.
"""

import os
import unittest
from pathlib import Path

from codefactory.analyzers.generic import available as generic_available
from codefactory.cli import build
from tests.test_typescript import available as ts_available

HERE = Path(__file__).parent
FIXTURES = {"shop": lambda: True, "tsapp": ts_available, "polyglot": generic_available}


def snapshot(name: str) -> str:
    g = build(HERE / "fixtures" / name, cache=False)
    lines = [f"layers: {' | '.join(g.layers)}"]
    lines += [f"layer {f.id}: {f.layer}" for f in sorted(g.files, key=lambda f: f.id)]
    edges = sorted(f"{e.kind} {e.src} -> {e.dst}" for e in g.edges)
    lines += [f"edge {e}" for e in edges]
    lines += sorted(f"flag {f.severity} {f.kind} {f.target}:{f.line} {f.message}" for f in g.flags)
    return "\n".join(lines) + "\n"


class GoldenTest(unittest.TestCase):
    def test_fixtures_match_their_snapshots(self):
        for name, ready in FIXTURES.items():
            with self.subTest(name):
                if not ready():
                    self.skipTest(f"{name}: its analyzer isn't available here")
                path = HERE / "golden" / f"{name}.txt"
                got = snapshot(name)
                if os.environ.get("CODEFACTORY_UPDATE_GOLDEN"):
                    path.write_text(got, encoding="utf-8")
                self.assertTrue(path.is_file(), f"no snapshot for {name}: run with CODEFACTORY_UPDATE_GOLDEN=1")
                self.assertEqual(got, path.read_text(encoding="utf-8"), f"{name}: findings changed (see the module docstring)")


if __name__ == "__main__":
    unittest.main()
