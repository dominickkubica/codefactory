"""Efficiency and near-duplicate checks, on the shop (Python) and tsapp (TypeScript) fixtures."""
import unittest
from pathlib import Path

from codefactory.cli import build
from codefactory.efficiency import kind_of
from tests.test_rules import project
from tests.test_typescript import available

FIX = Path(__file__).parent / "fixtures"


def flags_of(g, kind):
    return {f.target: f for f in g.flags if f.kind == kind}


class PythonEfficiencyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = build(FIX / "shop")

    def test_io_recorded(self):
        fns = {f.id: f for f in self.g.functions}
        self.assertIn('conn.execute("SELECT …")', fns["shop/db/sql.py::get_order"].io)
        self.assertEqual(fns["shop/db/sql.py::connect"].io, ["sqlite3.connect"])

    def test_n_plus_one_read_is_warn_and_writes_info(self):
        loops = flags_of(self.g, "io_in_loop")
        read = loops["shop/api/reports.py::order_report"]
        self.assertEqual(read.severity, "warn")
        self.assertIn("get_order()", read.message)
        self.assertEqual(read.related, ["shop/db/sql.py::get_order"])
        self.assertEqual(read.line, 6)  # the call, inside the list comprehension
        self.assertEqual(loops["shop/api/reports.py::import_lines"].severity, "info")
        self.assertNotIn("shop/api/routes.py::checkout", loops)

    def test_near_duplicate(self):
        sim = flags_of(self.g, "similar")
        self.assertIn("shop/api/reports.py::shipping_cost", sim)
        self.assertIn("shop/api/reports.py::freight_cost", sim)
        self.assertGreaterEqual(sim["shop/api/reports.py::freight_cost"].score, 0.75)
        # exact copies stay "duplicate", not "similar"
        self.assertNotIn("shop/core/pricing.py::discount", sim)

    def test_tokens_dropped_after_flags(self):
        self.assertFalse(any(f.tokens for f in self.g.functions))

    def test_fixed_python_loops(self):
        root = project({"app/db.py": """
            TABLES = ("orders", "lines")

            def counts(conn):
                return {t: conn.execute("SELECT count(*) FROM orders").fetchone() for t in TABLES}

            def first(conn):
                for i in range(3):
                    conn.execute("SELECT * FROM orders WHERE id = ?", (i,))

            def each(conn, ids):
                for i in ids:
                    conn.execute("SELECT * FROM orders WHERE id = ?", (i,))
        """})
        loops = flags_of(build(root), "io_in_loop")
        self.assertEqual(loops["app/db.py::counts"].severity, "info")
        self.assertEqual(loops["app/db.py::first"].severity, "info")
        self.assertEqual(loops["app/db.py::each"].severity, "warn")

    def test_kinds(self):
        self.assertEqual(kind_of("fetch"), "network")
        self.assertEqual(kind_of("db.getAllAsync"), "read")
        self.assertEqual(kind_of("db.runAsync"), "write")
        self.assertEqual(kind_of("fs.readFileSync"), "file")


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class TypeScriptEfficiencyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = build(FIX / "tsapp")

    def test_loop_query(self):
        loops = flags_of(self.g, "io_in_loop")
        f = loops["src/data/repo.ts::loadAll"]
        self.assertEqual(f.severity, "warn")
        self.assertEqual(f.line, 7)
        self.assertNotIn("src/ui/List.tsx::List", loops)  # inside onPress={() => …} in a .map: runs on press
        self.assertNotIn("src/data/repo.ts::loadAll", flags_of(self.g, "sequential_await"))  # said once, above

    def test_loops_over_fixed_lists_are_info(self):
        loops = flags_of(self.g, "io_in_loop")
        for fid in ("src/data/fixed.ts::countTables", "src/data/fixed.ts::firstFive"):
            self.assertEqual(loops[fid].severity, "info", fid)
            self.assertIn("fixed in the code", loops[fid].message)
        self.assertEqual(loops["src/data/repo.ts::loadAll"].severity, "warn")  # loops over a parameter: can grow

    def test_framework_methods_and_lazy_require_are_used(self):
        unused = {f.target for f in self.g.flags if f.kind in ("unused", "test_only")}
        for name in ("Boundary.getDerivedStateFromError", "Boundary.componentDidCatch", "Boundary.render"):
            self.assertNotIn(f"src/ui/Boundary.tsx::{name}", unused)
        calls = {(e.src, e.dst) for e in self.g.edges if e.kind == "call"}
        self.assertIn(("src/data/fixed.ts::report", "src/data/lazy.ts::buildReport"), calls)  # const { fn } = require(…)
        self.assertIn(("src/data/fixed.ts::report", "src/data/lazy.ts::buildSummary"), calls)  # m = require(…); m.fn()

    def test_scan_in_map(self):
        scans = flags_of(self.g, "quadratic_scan")
        self.assertIn("src/data/repo.ts::tagged", scans)
        self.assertIn("picked.includes()", scans["src/data/repo.ts::tagged"].message)


if __name__ == "__main__":
    unittest.main()
