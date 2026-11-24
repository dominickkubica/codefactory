"""SQL export, saved-query flags, trace and path."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from codefactory.cli import build, main
from codefactory.sqlgraph import run_query, to_sqlite
from codefactory.trace import find_function, shortest_path, trace
from tests.test_rules import project

SHOP = Path(__file__).parent / "fixtures" / "shop"


def run(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class SqlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = build(SHOP).to_dict()

    def test_tables_and_views(self):
        db = to_sqlite(self.graph)
        _, rows = run_query(db, "SELECT COUNT(*) FROM files")
        self.assertEqual(rows[0][0], len(self.graph["files"]))
        _, rows = run_query(db, "SELECT qualname, fan_in, caller_files FROM function_stats WHERE qualname = 'total'")
        self.assertEqual(rows, [("total", 2, 2)])  # checkout and preview, from two files
        _, rows = run_query(
            db, "SELECT calls FROM file_deps WHERE src_file = 'shop/api/routes.py' AND dst_file = 'shop/db/store.py'"
        )
        self.assertEqual(rows, [(2,)])  # save_order and load_orders
        db.close()

    def test_sql_file_and_query_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "g.db")
            self.assertEqual(run("sql", str(SHOP), "-o", out)[0], 0)
            code, text = run("query", out, "SELECT name FROM functions WHERE name = 'tax_for'")
            self.assertEqual(code, 0)
            self.assertIn("tax_for", text)
        with self.assertRaises(SystemExit):
            run("query", str(SHOP), "SELECT nope FROM nowhere")

    def test_saved_query_becomes_flag(self):
        root = project(
            {
                "factory.toml": """
[[queries]]
name = "too_many_params_proxy"
severity = "high"
message = "Function over 3 lines in core"
sql = "SELECT id AS target, loc FROM functions WHERE file LIKE 'core/%' AND loc > 3"
""",
                "core/big.py": "def big(a):\n    x = a\n    y = x\n    return y\n",
                "core/small.py": "def small():\n    return 1\n",
            }
        )
        flags = [f for f in build(root).flags if f.kind == "too_many_params_proxy"]
        self.assertEqual([(f.target, f.severity) for f in flags], [("core/big.py::big", "high")])
        self.assertIn("loc 4", flags[0].message)

    def test_saved_query_needs_target(self):
        root = project({"factory.toml": '[[queries]]\nname = "x"\nsql = "SELECT 1"\n', "a.py": "x = 1\n"})
        with self.assertRaises(ValueError):
            build(root)


class TraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = build(SHOP).to_dict()

    def test_find(self):
        self.assertEqual(len(find_function(self.graph, "checkout")), 1)
        self.assertEqual(find_function(self.graph, "shop/core/tax.py::tax_for")[0]["name"], "tax_for")
        self.assertEqual(find_function(self.graph, "nothing_like_this"), [])

    def test_trace(self):
        t = trace(self.graph, "shop/api/routes.py::checkout")
        depth = {f["qualname"]: f["depth"] for f in t["functions"]}
        self.assertEqual(depth, {"total": 1, "save_order": 1, "tax_for": 2})
        self.assertEqual(t["depth"], 2)
        self.assertEqual(len(t["files"]), 3)

    def test_trace_finds_call_loop(self):
        root = project({"a.py": "def ping(n):\n    return pong(n)\n\ndef pong(n):\n    return ping(n - 1) if n else 0\n"})
        g = build(root).to_dict()
        self.assertEqual(trace(g, "a.py::ping")["calls_back"], ["a.py::pong"])

    def test_path(self):
        self.assertEqual(
            shortest_path(self.graph, "shop/api/routes.py::checkout", "shop/core/tax.py::tax_for"),
            ["shop/api/routes.py::checkout", "shop/core/pricing.py::total", "shop/core/tax.py::tax_for"],
        )
        self.assertIsNone(shortest_path(self.graph, "shop/core/tax.py::tax_for", "shop/api/routes.py::checkout"))

    def test_cli(self):
        code, text = run("trace", str(SHOP), "checkout")
        self.assertEqual(code, 0)
        self.assertIn("reaches 3 functions in 3 files", text)
        self.assertEqual(run("path", str(SHOP), "checkout", "tax_for")[0], 0)
        self.assertEqual(run("path", str(SHOP), "tax_for", "checkout")[0], 1)
        with self.assertRaises(SystemExit):
            run("trace", str(SHOP), "no_such_function")


if __name__ == "__main__":
    unittest.main()
