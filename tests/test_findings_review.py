"""Behaviour found reviewing real projects: honest copy sizes, advice for same-named-apart copies, writes inside a
transaction, layers at a package's top, data stores from Python manifests, hidden folders and complexity."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.checks import scan_repo
from codefactory.cli import build
from codefactory.plan import batch_name, make_plan


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")


BODY = """
    if settings.enabled and settings.credentials:
        from app.vendor import Vendor
        client = Vendor(settings)
        client.connect(retries=3, timeout=10)
        return client
    return None
"""


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_copies_named_apart_get_a_shared_helper_and_honest_size(self):
        doc = '    """' + "A long explanation of why this one exists.\n    " * 8 + '"""'
        write(self.root, {"app/__init__.py": "", "app/vendor.py": "class Vendor:\n    pass\n",
                          "app/providers.py": '__all__ = ["get_quotes", "get_news"]\n\n\n'  # both public: kept apart on purpose
                          + "".join(f"def get_{n}(settings):\n{doc}{BODY}\n\n" for n in ("quotes", "news"))})  # fmt: skip
        task = next(t for t in make_plan(build(self.root, cache=False).to_dict()) if t["kind"] == "duplicate")
        self.assertTrue(task["title"].startswith("Share one body between get_news, get_quotes"), task["title"])
        self.assertIn("~7 lines", task["title"])  # def + 6 lines of body; the 9-line docstrings aren't copied logic
        self.assertTrue(any("private helper" in s for s in task["steps"]))

    def test_writes_inside_a_transaction_are_not_reported(self):
        write(self.root, {"app/__init__.py": "", "app/store.py": '''
            def save_all(db, rows):
                with db.session() as conn:
                    for r in rows:
                        conn.execute("INSERT INTO t VALUES (?)", (r,))


            def save_each(conn, rows):
                for r in rows:
                    conn.execute("INSERT INTO t VALUES (?)", (r,))
            '''})  # fmt: skip
        flagged = {f.target.split("::")[-1] for f in build(self.root, cache=False).flags if f.kind == "io_in_loop"}
        self.assertEqual(flagged, {"save_each"})

    def test_top_of_a_split_package_is_placed_by_its_imports(self):
        files = {"src/pkg/__init__.py": "", "src/pkg/config.py": "LEVEL = 1\n",
                 "src/pkg/cli.py": "from pkg.jobs import a\nfrom pkg.api import b\nfrom pkg.store import c\n"}  # fmt: skip
        for zone in ("jobs", "api", "store", "models"):
            for i in range(4):
                files[f"src/pkg/{zone}/m{i}.py"] = "from pkg.config import LEVEL\n"
        write(self.root, files)
        layer = {f.id: f.layer for f in build(self.root, cache=False).files}
        self.assertEqual(layer["src/pkg/config.py"], "pkg shared")
        self.assertEqual(layer["src/pkg/cli.py"], "pkg app")

    def test_hidden_folders_are_tooling(self):
        write(self.root, {"app.py": "def main():\n    return 1\n", ".claude/hooks/prefetch.py": "def hook():\n    return 2\n"})
        self.assertEqual({f.id for f in build(self.root, cache=False).files}, {"app.py"})

    def test_python_dependencies_name_the_data_stores(self):
        write(self.root, {"pyproject.toml": '[project]\nname = "x"\ndependencies = ["duckdb>=1.0", "pyarrow", "fastapi[all]"]\n'})
        self.assertTrue({"duckdb", "pyarrow", "fastapi"} <= set(scan_repo(self.root)["deps"]))

    def test_complexity_and_batch_names(self):
        write(self.root, {"m.py": "def f(x):\n    if x and x > 1:\n        return [i for i in x if i]\n    return 0\n"})
        f = next(f for f in build(self.root, cache=False).functions if f.name == "f")
        self.assertEqual(f.branches, 4)  # if, and, the comprehension and its if
        self.assertEqual(batch_name("get_order", "a.py"), "get_order_batch(ids)")
        self.assertEqual(batch_name("getOrder", "a.ts"), "getOrderMany(ids)")


if __name__ == "__main__":
    unittest.main()


class TypeScriptTransactionTest(unittest.TestCase):
    def test_writes_in_a_transaction_callback_are_not_reported(self):
        from tests.test_typescript import available

        if not available():
            self.skipTest("Node.js and the typescript package are needed")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, {"tsconfig.json": '{"compilerOptions": {"strict": true}}', "store.ts": """
                declare const db: { runAsync(sql: string, ...args: unknown[]): Promise<void> };
                declare function transaction(task: () => Promise<void>): Promise<void>;

                export async function saveAll(rows: number[]) {
                  await transaction(async () => {
                    for (const r of rows) await db.runAsync("INSERT INTO t VALUES (?)", r);
                  });
                }

                export async function saveEach(rows: number[]) {
                  for (const r of rows) await db.runAsync("INSERT INTO t VALUES (?)", r);
                }
                """})  # fmt: skip
            flagged = {f.target.split("::")[-1] for f in build(root, cache=False).flags if f.kind == "io_in_loop"}
            self.assertEqual(flagged, {"saveEach"})
