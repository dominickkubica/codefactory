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

    def test_a_function_only_called_inside_a_transaction_counts_as_in_one(self):
        write(self.root, {"app/__init__.py": "", "app/store.py": '''
            def insert_items(conn, rows):
                for r in rows:
                    conn.execute("INSERT INTO items VALUES (?)", (r,))


            def insert_logs(conn, rows):
                for r in rows:
                    conn.execute("INSERT INTO logs VALUES (?)", (r,))


            def save_meal(db, rows):
                with db.session() as conn:
                    insert_items(conn, rows)
                    insert_logs(conn, rows)


            def quick_log(conn, rows):
                insert_logs(conn, rows)  # this caller opens no transaction
            '''})  # fmt: skip
        flagged = {f.target.split("::")[-1] for f in build(self.root, cache=False).flags if f.kind == "io_in_loop"}
        self.assertEqual(flagged, {"insert_logs"})

    def test_a_transaction_opened_further_up_the_call_chain_counts(self):
        write(self.root, {"app/__init__.py": "", "app/layers.py": '''
            def insert_rows(conn, rows):
                for r in rows:
                    conn.execute("INSERT INTO t VALUES (?)", (r,))


            def import_file(conn, rows):
                insert_rows(conn, rows)


            def handle_upload(db, rows):
                with db.session() as conn:
                    import_file(conn, rows)
            '''})  # fmt: skip
        flagged = {f.target.split("::")[-1] for f in build(self.root, cache=False).flags if f.kind == "io_in_loop"}
        self.assertEqual(flagged, set())  # route -> service -> repository, two levels from the transaction

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

    def test_a_method_named_in_getattr_is_used(self):
        write(self.root, {"app.py": '''
            class Provider:
                def bulk(self, ids):
                    return ids

                def never(self):
                    return 0


            def load(provider, ids):
                fetch = getattr(provider, "bulk", None)
                return fetch(ids) if fetch else []
            '''})  # fmt: skip
        unused = {f.target.split("::")[-1] for f in build(self.root, cache=False).flags if f.kind == "unused"}
        self.assertNotIn("Provider.bulk", unused)
        self.assertIn("Provider.never", unused)

    def test_review_separates_writes_from_file_operations_and_fixed_loops(self):
        from codefactory.review import review_markdown

        write(self.root, {"app.py": '''
            from pathlib import Path

            TABLES = ["a", "b"]


            def snapshot_dates(folder, symbols):
                return [sorted(Path(folder, s).glob("*.parquet")) for s in symbols]


            def save(conn, rows):
                for r in rows:
                    conn.execute("INSERT INTO t VALUES (?)", (r,))


            def count_tables(conn):
                return [conn.execute(f"SELECT count(*) FROM {t}").fetchone() for t in TABLES]
            '''})  # fmt: skip
        text = review_markdown(build(self.root, cache=False).to_dict(), self.root)
        self.assertIn("Writes inside loops in 1 place", text)
        self.assertIn("File or program operations inside loops in 1 place", text)
        self.assertNotIn("count_tables", text.split("## 4.")[0].split("Writes inside loops")[-1])

    def test_loop_calls_are_classified_by_what_they_do(self):
        write(self.root, {"app.py": '''
            import shutil


            def read_snapshot(conn, day):
                return conn.execute(f"SELECT * FROM snaps WHERE day = '{day}'").fetchall()


            def load_bars(conn, day):
                return conn.execute(QUERY, (day,))


            def backup(files, dest):
                for f in files:
                    shutil.copy2(f, dest)


            def fit(conn, days):
                return [read_snapshot(conn, d) for d in days]


            def fit_again(conn, days):
                return [load_bars(conn, d) for d in days]
            '''})  # fmt: skip
        kinds = {f.target.split("::")[-1]: f.detail for f in build(self.root, cache=False).flags if f.kind == "io_in_loop"}
        self.assertEqual(kinds, {"backup": "file", "fit": "read", "fit_again": "read"})

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
                async function transaction(task: () => Promise<void>): Promise<void> {
                  await db.runAsync("BEGIN");
                  await task();
                  await db.runAsync("COMMIT");
                }

                export async function saveAll(rows: number[]) {
                  await transaction(async () => {
                    for (const r of rows) await db.runAsync("INSERT INTO t VALUES (?)", r);
                  });
                }

                export async function syncInBatches(batches: number[][]) {
                  for (const b of batches) await transaction(async () => { await db.runAsync("INSERT …", b); });
                }

                export async function saveEach(rows: number[]) {
                  for (const r of rows) await db.runAsync("INSERT INTO t VALUES (?)", r);
                }
                """})  # fmt: skip
            flagged = {f.target.split("::")[-1] for f in build(root, cache=False).flags if f.kind == "io_in_loop"}
            self.assertEqual(flagged, {"saveEach"})
