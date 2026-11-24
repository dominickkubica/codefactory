"""The general analyzer (tree-sitter) on a small Go/Java/Ruby app with planted problems and their look-alikes, plus
extraction across languages. Skipped when the optional language pack isn't installed."""

import shutil
import tempfile
import unittest
from pathlib import Path

from codefactory.analyzers.generic import available
from codefactory.cli import build

FIXTURE = Path(__file__).parent / "fixtures" / "polyglot"


@unittest.skipUnless(available(), 'needs pip install "codefactory[languages]"')
class PolyglotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = build(FIXTURE, cache=False)
        cls.flags = {(f.kind, f.target.split("::")[-1]) for f in cls.g.flags}

    def test_languages_and_imports(self):
        self.assertIn("go", self.g.language)
        imports = {(e.src, e.dst) for e in self.g.edges if e.kind == "import"}
        self.assertIn(("api/handlers.go", "store/store.go"), imports)  # a Go package, through one of its files
        self.assertIn(("java/com/shop/Orders.java", "java/com/shop/Repo.java"), imports)
        self.assertFalse([f for f in self.g.flags if f.kind == "cycle"])

    def test_finds_planted_problems(self):
        for expected in [
            ("duplicate", "summarize"),
            ("io_in_loop", "LoadAll"),  # db.conn.Query per id
            ("io_in_loop", "Report.build"),  # Ruby: DB.query inside ids.each do … end
            ("unused", "helperUnused"),
            ("unused", "Orders.unusedHelper"),
        ]:
            self.assertIn(expected, self.flags)

    def test_leaves_look_alikes_alone(self):
        self.assertNotIn(("unused", "usedByGenerated"), self.flags)  # only generated code calls it: still used
        self.assertNotIn(("unused", "LoadAll"), self.flags)  # exported Go API
        self.assertNotIn(("duplicate", "normalize"), self.flags)  # path_linux.go / path_darwin.go: on purpose
        self.assertFalse([f for f in self.g.functions if f.file == "gen/tables.go" and f.kind != "module"])

    def test_calls_resolve_by_name(self):
        calls = {(e.src.split("::")[-1], e.dst.split("::")[-1]) for e in self.g.edges if e.kind == "call"}
        self.assertIn(("Report", "summarize"), calls)
        self.assertIn(("Orders.load", "Repo.findById"), calls)

    def test_per_file_cache_reuses_unchanged_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "app"
            shutil.copytree(FIXTURE, root)
            first = build(root)
            (root / "store" / "store.go").write_text("package store\n\nfunc Only() int { return 1 }\n", encoding="utf-8")
            second = build(root)
            self.assertTrue((root / ".codefactory" / "files-generic.json").is_file())
            names = lambda g: {f.qualname for f in g.functions if f.file == "store/store.go"}  # noqa: E731
            self.assertIn("helperUnused", names(first))
            self.assertEqual(names(second), {"<module>", "Only"})


@unittest.skipUnless(available(), 'needs pip install "codefactory[languages]"')
class ExtractionTest(unittest.TestCase):
    """Functions, their calls and which calls run per loop item, in each language's own syntax."""

    SAMPLES = {
        "a.rs": "fn helper(x: i32) -> i32 { x }\nimpl S { pub fn run(&self, ids: Vec<i32>) { for id in ids { self.pool.query(id); helper(id); } } }\n",
        "A.kt": "class Orders { fun load(ids: List<Int>) { for (id in ids) { repo.find(id); helper(id) } }\n private fun helper(x: Int) = x }\n",
        "a.swift": "class Orders { func load(ids: [Int]) { for id in ids { db.query(id); helper(id) } }\n func helper(_ x: Int) -> Int { return x } }\n",
        "a.c": '#include "db.h"\nstatic int helper(int x) { return x; }\nint run(int *ids, int n) { for (int i = 0; i < n; i++) { db_query(ids[i]); helper(i); } return 0; }\n',
        "A.cs": "class Orders { public void Load(int[] ids) { foreach (var id in ids) { _db.Find(id); Helper(id); } } int Helper(int x) { return x; } }\n",
        "a.php": "<?php\nclass Orders { function load($ids) { foreach ($ids as $id) { $this->db->query($id); $this->helper($id); } } function helper($x) { return $x; } }\n",
    }

    def test_each_language(self):
        from tree_sitter_language_pack import get_parser

        from codefactory.analyzers.generic import LANGS
        from codefactory.analyzers.treewalk import walk

        for name, src in self.SAMPLES.items():
            with self.subTest(name):
                data = walk(src.encode(), get_parser(LANGS[Path(name).suffix]), name)
                fns = {f["name"]: f for f in data["functions"]}
                self.assertIn("helper", {n.lower() for n in fns})
                loader = next(f for n, f in fns.items() if n.lower() in ("run", "load"))
                in_loop = {c[0].lower() for c in loader["calls"] if c[2]}
                self.assertTrue({"helper"} <= in_loop and in_loop & {"query", "find", "db_query"}, (name, loader["calls"]))


if __name__ == "__main__":
    unittest.main()
