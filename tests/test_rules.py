"""Layer rules, config parsing and the analyzer's tolerance of odd code, on small throwaway projects."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.cli import build
from codefactory.config import parse_rule


def project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return root


class RulesTest(unittest.TestCase):
    def test_parse_rule(self):
        self.assertEqual(parse_rule(" ui ->  db "), ("ui", "db"))
        with self.assertRaises(ValueError):
            parse_rule("ui db")

    def test_layer_violation_and_globs(self):
        root = project(
            {
                "factory.toml": '[layers]\nscreens = ["app/ui/*"]\nstorage = ["app/data/*"]\n[rules]\nforbid = ["screens -> storage"]\n',
                "app/ui/home.py": "from app.data.repo import load\n\ndef show():\n    return load()\n",
                "app/data/repo.py": "def load():\n    return []\n",
            }
        )
        g = build(root)
        self.assertEqual({f.id: f.layer for f in g.files}["app/ui/home.py"], "screens")
        bad = [f for f in g.flags if f.kind == "layer_violation"]
        self.assertEqual([f.target for f in bad], ["app/ui/home.py"])

    def test_relative_imports_and_reexports(self):
        root = project(
            {
                "pkg/__init__.py": "from .core import run\n",
                "pkg/core.py": "from . import util\n\ndef run():\n    return util.helper()\n",
                "pkg/util.py": "def helper():\n    return 1\n",
                "main.py": "import pkg\n\ndef main():\n    pkg.run()\n",
            }
        )
        edges = {(e.src, e.dst) for e in build(root).edges if e.kind == "call"}
        self.assertIn(("pkg/core.py::run", "pkg/util.py::helper"), edges)
        self.assertIn(("main.py::main", "pkg/core.py::run"), edges)  # through the package's re-export

    def test_callbacks_and_decorators_are_not_unused(self):
        root = project(
            {
                "app.py": """
                import atexit

                def cleanup():
                    pass

                def route(f):
                    return f

                @route
                def index():
                    return "hi"

                atexit.register(cleanup)
            """,
            }
        )
        unused = {f.target for f in build(root).flags if f.kind == "unused"}
        self.assertNotIn("app.py::cleanup", unused)  # passed by name
        self.assertNotIn("app.py::index", unused)  # decorated: a framework calls it
        self.assertNotIn("app.py::route", unused)  # used as a decorator

    def test_same_name_twice_gets_unique_ids(self):
        root = project(
            {
                "a.py": """
            class Box:
                @property
                def size(self):
                    return self._size

                @size.setter
                def size(self, v):
                    self._size = v
        """
            }
        )
        ids = [f.id for f in build(root).functions if f.name == "size"]
        self.assertEqual(len(set(ids)), 2)
        self.assertIn("a.py::Box.size", ids)

    def test_imports_inside_functions_and_type_checking_make_no_loop(self):
        root = project(
            {
                "pkg/__init__.py": "",
                "pkg/a.py": "from pkg import b\n\ndef fa():\n    return b.fb()\n",
                "pkg/b.py": """
                from typing import TYPE_CHECKING

                if TYPE_CHECKING:
                    from pkg.a import fa

                def fb():
                    from pkg import a  # deliberately lazy: breaks the loop at load time
                    return a
            """,
            }
        )
        g = build(root)
        self.assertFalse([f for f in g.flags if f.kind == "cycle"])
        self.assertIn(("pkg/a.py", "pkg/b.py"), {(e.src, e.dst) for e in g.edges if e.kind == "import"})

    def test_one_dominant_zone_is_split_by_the_next_folder(self):
        files = {"pkg/__init__.py": "", "pkg/main.py": "x = 1\n"}
        for sub in ("cli", "net", "models", "utils"):
            for i in range(4):
                files[f"pkg/_internal/{sub}/m{i}.py"] = "x = 1\n"
        layers = {f.id: f.layer for f in build(project(files)).files}
        self.assertEqual(layers["pkg/_internal/cli/m0.py"], "cli")
        self.assertEqual(layers["pkg/_internal/utils/m3.py"], "utils")
        self.assertEqual(layers["pkg/main.py"], "pkg app")  # top-level glue goes by its imports

    def test_bad_syntax_is_skipped(self):
        root = project({"ok.py": "def f():\n    return 1\n", "broken.py": "def (:\n"})
        self.assertEqual([f.id for f in build(root).files], ["ok.py"])

    def test_ignored_folders(self):
        root = project({"src/a.py": "x = 1\n", ".venv/lib/b.py": "y = 2\n", "node_modules/c.py": "z = 3\n"})
        self.assertEqual([f.id for f in build(root).files], ["src/a.py"])


if __name__ == "__main__":
    unittest.main()
