"""Imports inside a function name things for that function only: two functions importing different `summarize`s each
call their own. (Found on a real CLI where one of them then looked unused.)"""

import tempfile
import unittest
from pathlib import Path

from codefactory.analyzers.python import analyze_python


class FunctionImportsTest(unittest.TestCase):
    def test_each_function_resolves_its_own_import(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("")
            (root / "pkg" / "manage.py").write_text("def summarize(r):\n    return [r]\n")
            (root / "pkg" / "ledger.py").write_text("def summarize(t, x):\n    return t\n")
            (root / "pkg" / "cli.py").write_text(
                "def cmd_manage(r):\n    from pkg.manage import summarize\n    return summarize(r)\n\n\n"
                "def cmd_ledger(t):\n    from pkg.ledger import summarize\n    return summarize(t, 1)\n"
            )
            g = analyze_python(root, [], cache=False)
            calls = {(e.src, e.dst) for e in g.edges if e.kind == "call"}
            self.assertIn(("pkg/cli.py::cmd_manage", "pkg/manage.py::summarize"), calls)
            self.assertIn(("pkg/cli.py::cmd_ledger", "pkg/ledger.py::summarize"), calls)
            self.assertNotIn(("pkg/cli.py::cmd_manage", "pkg/ledger.py::summarize"), calls)


if __name__ == "__main__":
    unittest.main()
