"""TypeScript analyzer, against tests/fixtures/tsapp (needs Node and the typescript package; skipped otherwise)."""
import shutil
import unittest
from pathlib import Path

from codefactory.analyzers.typescript import TypeScriptUnavailable, find_typescript
from codefactory.cli import build

APP = Path(__file__).parent / "fixtures" / "tsapp"


def available() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    try:
        find_typescript(APP, node)
        return True
    except TypeScriptUnavailable:
        return False


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class TypeScriptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = build(APP)
        cls.calls = {(e.src, e.dst) for e in cls.g.edges if e.kind == "call"}
        cls.imports = {(e.src, e.dst) for e in cls.g.edges if e.kind == "import"}
        cls.flags = {(f.kind, f.target) for f in cls.g.flags}

    def test_language_and_layers(self):
        self.assertEqual(self.g.language, "typescript")
        layers = {f.id: f.layer for f in self.g.files}
        self.assertEqual(layers["src/ui/Screen.tsx"], "ui")  # src/ is skipped for zone names
        self.assertLess(self.g.layers.index("ui"), self.g.layers.index("data"))

    def test_path_alias_imports(self):
        self.assertIn(("src/ui/Screen.tsx", "src/state/useCart.ts"), self.imports)  # "@/state/useCart"
        self.assertNotIn(("src/data/store.ts", "src/util/math.ts"), self.imports)  # import type

    def test_calls_through_hooks_methods_and_jsx(self):
        c = self.calls
        self.assertIn(("src/ui/Screen.tsx::Screen", "src/state/useCart.ts::useCart"), c)
        self.assertIn(("src/ui/Screen.tsx::Screen", "src/ui/Button.tsx::Button"), c)  # <Button />
        self.assertIn(("src/ui/Screen.tsx::Screen", "src/state/useCart.ts::useCart.total"), c)  # from the hook
        self.assertIn(("src/ui/Screen.tsx::Screen", "src/state/useCart.ts::useCart.add"), c)  # inside an inline callback
        self.assertIn(("src/state/useCart.ts::useCart.add", "src/data/store.ts::Store.save"), c)  # typed method call
        self.assertIn(("src/state/useCart.ts::useCart.total", "src/util/math.ts::sum"), c)

    def test_flags(self):
        f = self.flags
        self.assertIn(("unused", "src/util/math.ts::unusedHelper"), f)
        self.assertNotIn(("unused", "src/ui/Screen.tsx::Screen"), f)  # default export of a file nothing imports
        self.assertIn(("duplicate", "src/util/math.ts::sum"), f)
        self.assertIn(("duplicate", "src/util/math.ts::addUp"), f)
        self.assertIn(("cycle", "src/util/math.ts"), f)
        self.assertNotIn(("cycle", "src/data/store.ts"), f)


if __name__ == "__main__":
    unittest.main()
