"""End-to-end checks against tests/fixtures/shop, a tiny app with known problems planted in it."""
import json
import tempfile
import unittest
from pathlib import Path

from codefactory.cli import build, main
from codefactory.viewer import render_html

SHOP = Path(__file__).parent / "fixtures" / "shop"


class ShopTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = build(SHOP)
        cls.flags = {(f.kind, f.target) for f in cls.g.flags}
        cls.edges = {(e.src, e.dst, e.kind) for e in cls.g.edges}

    def test_files_and_layers(self):
        layers = {f.id: f.layer for f in self.g.files}
        self.assertEqual(layers["shop/api/routes.py"], "api")
        self.assertEqual(layers["shop/db/store.py"], "db")
        # api uses core and db, core is used: api sits left of db and core
        order = self.g.layers
        self.assertLess(order.index("api"), order.index("db"))
        self.assertLess(order.index("api"), order.index("core"))

    def test_calls_resolve(self):
        self.assertIn(("shop/api/routes.py::checkout", "shop/core/pricing.py::total", "call"), self.edges)  # module.attr
        self.assertIn(("shop/api/routes.py::checkout", "shop/db/store.py::save_order", "call"), self.edges)  # from-import
        self.assertIn(("shop/core/pricing.py::total", "shop/core/tax.py::tax_for", "call"), self.edges)
        self.assertIn(("shop/db/store.py::<module>", "shop/db/store.py::Store.__init__", "call"), self.edges)  # Class()

    def test_import_cycle(self):
        self.assertIn(("cycle", "shop/core/pricing.py"), self.flags)
        self.assertIn(("cycle", "shop/core/tax.py"), self.flags)
        self.assertNotIn(("cycle", "shop/api/routes.py"), self.flags)

    def test_duplicates_ignore_renamed_variables(self):
        self.assertIn(("duplicate", "shop/core/pricing.py::discount"), self.flags)
        self.assertIn(("duplicate", "shop/core/pricing.py::apply_coupon"), self.flags)

    def test_unused(self):
        self.assertIn(("unused", "shop/api/routes.py::legacy_export"), self.flags)
        self.assertNotIn(("unused", "shop/core/tax.py::tax_for"), self.flags)
        self.assertNotIn(("unused", "shop/db/store.py::Store.__init__"), self.flags)  # dunder
        self.assertNotIn(("unused", "shop/db/store.py::Store.add"), self.flags)  # _store.add: unique method name

    def test_layer_rule(self):
        # factory.toml forbids db -> api; nothing in db imports api
        self.assertFalse([f for f in self.g.flags if f.kind == "layer_violation"])

    def test_view_is_self_contained(self):
        page = render_html(self.g.to_dict())
        self.assertIn("window.FACTORY = {", page)
        self.assertNotIn("/*JS*/", page)
        self.assertNotIn("<script src", page)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "g.json"
            self.assertEqual(main(["analyze", str(SHOP), "-o", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["schema"], 1)
            self.assertEqual(main(["flags", str(out), "--fail-on", "high"]), 1)
            self.assertEqual(main(["view", str(out), "-o", str(Path(d) / "f.html"), "--no-open"]), 0)


if __name__ == "__main__":
    unittest.main()
