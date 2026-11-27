"""Python false positives from the round-5 held-out sample (saleor, mitmproxy, owid/etl), each pinned next to a true
case that must stay reported."""

import os
import unittest

from codefactory.cli import build
from codefactory.paths import walk
from tests.test_large_repo import repo


def loops(root):
    return sorted(f.target.split("::")[-1] for f in build(root, cache=False).flags if f.kind == "io_in_loop")


class LazyQuerySetTest(unittest.TestCase):
    def test_a_queryset_built_in_a_loop_but_not_run_there_is_no_query(self):
        root = repo({  # saleor: querysets OR-ed together or kept for later run once, after the loop
            "shop/predicates.py": (
                "from django.db.models import Exists, OuterRef\nfrom shop.models import Checkout, Payment\n\n\n"
                "def where(qs, data):\n    return qs\n\n\n"
                "def checkout_predicate(result_qs, base_qs, data):\n"
                "    checkouts = where(Checkout.objects.filter(pk__in=base_qs.values('pk')), data)\n"
                "    result_qs &= checkouts\n    return result_qs\n\n\n"
                "def or_data(result_qs, base_qs, items):\n    qs = result_qs.model.objects.none()\n"
                "    for data in items:\n        qs = checkout_predicate(qs, base_qs, data)\n"
                "    result_qs &= qs\n    return result_qs\n\n\n"
                "def to_capture(orders, ids):\n    found = []\n    for i in ids:\n"
                "        payments = Payment.objects.filter(order_id=i).values('id')\n"
                "        found.append(orders.filter(Exists(payments.filter(order_id=OuterRef('id')))))\n"
                "    return found\n\n\n"
                "def clear(deliveries):\n    ids = []\n    for d in deliveries:\n        ids.append(d.payload_id)\n"
                "        to_delete = Payment.objects.filter(pk=d.payload_id)\n"
                "    if ids:\n        to_delete = Payment.objects.filter(pk__in=ids)\n        to_delete.delete()\n"
            ),
        })  # fmt: skip
        self.assertEqual(loops(root), [])

    def test_a_queryset_evaluated_in_a_loop_is_still_a_query_per_item(self):
        root = repo({
            "shop/orders.py": (
                "from shop.models import Item, Order\n\n\n"
                "def totals(orders):\n    out = []\n    for o in orders:\n"
                "        items = Item.objects.filter(order=o).order_by('id')\n        out.append(len(items))\n"
                "    return out\n\n\n"
                "def names(ids):\n    return [Item.objects.get(id=i).name for i in ids]\n\n\n"
                "def first_items(orders):\n    return [Item.objects.filter(order=o).first() for o in orders]\n\n\n"
                "def items_of(o):\n    return Item.objects.filter(order=o)\n\n\n"
                "def each(orders):\n    for o in orders:\n        for i in Item.objects.filter(order=o):\n"
                "            print(i)\n\n\n"
                "def later(orders):\n    for o in orders:\n        qs = Item.objects.filter(order=o)\n"
                "        if qs:\n            print(o)\n"
            ),
        })  # fmt: skip
        self.assertEqual(loops(root), ["each", "first_items", "later", "names", "totals"])


class OverloadTest(unittest.TestCase):
    def test_a_function_with_overload_stubs_is_used_through_them(self):
        root = repo({  # mitmproxy's strutils.always_bytes: calls name the stubs, the implementation runs
            "lib/strutils.py": (
                "from typing import overload\n\n\n@overload\ndef always_bytes(x: None) -> None: ...\n\n\n"
                "@overload\ndef always_bytes(x: str) -> bytes: ...\n\n\n"
                "def always_bytes(x):\n    return x.encode() if x else x\n\n\n"
                "def really_unused(x):\n    return x\n"
            ),
            "lib/use.py": "from lib.strutils import always_bytes\n\n\ndef run():\n    return always_bytes('a')\n",
        })  # fmt: skip
        g = build(root, cache=False)
        unused = {f.target for f in g.flags if f.kind == "unused"}
        self.assertIn("lib/strutils.py::really_unused", unused)
        self.assertFalse({t for t in unused if "always_bytes" in t}, unused)
        impl = next(f for f in g.functions if f.name == "always_bytes" and f.line == 12)
        self.assertEqual(impl.id, "lib/strutils.py::always_bytes")


@unittest.skipIf(os.name == "nt", "symbolic links")
class SymlinkTest(unittest.TestCase):
    def test_a_file_linked_inside_the_repository_is_analyzed_once(self):
        root = repo({  # owid/etl: 102 step files linked to one shared module
            "steps/shared.py": "def orphan():\n    return 1\n",
            "steps/latest/keep.py": "def also_orphan():\n    return 1\n",
            ".tools/hidden.py": "def hidden_orphan():\n    return 1\n",
        })  # fmt: skip
        (root / "steps/latest/a.py").symlink_to("../shared.py")
        (root / "steps/latest/b.py").symlink_to("../shared.py")
        (root / "tool.py").symlink_to(".tools/hidden.py")  # its target isn't read directly: read through the link
        (root / "tool2.py").symlink_to(".tools/hidden.py")
        files = sorted(walk(root, suffixes=(".py",), hidden=False))
        self.assertEqual(files, ["steps/latest/keep.py", "steps/shared.py", "tool.py"])
        unused = sorted(f.target for f in build(root, cache=False).flags if f.kind == "unused")
        expected = ["steps/latest/keep.py::also_orphan", "steps/shared.py::orphan", "tool.py::hidden_orphan"]
        self.assertEqual(unused, expected)


if __name__ == "__main__":
    unittest.main()
