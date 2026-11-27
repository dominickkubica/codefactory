"""Gaps in the JavaScript / TypeScript call graph that made used code look unused or untested: code loaded with
import("./x"), a workspace package imported by name, a named callback, a getter of an object literal. Each next to a
true case that must stay reported (needs Node and the typescript package; skipped otherwise)."""

import unittest

from codefactory.brief import View
from codefactory.checks import test_reach
from codefactory.cli import build
from tests.test_large_repo import repo
from tests.test_typescript import available


def reached(g) -> set[str]:
    return test_reach(View(g.to_dict()))


def unused(g) -> set[str]:
    return {f.target for f in g.flags if f.kind == "unused"}


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class JsGraphTest(unittest.TestCase):
    def test_a_dynamic_import_reaches_the_module_it_loads(self):
        g = build(repo({
            "src/button.tsx": "export function Button() {\n  return <button />;\n}\n",
            "src/demo.tsx": "import { Button } from './button';\n"
                            "export default function Demo() {\n  return <Button />;\n}\n",
            "src/pages.ts": "export async function loadDemos() {\n  const load = () => import('./demo');\n"
                            "  return load();\n}\n",
            "src/pages.test.ts": "import { loadDemos } from './pages';\ntest('loads', () => loadDemos());\n",
            # never imported, statically or dynamically
            "src/orphan.tsx": "import { Button } from './button';\n"
                              "export function Orphan() {\n  return <Button />;\n}\n"
                              "function stray() {\n  return 1;\n}\n",
        }), cache=False)  # fmt: skip
        reach = reached(g)
        self.assertIn("src/demo.tsx::Demo", reach)
        self.assertIn("src/button.tsx::Button", reach)
        self.assertIn("src/demo.tsx::<module>", reach)
        self.assertNotIn("src/orphan.tsx::Orphan", reach)
        self.assertIn("src/orphan.tsx::stray", unused(g))
        imports = {(e.src, e.dst) for e in g.edges if e.kind == "import"}
        self.assertNotIn(("src/pages.ts", "src/demo.tsx"), imports)  # loaded on demand: can't form a loading loop

    def test_a_workspace_package_resolves_without_node_modules(self):
        g = build(repo({
            "packages/ui/package.json": '{"name": "@acme/ui", "exports": {"./components/*": "./src/components/*.tsx"}}',
            "packages/ui/src/components/button.tsx": "export function Button() {\n  return <button />;\n}\n",
            "packages/ui/src/components/card.tsx": "export function Card() {\n  return <div />;\n}\n",
            "app/src/demo.tsx": "import { Button } from '@acme/ui/components/button';\n"
                                "export function Demo() {\n  return <Button />;\n}\n",
            "app/src/demo.test.tsx": "import { Demo } from './demo';\ntest('renders', () => Demo());\n",
        }), cache=False)  # fmt: skip
        reach = reached(g)
        self.assertIn("packages/ui/src/components/button.tsx::Button", reach)
        self.assertNotIn("packages/ui/src/components/card.tsx::Card", reach)
        imports = {(e.src, e.dst) for e in g.edges if e.kind == "import"}
        self.assertIn(("app/src/demo.tsx", "packages/ui/src/components/button.tsx"), imports)

    def test_a_named_function_expression_passed_as_an_argument_is_a_callback(self):
        g = build(repo({
            "lib/scope.js": "function watchGroup(scope, exprs) {\n"
                            "  return scope.$watch(exprs[0], function watchGroupAction(value) {\n"
                            "    return value;\n  });\n}\n"
                            "function neverCalled() {\n  return 2;\n}\n"
                            "var handler = function namedButUnused() {\n  return 3;\n};\n"
                            "module.exports = { watchGroup: watchGroup };\n",
        }), cache=False)  # fmt: skip
        found = unused(g)
        self.assertNotIn("lib/scope.js::watchGroup.watchGroupAction", found)
        self.assertNotIn("lib/scope.js::watchGroupAction", found)
        self.assertIn("lib/scope.js::neverCalled", found)
        self.assertIn("lib/scope.js::namedButUnused", found)

    def test_getters_of_an_object_literal_are_read_by_property_access(self):
        g = build(repo({
            "src/sandbox.js": "function makeApi(inputs) {\n  return {\n    info: {\n"
                              "      get requestLabel() {\n        return inputs.label();\n      },\n"
                              "      get loopTotal() {\n        throw new Error('unsupported');\n      },\n"
                              "    },\n  };\n}\n"
                              "const shared = {\n  get sharedCount() {\n    return 1;\n  },\n};\n"
                              "function forgotten() {\n  return 4;\n}\n"
                              "module.exports = { makeApi, shared };\n",
        }), cache=False)  # fmt: skip
        found = unused(g)
        self.assertFalse({t for t in found if t.endswith(("requestLabel", "loopTotal", "sharedCount"))}, found)
        self.assertIn("src/sandbox.js::forgotten", found)


if __name__ == "__main__":
    unittest.main()
