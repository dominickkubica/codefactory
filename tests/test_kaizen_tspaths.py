"""Path aliases of a monorepo app's own tsconfig ("@/*" in apps/web/tsconfig.json, not the root one): imports through
them are edges, also when `extends` (a relative file or a workspace package's config) provides the paths, or a
solution-style tsconfig hands the file to a referenced one. A function nobody imports stays unused."""

import unittest

from codefactory.cli import build
from tests.test_large_repo import repo
from tests.test_typescript import available

HOOK = "export function useThing() { return 1; }\nexport function lonely() { return 2; }\n"
PAGE = "import { useThing } from '@/lib/hooks';\nexport function Page() { return useThing(); }\n"


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class TsConfigPathsTest(unittest.TestCase):
    def check(self, files, app="apps/web"):
        g = build(repo({**files, f"{app}/src/lib/hooks.ts": HOOK, f"{app}/src/page.ts": PAGE}), cache=False)
        imports = {(e.src, e.dst) for e in g.edges if e.kind == "import"}
        unused = {f.target for f in g.flags if f.kind == "unused"}
        self.assertIn((f"{app}/src/page.ts", f"{app}/src/lib/hooks.ts"), imports)
        self.assertNotIn(f"{app}/src/lib/hooks.ts::useThing", unused)
        self.assertIn(f"{app}/src/lib/hooks.ts::lonely", unused)  # the true case: nobody imports it

    def test_nested_app_tsconfig(self):
        self.check({
            "package.json": '{"name": "mono", "private": true}',
            "tsconfig.json": '{"compilerOptions": {"strict": true}}',
            "apps/web/tsconfig.json": '{\n  // the app\'s own\n  "compilerOptions": {"paths": {"@/*": ["./src/*"]}}}',
        })  # fmt: skip

    def test_paths_from_an_extends_chain(self):
        self.check({
            "apps/web/tsconfig.base.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}}',
            "apps/web/tsconfig.mid.json": '{"extends": "./tsconfig.base.json"}',
            "apps/web/tsconfig.json": '{"extends": "./tsconfig.mid.json", "compilerOptions": {"strict": true}}',
        })  # fmt: skip

    def test_extends_a_workspace_package_config(self):
        self.check({
            "packages/tsconfig/package.json": '{"name": "@org/tsconfig"}',
            "packages/tsconfig/web.json": '{"compilerOptions": {"paths": {"@/*": ["${configDir}/src/*"]}}}',
            "apps/web/tsconfig.json": '{"extends": "@org/tsconfig/web.json"}',
        })  # fmt: skip

    def test_solution_style_tsconfig(self):
        self.check({
            "apps/web/tsconfig.json": '{"files": [], "references": [{"path": "./tsconfig.node.json"}, '
                                      '{"path": "./tsconfig.app.json"}]}',
            "apps/web/tsconfig.node.json": '{"compilerOptions": {"composite": true}, "include": ["vite.config.ts"]}',
            "apps/web/tsconfig.app.json": '{"compilerOptions": {"paths": {"@/*": ["./src/*"]}}, "include": ["src"]}',
        })  # fmt: skip


if __name__ == "__main__":
    unittest.main()
