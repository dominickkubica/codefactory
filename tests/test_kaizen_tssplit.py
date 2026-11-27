"""A repository too big for one type checker is analyzed in groups of files, one TypeScript Program each: the graph is
the same as one Program's. Forced here with a tiny threshold, which puts every file in a group of its own: a call
into another package, a method on a type from another package, a require() of a file the group never loads and a
mocked module it doesn't import all link as they do in one Program."""

import dataclasses
import os
import unittest
from unittest import mock

from codefactory.analyzers.typescript import analyze_typescript
from codefactory.config import DEFAULT_IGNORE
from tests.test_large_repo import repo
from tests.test_typescript import available

FILES = {
    "package.json": '{"name": "mono", "private": true}',
    "packages/b/package.json": '{"name": "@x/b", "main": "src/index.ts"}',
    "packages/b/src/index.ts": "export function format(s: string) { return s.trim(); }\n"
                               "export class Store { save() { return format('x'); } }\n",
    "packages/b/src/slow.ts": "export function slow() { return 2; }\nexport function unused() { return 3; }\n",
    "packages/b/src/mocked.ts": "export function fetchAll() { return fetch('https://x.test'); }\n",
    "packages/a/package.json": '{"name": "@x/a"}',
    "packages/a/src/index.ts": "import { format } from '@x/b';\n"
                               "export function greet(n: string) { return format(n); }\n",
    "packages/a/src/use.ts": "import { Store } from '@x/b';\nexport function run(s: Store) { return s.save(); }\n",
    "packages/a/src/legacy.ts": "const { slow } = require('../../b/src/slow');\n"
                                "export function viaRequire() { return slow(); }\n",
    "packages/a/src/a.test.ts": "import { greet } from './index';\nvi.mock('../../b/src/mocked');\n"
                                "test('greets', () => { for (const n of names()) greet(n); });\n"
                                "function names() { return ['a']; }\n",
}  # fmt: skip


def graph(split: bool) -> dict:
    env = {"CODEFACTORY_TS_SPLIT_MB": "0.000001", "CODEFACTORY_TS_GROUP_MB": "0.000001"} if split else {}
    with mock.patch.dict(os.environ, env):
        if not split:
            for k in ("CODEFACTORY_TS_SPLIT_MB", "CODEFACTORY_TS_GROUP_MB"):
                os.environ.pop(k, None)
        g = analyze_typescript(repo(FILES), list(DEFAULT_IGNORE), cache=False)
    return {
        "files": sorted(f.id for f in g.files),
        "functions": sorted((dataclasses.asdict(f) for f in g.functions), key=lambda f: f["id"]),
        "edges": sorted((e.src, e.dst, e.kind, e.count) for e in g.edges),
        "sites": sorted((s.fn, s.kind, s.line, s.target) for s in g.sites),
    }


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class SplitProgramTest(unittest.TestCase):
    def test_groups_give_the_graph_of_one_program(self):
        one, split = graph(False), graph(True)
        edges = {e[:3] for e in one["edges"]}
        for e in [
            ("packages/a/src/index.ts::greet", "packages/b/src/index.ts::format", "call"),  # across packages
            ("packages/a/src/use.ts::run", "packages/b/src/index.ts::Store.save", "call"),  # a method of their type
            ("packages/a/src/legacy.ts::viaRequire", "packages/b/src/slow.ts::slow", "call"),  # a file not loaded
        ]:
            self.assertIn(e, edges)
        mocks = {f["id"]: f["mocks"] for f in one["functions"] if f.get("mocks")}
        mocked = ["packages/b/src/mocked.ts::<module>", "packages/b/src/mocked.ts::fetchAll"]
        self.assertEqual({"packages/a/src/a.test.ts::<module>": mocked}, mocks)
        self.assertEqual(one, split)


if __name__ == "__main__":
    unittest.main()
