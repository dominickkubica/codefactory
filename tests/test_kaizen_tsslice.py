"""A large project's walk is shared out: children that each build the whole TypeScript Program and walk a run of its
files, side by side, merged in order. Same Program, same answers, so the graph is one run's.

The exception was a call on a union: the checker names one member's function, whichever type it created first, and
that moved with which files a child walked (and, in one run, with the order of the files). `run(x: Alpha | Zed)` here
names Zed's when first.ts, walked earlier, made Zed's type first, and Alpha's in a child walking second.ts alone. The
pick is now the same every time: the member function first by id. Likewise for functions of one type read from a
table (`const Icon = ICONS[kind]; <Icon />`), which the checker reduces to one type."""

import os
import unittest
from unittest import mock

from codefactory.analyzers.typescript import analyze_typescript
from codefactory.config import DEFAULT_IGNORE
from tests.test_large_repo import repo
from tests.test_typescript import available

FILES = {
    "package.json": '{"name": "app", "private": true}',
    "src/models.ts": "export class Zed { run() { return 1; } }\nexport class Alpha { run() { return 2; } }\n"
                     "export function zap() { return 1; }\nexport function bolt() { return 2; }\n"
                     "export const ICONS = { z: zap, b: bolt };\n",
    # (long, so the cut between the two children falls after it)
    "src/first.ts": "import { Zed, zap } from './models';\nexport const made = new Zed();\nmade.run();\nzap();\n"
                    + "// padding\n" * 400,
    "src/second.ts": "import { Alpha, Zed, ICONS } from './models';\n"
                     "export function go(x: Alpha | Zed) { return x.run(); }\n"
                     "export function pick(k: 'z' | 'b') { const icon = ICONS[k]; return icon(); }\n",
}  # fmt: skip


def edges(sliced: bool) -> set:
    env = {"CODEFACTORY_TS_HEAP_MB": "4096", "CODEFACTORY_TS_WIDTH": "2" if sliced else "1"}
    if sliced:
        env["CODEFACTORY_TS_SLICE_MB"] = "0.000001"
    with mock.patch.dict(os.environ, env):
        if not sliced:
            os.environ.pop("CODEFACTORY_TS_SLICE_MB", None)
        g = analyze_typescript(repo(FILES), list(DEFAULT_IGNORE), cache=False)
    return {(e.src, e.dst, e.kind) for e in g.edges}


@unittest.skipUnless(available(), "Node.js and the typescript package are needed")
class SliceTest(unittest.TestCase):
    def test_slices_give_one_runs_graph(self):
        one, sliced = edges(False), edges(True)
        self.assertEqual(one, sliced)

    def test_a_call_on_a_union_names_the_member_first_by_id(self):
        for sliced in (False, True):
            found = edges(sliced)
            self.assertIn(("src/second.ts::go", "src/models.ts::Alpha.run", "call"), found)
            self.assertNotIn(("src/second.ts::go", "src/models.ts::Zed.run", "call"), found)

    def test_a_function_read_from_a_table_names_the_first_by_id(self):
        for sliced in (False, True):
            found = edges(sliced)
            self.assertIn(("src/second.ts::pick", "src/models.ts::bolt", "call"), found)
            self.assertNotIn(("src/second.ts::pick", "src/models.ts::zap", "call"), found)


if __name__ == "__main__":
    unittest.main()
