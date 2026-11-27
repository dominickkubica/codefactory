"""Copied-logic lessons from held-out labels (rounds 4-5): framework scaffolding, frozen versions and comment-padded
handlers reported as copies to merge. Each is pinned next to a true copy that must stay reported."""

import unittest

from codefactory.analyzers.generic import available
from codefactory.cli import build
from codefactory.paths import deliberate_copies
from codefactory.review import Review, _frozen_versions
from tests.test_large_repo import repo
from tests.test_typescript import available as ts_available


def copied(files) -> str:
    """The evidence of the "Copied logic" finding, or "" when there is none."""
    root = repo(files)
    r = Review(build(root, cache=False).to_dict(), root)
    r.run()
    found = next((f for f in r.findings if f.title.startswith("Copied logic")), None)
    return "\n".join(found.evidence) if found else ""


GO_SWAGGER = "".join(f"\t// - name: p{i}\n\t//   in: path\n\t//   type: string\n" for i in range(10))
GO_BODY = """	review, _, statusSet := prepareSingleReview(ctx)
	if statusSet {
		return
	}

	api, err := convert.CONVERT(ctx, review, ctx.Doer)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
EXTRA
	ctx.JSON(http.StatusOK, api)
}
"""
GO_EXTRA = "".join(f'\tif ctx.Written{i}() {{\n\t\tctx.Log("step {i}", review.ID)\n\t}}\n' for i in range(3))


def go_handlers(extra: str = "") -> str:
    out = "package repo\n\n"
    for name, conv in (("GetPullReview", "ToPullReview"), ("GetPullReviewComments", "ToPullReviewCommentList")):
        out += f"func {name}(ctx *context.APIContext) {{\n{GO_SWAGGER}\n"
        out += GO_BODY.replace("CONVERT", conv).replace("EXTRA", extra) + "\n"
    return out


class CopiesTest(unittest.TestCase):
    @unittest.skipUnless(available(), "needs the language pack (Go is parsed with tree-sitter)")
    def test_swagger_comments_do_not_make_a_short_handler_long(self):  # gitea: "88% similar, ~48 lines"
        self.assertNotIn("GetPullReview", copied({"routers/pull_review.go": go_handlers()}))
        # the same edit with real code around it is a copy worth sharing
        self.assertIn("GetPullReview", copied({"routers/pull_review.go": go_handlers(GO_EXTRA)}))

    @unittest.skipUnless(available(), "needs the language pack")
    def test_a_function_called_through_call_keeps_its_name(self):  # n8n: googleApiRequest.call vs apiRequest.call
        from tree_sitter_language_pack import get_parser

        from codefactory.analyzers.treewalk import walk

        src = "async function f%s() {\n  const q = { fields: 'sheets' };\n  return await %s.call(this, 'GET', q);\n}\n"
        toks = [walk((src % (i, h)).encode(), get_parser("typescript"), "x.ts")["functions"][0]["tokens"]
                for i, h in ((1, "googleApiRequest"), (2, "apiRequest"))]  # fmt: skip
        self.assertNotEqual(*toks)

    def test_build_scripts_and_redated_steps_are_deliberate(self):  # hoppscotch build.rs, owid polio_deaths
        self.assertTrue(deliberate_copies(["plugins/tauri-plugin-relay/build.rs", "plugins/tauri-plugin-app/build.rs"]))
        self.assertTrue(deliberate_copies(["meadow/reports/2025-03-14/polio.py", "meadow/cdc/2025-03-14/polio.py",
                                           "meadow/cdc/2026-11-06/polio.py"]))  # fmt: skip
        self.assertFalse(deliberate_copies(["crates/a/src/lib.rs", "crates/b/src/lib.rs"]))
        self.assertFalse(deliberate_copies(["faostat/2026-11-23/faostat_fbs.py", "faostat/2026-11-23/shared.py"]))

    def test_versioned_node_folders_are_frozen(self):  # n8n's Sheet/v1, Sheet/v2; meilisearch's live reader/v2..v5
        known = {"Sheet/v1/GoogleSheetsV1.node.ts", "Sheet/v1/GoogleSheet.ts", "Sheet/v2/GoogleSheetsV2.node.ts",
                 "Sheet/v2/helpers/GoogleSheet.ts", "reader/v2/mod.rs", "reader/v3/mod.rs"}  # fmt: skip
        self.assertTrue(_frozen_versions(["Sheet/v1/GoogleSheet.ts", "Sheet/v2/helpers/GoogleSheet.ts"], known))
        self.assertFalse(_frozen_versions(["reader/v2/mod.rs", "reader/v3/mod.rs"], known))
        sheet = ("class GoogleSheet:\n    def get_sheets(self):\n        query = {'fields': 'sheets.properties'}\n"
                 "        response = api_request(self.fns, 'GET', f'/v4/spreadsheets/{self.id}', {}, query)\n"
                 "        if not response:\n            raise ValueError('no sheets')\n"
                 "        return response['sheets']\n")  # fmt: skip
        frozen = {"nodes/Sheet/v1/sheet.py": sheet, "nodes/Sheet/v1/SheetV1.node.py": "X = 1\n",
                  "nodes/Sheet/v2/sheet.py": sheet, "nodes/Sheet/v2/SheetV2.node.py": "X = 2\n"}  # fmt: skip
        self.assertNotIn("get_sheets", copied(frozen))
        self.assertIn("get_sheets", copied({"reader/v2/sheet.py": sheet, "reader/v3/sheet.py": sheet}))

    def test_a_step_template_next_to_its_shared_module(self):  # owid/etl: run() in every war step
        run = ("from shared import make_tables\n\n\ndef run(dest_dir):\n    ds = paths.load_dependency(NAME)\n"
               "    tb = ds[NAME]\n    df = clean_df(tb)\n    tables = make_tables(df, NAME)\n"
               "    ds_garden = create_dataset(dest_dir, tables=tables, default_metadata=ds.metadata)\n"
               "    ds_garden.save()\n    log.info('end')\n")  # fmt: skip
        steps = {"steps/war/2023-01-18/sorokin_1937.py": run, "steps/war/2023-01-18/kaye_1985.py": run}
        shared = {"steps/war/2023-01-18/shared.py": "def make_tables(df, n):\n    return [df]\n"}
        self.assertNotIn("run", copied({**steps, **shared}))
        self.assertIn("run", copied(steps))  # no shared module: the step logic itself is copied
        load = run.replace("def run(", "def load_data(")  # a helper pasted next to shared.py stays a copy
        self.assertIn("load_data", copied({"fao/a.py": load, "fao/b.py": load, "fao/shared.py": "X = 1\n"}))

    @unittest.skipUnless(ts_available(), "Node.js and the typescript package are needed")
    def test_a_file_routes_component_reading_its_own_route(self):  # appwrite: TanStack Router ColumnsPage
        page = ("import { createFileRoute } from '@tanstack/react-router'\nimport { Workspace } from './View'\n\n"
                "export const Route = createFileRoute('/x')({ component: ColumnsPage })\n\n"
                "function ColumnsPage() {\n  const { databaseId, tableId } = Route.useParams()\n\n  return (\n"
                "    <Workspace databaseId={databaseId} tableId={tableId} activeTab=\"columns\" />\n  )\n}\n")  # fmt: skip
        routes = {"src/routes/tables.columns.tsx": page, "src/routes/collections.columns.tsx": page}
        self.assertNotIn("ColumnsPage", copied(routes))
        # the same few lines reading a shared hook are logic that could live once
        shared = {k: v.replace("Route.useParams()", "useWorkspaceParams()") for k, v in routes.items()}
        self.assertIn("ColumnsPage", copied(shared))


if __name__ == "__main__":
    unittest.main()
