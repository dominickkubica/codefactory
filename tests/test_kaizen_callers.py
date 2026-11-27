"""A parameter put into SQL, HTML or a shell command is as risky as what its callers pass: when every caller in the
repository passes a literal or an escaped value, nothing from outside reaches the line (codefactory/callers.py)."""

import unittest

from codefactory.checks import scan_sources
from tests.test_large_repo import repo

GO_INDEX = """package db

func mysqlNextIndex(ctx context.Context, tableName string, groupID int64) (int64, error) {
\tif _, err := GetEngine(ctx).Exec(fmt.Sprintf("INSERT INTO %s (group_id, max_index) "+
\t\t"VALUES (?,1) ON DUPLICATE KEY UPDATE max_index = max_index+1",
\t\ttableName), groupID); err != nil {
\t\treturn 0, err
\t}
\treturn 0, nil
}

func NextIndex(ctx context.Context, tableName string, groupID int64) (int64, error) {
\treturn mysqlNextIndex(ctx, tableName, groupID)
}
"""
GO_CALLERS = """package issues

func newIssue(ctx context.Context, repo *Repo) {
\tidx, err := db.NextIndex(ctx, "issue_index", repo.ID)
}

func newRun(ctx context.Context, run *Run) {
\tidx, err := db.NextIndex(ctx, "action_run_index", run.RepoID)
}
"""
JS_NOTICE = """const chartEl = document.getElementById("chart");
function esc(text) { return String(text).replace(/[&<>]/g, ""); }

function showNotice(message) {
  disposeChart();
  chartEl.innerHTML = `<div class="notice">${message}</div>`;
}

function render(err, link) {
  if (!link) return showNotice("Every dropdown needs at least one option.");
  showNotice(`Couldn't load indicator ${link.id}: ${esc(err.message)}`);
  return showNotice(link.ready
    ? "Start by linking an indicator."
    : "No indicator linked yet.");
}
showNotice("Loading Grapher…");
"""


def hits(found, key):
    return [(e.file, e.line) for e in found[key].hits]


def scan(files):
    return scan_sources(repo(files), list(files))


class CallersTest(unittest.TestCase):
    def test_go_table_name_fixed_at_every_caller(self):
        found = scan({"models/db/index.go": GO_INDEX, "models/issues/issue.go": GO_CALLERS})
        self.assertEqual(hits(found, "sql_built"), [])

    def test_go_table_name_from_a_variable_is_reported(self):
        callers = GO_CALLERS + '\nfunc fromUser(ctx context.Context, r *http.Request) {\n' \
                               '\tdb.NextIndex(ctx, r.FormValue("table"), 1)\n}\n'  # fmt: skip
        found = scan({"models/db/index.go": GO_INDEX, "models/issues/issue.go": callers})
        self.assertEqual(hits(found, "sql_built"), [("models/db/index.go", 4)])

    def test_go_without_callers_is_reported(self):
        found = scan({"models/db/index.go": GO_INDEX})
        self.assertEqual(hits(found, "sql_built"), [("models/db/index.go", 4)])

    def test_js_notice_with_constant_and_escaped_callers(self):
        self.assertEqual(hits(scan({"app/simulator.js": JS_NOTICE}), "raw_html"), [])

    def test_js_notice_with_a_user_value_is_reported(self):
        for call in ("showNotice(location.hash);", "showNotice(`Hello ${params.get('name')}`);",
                     "const q = input.value;\nshowNotice(q);"):  # fmt: skip
            found = scan({"app/simulator.js": JS_NOTICE + call + "\n"})
            self.assertEqual(hits(found, "raw_html"), [("app/simulator.js", 6)], call)

    def test_js_notice_with_a_caller_in_another_file(self):
        other = "import { showNotice } from './simulator.js';\nshowNotice(document.cookie);\n"
        found = scan({"app/simulator.js": JS_NOTICE, "app/other.js": other})
        self.assertEqual(hits(found, "raw_html"), [("app/simulator.js", 6)])

    def test_js_notice_without_callers_is_reported(self):
        lone = "function showNotice(message) {\n  chartEl.innerHTML = `<div>${message}</div>`;\n}\n"
        self.assertEqual(hits(scan({"app/notice.js": lone}), "raw_html"), [("app/notice.js", 2)])

    def test_python_sql_with_literal_callers(self):
        code = ("def tally(cur, table):\n    cur.execute(f\"SELECT count(*) FROM {table}\")\n\n\n"
                "tally(cur, 'users')\ntally(cur, table='orders')\n")  # fmt: skip
        self.assertEqual(hits(scan({"app/db.py": code}), "sql_built"), [])
        code += "tally(cur, request.args['t'])\n"
        self.assertEqual(hits(scan({"app/db.py": code}), "sql_built"), [("app/db.py", 2)])


if __name__ == "__main__":
    unittest.main()
