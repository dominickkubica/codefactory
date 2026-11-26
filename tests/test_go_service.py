"""False positives from reviewing a Go service (findings its maintainer triaged as wrong), each rebuilt in miniature:
a subfolder review missing the repository's CI and README, calls matched by name read as N+1 queries, batched and
migration loops, tests reaching methods through an interface, a constant string flagged as XSS, and Go's standard
library `sync` taken for the repository's own `sync` package."""

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.analyzers.generic import available
from codefactory.checks import scan_repo, scan_sources
from codefactory.cli import build
from codefactory.review import Review

GO_MOD = "module example.com/svc\n\ngo 1.22\n"
WEB = """
package web

import (
\t"database/sql"
\t"net/http"
)

type Server struct{ db *sql.DB }

func (s *Server) SetCookies(w http.ResponseWriter, names []string) {
\tfor _, n := range names {
\t\thttp.SetCookie(w, &http.Cookie{Name: n})
\t}
}

func (s *Server) Routes(r Router, paths []string) {
\tfor _, p := range paths {
\t\tr.Get("/api/"+p, s.handle)
\t}
}

func NewServer(registries []string) *Server {
\tfor _, u := range registries {
\t\thttp.Get(u + "/certs")
\t}
\treturn &Server{}
}

func (s *Server) Report(ids []int) {
\tfor _, id := range ids {
\t\ts.db.Query("SELECT name FROM users WHERE id = $1", id)
\t}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {}

type Router interface{ Get(string, http.HandlerFunc) }
"""
STORE = """
package store

import "database/sql"

type Chunks struct{ db *sql.DB }

func (c *Chunks) DeleteChunks(keys []string) {
\tfor i := 0; i < len(keys); i += 1000 {
\t\tc.db.Exec("DELETE FROM chunks WHERE key = ANY($1)", keys[i:i+1000])
\t}
}

func (c *Chunks) BulkUpdateMembers(ids []int) error {
\t_, err := c.db.Exec("UPDATE members SET seen = now() WHERE id = ANY($1)", ids)
\treturn err
}
"""
STORE_TEST = """
package store_test

import "testing"

type updater interface{ BulkUpdateMembers([]int) error }

func TestBulkUpdate(t *testing.T) {
\tvar s updater = newStore(t)
\tif err := s.BulkUpdateMembers([]int{1}); err != nil {
\t\tt.Fatal(err)
\t}
}
"""


def go_repo() -> Path:
    top = Path(tempfile.mkdtemp())
    files = {
        "go.mod": GO_MOD, "README.md": "# svc\n\nRun: go run ./cmd/svc\n", "rio.yml": "pipeline:\n  - go test ./...\n",
        "internal/web/web.go": WEB, "internal/store/store.go": STORE, "internal/store/store_test.go": STORE_TEST,
        # several stores implement the same interface (CockroachDB, Postgres, memory…): calling the method by name
        # is ambiguous, so the call graph can't link a test's `s.BulkUpdateMembers` to any one of them
        "internal/store/others.go": "package store\n\n" + "".join(
            f"type {k} struct{{}}\n\nfunc (x *{k}) BulkUpdateMembers(ids []int) error {{ return nil }}\n\n"
            for k in ("Memory", "Postgres", "Cockroach", "Fake")),
        "internal/sync/sync.go": "package sync\n\nfunc Run() {}\n",
        "internal/auth/auth.go": 'package auth\n\nimport "sync"\n\nvar mu sync.Mutex\n\nfunc Check() { mu.Lock() }\n',
        "internal/web/token_ui.go": 'package web\n\nconst page = `<script>\nel.innerHTML = "<b>Copied</b>";\n</script>`\n',
    }  # fmt: skip
    for name, text in files.items():
        (top / name).parent.mkdir(parents=True, exist_ok=True)
        (top / name).write_text(textwrap.dedent(text), encoding="utf-8")
    subprocess.run(["git", "-C", str(top), "init", "-q"], check=True)
    return top


class RepositoryLevelTest(unittest.TestCase):
    def test_a_subfolder_review_finds_the_repositorys_ci_and_readme(self):
        top = go_repo()
        info = scan_repo(top / "internal")  # reviewing internal/ only
        self.assertEqual(info["ci"], ["../rio.yml"])  # a CI system beyond GitHub, GitLab and Jenkins, one level up
        self.assertEqual(info["readme"], "../README.md")
        self.assertIn("tests", info["ci_steps"])

    def test_constant_html_isnt_xss(self):
        top = go_repo()
        hits = scan_sources(top, ["internal/web/token_ui.go"])["raw_html"].hits
        self.assertEqual(hits, [])


@unittest.skipUnless(available(), "needs the tree-sitter language pack")
class GoAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.top = go_repo()
        self.g = build(self.top, cache=False).to_dict()

    def test_only_the_real_n_plus_one_is_a_warning(self):
        loops = {f["target"].split("::")[-1]: f["severity"] for f in self.g["flags"] if f["kind"] == "io_in_loop"}
        self.assertEqual(loops.get("Server.Report"), "warn")  # a query per id: the real one
        for not_io in ("Server.SetCookies", "Server.Routes", "Chunks.DeleteChunks"):
            self.assertNotIn(not_io, loops)  # setting a header, registering routes, deleting in batches of 1000
        self.assertEqual(loops.get("NewServer"), "info")  # once per configured registry, at startup

    def test_standard_library_imports_arent_the_repositorys_packages(self):
        imports = {(e["src"], e["dst"]) for e in self.g["edges"] if e["kind"] == "import"}
        self.assertNotIn(("internal/auth/auth.go", "internal/sync/sync.go"), imports)

    def test_a_method_tests_call_through_an_interface_is_reached(self):
        r = Review(self.g, self.top)
        r.run()
        self.assertIn("internal/store/store.go::Chunks.BulkUpdateMembers", r.reached)


class NothingAnalyzedTest(unittest.TestCase):
    """A TypeScript repository on a machine without a TypeScript compiler or the language pack: nothing was analyzed,
    and the review graded it "Strong" and said there were no tests (there were hundreds)."""

    def test_a_review_of_unanalyzed_code_isnt_graded(self):
        import contextlib
        import io
        from unittest import mock

        from codefactory.analyzers.typescript import TypeScriptUnavailable

        root = Path(tempfile.mkdtemp())
        (root / "src").mkdir()
        (root / "src" / "store.ts").write_text("export function save(db: any) { return db.run('x'); }\n", encoding="utf-8")
        (root / "src" / "store.test.ts").write_text("import { save } from './store';\ntest('s', () => save({}));\n")
        with mock.patch("codefactory.analyzers.analyze_typescript", side_effect=TypeScriptUnavailable("no compiler.")), \
             mock.patch("codefactory.analyzers.generic.available", return_value=False), \
             contextlib.redirect_stderr(io.StringIO()) as err:  # fmt: skip
            g = build(root, cache=False).to_dict()
            r = Review(g, root)
            r.run()
            text = r.markdown()
        self.assertEqual(g["files"], [])
        self.assertIn("NOT analyzed", err.getvalue())
        self.assertEqual(r.health()[0], "Not assessed")
        self.assertIn("npm install -g typescript@5", text)
        self.assertNotIn("No automated tests", [f.title for f in r.findings])  # the test file is on disk
        self.assertIn("**Tests:** 1 test files", text)


if __name__ == "__main__":
    unittest.main()
