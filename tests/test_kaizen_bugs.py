"""Bugs found by running codefactory on odd inputs (a 2 MB minified line, a byte-order mark, a folder this user can't
read, a grammar that can't download): each pinned with the input that showed it."""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from codefactory.analyzers import INCOMPLETE, generic
from codefactory.analyzers.generic import analyze_generic, available
from codefactory.cli import build, cmd_sql
from codefactory.export import _located
from tests.test_large_repo import repo

JSTAINT_APP = Path(__file__).parent / "fixtures" / "jstaintapp"


class KaizenBugsTest(unittest.TestCase):
    def test_a_minified_line_is_cut_before_it_is_redacted(self):
        # export redacted the whole line under every finding on it: 90,000 findings on one 2 MB line ran for hours
        line = "var a=" + ";".join(f"function f{i}(x){{return x+{i}}}" for i in range(80000))
        root = repo({"big.js": line + "\n"})
        seen = []

        def spy(text):
            seen.append(len(text))
            return text

        with mock.patch("codefactory.checks.redact", spy):
            out = _located(root, "`big.js:1` f5 is never called", {})
        self.assertTrue(seen and max(seen) <= 400, seen)
        self.assertIn("var a=function f0", out)
        stripe = "sk_" + "live_"  # (split so the test file itself isn't a key-shaped string)
        root = repo({"cfg.js": f'const API_KEY = "{stripe}abcdefghijklmnopqrstuvwx";\n'})
        self.assertNotIn("abcdefghijkl", _located(root, "`cfg.js:1` a secret", {}))  # still redacted

    def test_a_python_file_with_a_byte_order_mark_is_analyzed(self):
        # Windows editors write one; ast.parse on the decoded text called it a syntax error and the file vanished
        g = build(repo({"a.py": "﻿import os\n\ndef f():\n    return os.getcwd()\n"}), cache=False)
        self.assertIn("a.py::f", {f.id for f in g.functions})
        self.assertEqual(next(f.line for f in g.functions if f.id == "a.py::f"), 3)

    @unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
    def test_a_grammar_that_cannot_load_is_reported_not_dropped_quietly(self):
        # offline on first use, every Go file failed one by one inside the workers and was cached as unparseable
        import tree_sitter_language_pack

        real = tree_sitter_language_pack.get_parser

        def offline(lang):
            if lang == "go":
                raise tree_sitter_language_pack.DownloadError("Failed to fetch manifest")
            return real(lang)

        root = repo({"main.go": "package main\nfunc main() {}\n", "lib.rs": "fn helper() -> i32 { 1 }\n"})
        err = io.StringIO()
        INCOMPLETE.clear()
        with mock.patch.object(tree_sitter_language_pack, "get_parser", offline), \
                mock.patch.dict(generic._PARSERS, clear=True), contextlib.redirect_stderr(err):  # fmt: skip
            g = analyze_generic(root, [], cache=False)
        self.assertEqual([f.id for f in g.files], ["lib.rs"])
        self.assertIn("1 files in go aren't analyzed", err.getvalue())
        self.assertIn("DownloadError", err.getvalue())
        self.assertEqual(INCOMPLETE, ["go"])  # so the result isn't cached and the next run tries again
        INCOMPLETE.clear()

    @unittest.skipUnless(available() and shutil.which("node"), "needs the language pack and Node.js")
    def test_a_js_grammar_that_cannot_load_says_flows_werent_traced(self):
        import tree_sitter_language_pack

        def offline(lang):
            raise tree_sitter_language_pack.DownloadError("Failed to fetch manifest")

        err = io.StringIO()
        with mock.patch.object(tree_sitter_language_pack, "get_parser", offline), contextlib.redirect_stderr(err):
            g = build(JSTAINT_APP, cache=False)
        self.assertFalse([f for f in g.flags if f.kind == "taint"])
        self.assertIn("weren't traced", err.getvalue())
        self.assertTrue(INCOMPLETE)
        INCOMPLETE.clear()

    def test_a_typescript_analyzer_that_times_out_falls_back_instead_of_crashing(self):
        from codefactory.analyzers import typescript

        timeout = subprocess.TimeoutExpired(["node"], 1800)
        with mock.patch.object(typescript.shutil, "which", return_value="node"), \
                mock.patch.object(typescript, "find_typescript", return_value="ts"), \
                mock.patch.object(typescript.subprocess, "run", side_effect=timeout), \
                self.assertRaises(typescript.TypeScriptUnavailable) as e:  # fmt: skip
            typescript._run_helper(Path(tempfile.mkdtemp()), [])
        self.assertIn("timed out", str(e.exception))

    def test_sql_to_a_path_it_cannot_write_is_an_error_message_not_a_traceback(self):
        root = repo({"a.py": "def f():\n    return 1\n"})
        target = Path(tempfile.mkdtemp())  # a folder where the database file should be
        args = SimpleNamespace(path=str(root), lang=None, no_cache=True, output=str(target))
        with self.assertRaises(SystemExit) as e:
            cmd_sql(args)
        self.assertIn("can't save", str(e.exception))

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "root reads every folder")
    def test_a_folder_this_user_cannot_read_is_skipped(self):
        # the TypeScript helper's walk threw EACCES (the whole type-checker analysis fell back to by-name), and the
        # profile's and CI's folder listings raised PermissionError out of the review
        from codefactory.review import review_markdown

        root = repo({"src/app.ts": "export function used() { return 1 }\nused();\n", "package.json": "{}",
                     "secret/package.json": "{}", ".github/workflows/ci.yml": "on: push\n",
                     "app.py": "def f():\n    return 1\n"})  # fmt: skip
        (root / "secret").chmod(0)
        (root / ".github" / "workflows").chmod(0)
        try:
            g = build(root, cache=False)
            self.assertIn("src/app.ts", {f.id for f in g.files})
            self.assertIn("# Technical review", review_markdown(g.to_dict(), root))
        finally:
            (root / "secret").chmod(0o755)
            (root / ".github" / "workflows").chmod(0o755)

    def test_a_python_file_with_a_syntax_error_is_reported_not_dropped_quietly(self):
        # it vanished from the map with no note anywhere: not on stderr, not in the review's limits
        from codefactory.review import Review

        root = repo({"a.py": "def f():\n    return 1\n", "c.py": "def broken(:\n    pass\n"})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            g = build(root, cache=False)
        self.assertEqual([f.id for f in g.files], ["a.py"])
        self.assertIn("1 Python files aren't analyzed", err.getvalue())
        self.assertIn("c.py line 1", err.getvalue())
        limits = Review(g.to_dict(), root).limits()
        self.assertIn("Not analyzed (this Python can't parse them): 1 Python file.", limits)

    @unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
    def test_python_newer_than_the_running_one_is_analyzed_by_tree_sitter(self):
        # `except A, B:` is 3.14 (PEP 758), as `def f[T]()` is 3.12: on an older Python the file's functions vanished
        newer = "def used():\n    try:\n        return helper()\n    except ValueError, TypeError:\n        return 0\n"
        try:
            compile(newer, "b.py", "exec")
            self.skipTest("this Python parses it")
        except SyntaxError:
            pass
        root = repo({"a.py": "from b import used\n\ndef main():\n    return used()\n\n\ndef only_b_calls():\n"
                             "    return 1\n",
                     "b.py": newer + "\n\ndef helper():\n    return only_b_calls()\n"})  # fmt: skip
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            g = build(root, cache=False)
        ids = {f.id for f in g.functions}
        self.assertTrue({"b.py::used", "b.py::helper", "a.py::main"} <= ids, ids)
        self.assertIn("syntax newer than Python", err.getvalue())
        self.assertNotIn("aren't analyzed", err.getvalue())
        unused = {f.target for f in g.flags if f.kind == "unused"}
        self.assertFalse({"b.py::used", "a.py::only_b_calls"} & unused, unused)  # name-matched both ways

    def test_review_limits_count_only_files_an_analyzer_would_have_read(self):
        # .github/ scripts, SQL and folders the config ignores were all listed as "Not analyzed"
        root = repo({"app.py": "def f():\n    return 1\n", ".github/scripts/release.sh": "echo hi\n",
                     "db/schema.sql": "CREATE TABLE t (id int);\n", "build/gen.go": "package gen\n",
                     "factory.toml": 'ignore = ["third"]\n', "third/x.rb": "def x; end\n"})  # fmt: skip
        from codefactory.review import Review

        with contextlib.redirect_stderr(io.StringIO()):
            g = build(root, cache=False)
        limits = Review(g.to_dict(), root).limits()
        self.assertFalse([x for x in limits if x.startswith("Not analyzed")], limits)

    @unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
    def test_a_file_the_general_analyzer_skips_is_noted(self):
        # over 1 MB (or binary): left out with nothing on stderr
        root = repo({"main.go": "package main\nfunc main() {}\n",
                     "big.go": "package main\n" + "// padding\n" * 100_000 + "func big() {}\n"})  # fmt: skip
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            g = analyze_generic(root, [], cache=False)
        self.assertEqual([f.id for f in g.files], ["main.go"])
        self.assertIn("1 files aren't analyzed: over 1 MB, binary or not parseable (big.go)", err.getvalue())

    def test_a_typescript_helper_failure_says_what_failed(self):
        # "failed" alone, and output that wasn't JSON was a traceback rather than the fallback
        from codefactory.analyzers import typescript

        crash = subprocess.CompletedProcess([], 1, "", "/x/ts_helper.js:9\nTypeError: ts.foo is not a function\n"
                                                       "    at Object.<anonymous> (/x/ts_helper.js:9:4)\n")  # fmt: skip
        cut = subprocess.CompletedProcess([], 0, '{"files": [', "")
        said_crash = "failed on this project (Node.js heap 4096 MB): TypeError: ts.foo is not a function."
        for proc, said in [(crash, said_crash), (cut, "wasn't readable (not JSON)")]:
            with mock.patch.object(typescript.shutil, "which", return_value="node"), \
                    mock.patch.object(typescript, "find_typescript", return_value="ts"), \
                    mock.patch.object(typescript, "heap_mb", return_value=4096), \
                    mock.patch.object(typescript.subprocess, "run", return_value=proc), \
                    self.assertRaises(typescript.TypeScriptUnavailable) as e:  # fmt: skip
                typescript._run_helper(Path(tempfile.mkdtemp()), [])
            self.assertIn(said, str(e.exception))

    def test_corpus_results_keep_the_runs_notes(self):
        # a run that fell back to the general analyzer, or left files out, looked like any other in results.json
        from tools.corpus import notes

        stderr = ("codefactory: The TypeScript analyzer ran out of memory. Using the general analyzer instead.\n"
                  "Traceback noise\ncodefactory: 2 Python files aren't analyzed: x\n"
                  "codefactory: 2 Python files aren't analyzed: x\n")  # fmt: skip
        self.assertEqual(len(notes(stderr)), 2)
        self.assertEqual(notes(""), [])


if __name__ == "__main__":
    unittest.main()
