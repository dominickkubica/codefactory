"""Findings from a security audit of codefactory itself (0.20.3): what a repository being analyzed, or a pull request
to it, could make codefactory do. Each test is one finding, attacked the way the auditors described."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from codefactory import cache, paths
from codefactory.analyzers.typescript import TypeScriptUnavailable, find_typescript, has_api
from codefactory.checks import redact, scan_sources, source_files
from codefactory.cli import build, main
from codefactory.sarif import gha_command
from codefactory.sqlgraph import query_flags

ROOT = Path(__file__).parent.parent
KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
NEW = "def find(conn, name):\n    return conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"


def repo(d: str, files: dict[str, str]) -> list[str]:
    git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    for name, text in files.items():
        (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
        (Path(d) / name).write_text(text, encoding="utf-8")
    subprocess.run([*git, "add", "-A", "-f"], check=True)
    subprocess.run([*git, "commit", "-qm", "base"], check=True)
    return git


def diff_json(d: str) -> dict:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        main(["diff", d, "--base", "main", "--json"])
    return json.loads(out.getvalue())


class CacheFolderTest(unittest.TestCase):
    def test_a_symlinked_cache_folder_is_never_written_or_cleaned_through(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as victim:
            for name in ("keep1", "keep2", "keep3", "keep4"):  # what the diff's cleanup would have deleted
                (Path(victim) / name).mkdir()
            git = repo(d, {"app.py": "x = 1\n"})
            os.symlink(victim, Path(d) / ".codefactory")
            subprocess.run([*git, "add", ".codefactory"], check=True)
            subprocess.run([*git, "commit", "-qm", "plant a link"], check=True)
            subprocess.run([*git, "checkout", "-qb", "feature"], check=True)
            (Path(d) / "app.py").write_text(NEW, encoding="utf-8")
            self.assertIsNone(paths.cache_dir(d))
            result = diff_json(d)
            self.assertEqual(sorted(p.name for p in Path(victim).iterdir()), ["keep1", "keep2", "keep3", "keep4"])
            self.assertIn("sql_built", [i["kind"] for i in result["new"]])  # and the diff still works

    def test_a_link_inside_the_cache_folder_is_removed_not_followed(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as victim:
            for name in ("keep1", "keep2", "keep3", "keep4"):
                (Path(victim) / name).mkdir()
            repo(d, {"app.py": "x = 1\n"})
            (Path(d) / ".codefactory").mkdir()
            os.symlink(victim, Path(d) / ".codefactory" / "diff")
            (Path(d) / "app.py").write_text(NEW, encoding="utf-8")
            diff_json(d)
            self.assertEqual(len(list(Path(victim).iterdir())), 4)

    def test_a_planted_base_cache_doesnt_hide_new_findings(self):
        with tempfile.TemporaryDirectory() as d:
            git = repo(d, {"app.py": "x = 1\n"})
            sha = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            subprocess.run([*git, "checkout", "-qb", "feature"], check=True)
            # the pull request: new SQL injection, plus a fake "base" that already has it
            planted = Path(d) / ".codefactory" / "diff" / sha[:12]
            planted.mkdir(parents=True)
            (planted / "app.py").write_text(NEW, encoding="utf-8")
            (planted / ".complete").write_text(sha, encoding="utf-8")
            (Path(d) / "app.py").write_text(NEW, encoding="utf-8")
            subprocess.run([*git, "add", "-A", "-f"], check=True)
            subprocess.run([*git, "commit", "-qm", "pr"], check=True)
            self.assertIsNone(paths.cache_dir(d))  # committed: not trusted
            self.assertIn("sql_built", [i["kind"] for i in diff_json(d)["new"]])

    def test_an_ordinary_cache_folder_is_still_used(self):
        with tempfile.TemporaryDirectory() as d:
            repo(d, {"app.py": "x = 1\n"})
            self.assertEqual(paths.cache_dir(d), Path(d).resolve() / ".codefactory")


def fake_ts(folder: Path) -> Path:
    (folder / "lib").mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text('{"name": "typescript"}', encoding="utf-8")
    (folder / "lib" / "typescript.js").write_text("module.exports = {};\n", encoding="utf-8")
    return folder


class ProjectTypeScriptTest(unittest.TestCase):
    def test_the_repositorys_own_compiler_is_never_run(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as home:
            root = Path(d)
            fake_ts(root / "node_modules" / "typescript")  # installed or committed: the repository's code either way
            (root / ".npmrc").write_text(f"prefix={root / 'evil'}\n", encoding="utf-8")  # and npm pointed back inside
            fake_ts(root / "evil" / "lib" / "node_modules" / "typescript")
            env = {k: v for k, v in os.environ.items() if k != "CODEFACTORY_TYPESCRIPT"}
            with mock.patch.dict(os.environ, env, clear=True), mock.patch("pathlib.Path.home", return_value=Path(home)):
                cwd = os.getcwd()
                os.chdir(root)  # as when run from inside the repository
                try:
                    # node found inside the repository (node_modules/.bin on PATH during `npm run`), a compiler next to it
                    fake_ts(root / "tools" / "lib" / "node_modules" / "typescript")
                    found = find_typescript(root, str(root / "tools" / "bin" / "node"))
                except TypeScriptUnavailable:
                    found = ""
                finally:
                    os.chdir(cwd)
            self.assertFalse(found.startswith(str(root.resolve())) or found.startswith(str(root)), found)

    def test_typescript_7_has_no_api_to_run(self):
        with tempfile.TemporaryDirectory() as d:
            ts = Path(d) / "typescript"
            (ts / "lib").mkdir(parents=True)
            self.assertFalse(has_api(ts))  # TypeScript 7: lib/version.cjs, no lib/typescript.js
            self.assertTrue(has_api(fake_ts(ts)))

    def test_security_md_says_what_it_does(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("It never runs the code it analyzes.", text)
        self.assertIn("never one inside the analyzed", text)


class SecretsTest(unittest.TestCase):
    def test_reported_secrets_are_cut_to_four_characters(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            aws = "AKIA" + "ABCDEFGHIJKLMNOP"  # built here so the file itself holds no key-shaped string
            (root / "config.py").write_text(f'STRIPE_KEY = "{KEY}"\nAWS = "{aws}"\n', encoding="utf-8")
            checks = scan_sources(root, source_files(root, build(root, cache=False).to_dict()))
            texts = [e.text for e in checks["secret"].hits]
            self.assertEqual(len(texts), 2)
            self.assertFalse(any("4eC39Hq" in t or "ABCDEFGHIJ" in t for t in texts), texts)
            sarif = Path(d) / "out.sarif"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["sarif", d, "-o", str(sarif)])
            self.assertIn("STRIPE_KEY", sarif.read_text(encoding="utf-8"))
            self.assertNotIn("4eC39Hq", sarif.read_text(encoding="utf-8"))

    def test_redact(self):
        self.assertEqual(redact(f'k = "{KEY}"'), 'k = "sk_l…"')
        self.assertEqual(redact("AZURE_OPENAI_KEY=abcd1234efgh5678"), "AZURE_OPENAI_KEY=abcd…")
        self.assertEqual(redact("def get_token(self):"), "def get_token(self):")


class WorkflowCommandTest(unittest.TestCase):
    def test_messages_and_properties_are_escaped(self):
        line = gha_command("error", "a,b:c.py", 3, "codefactory x", "bad\n::add-mask::x 100%")
        self.assertEqual(line.count("\n"), 0)  # one command: a newline would start another
        self.assertIn("file=a%2Cb%3Ac.py,", line)
        self.assertTrue(line.endswith("::bad%0A::add-mask::x 100%25"))


class SavedQueryTest(unittest.TestCase):
    def test_saved_queries_can_only_read(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "written.db"
            g = {"files": [], "functions": [], "edges": [], "flags": []}
            for sql in (f"ATTACH DATABASE '{target}' AS x", "CREATE TABLE t(x)", "PRAGMA writable_schema = 1"):
                with self.assertRaisesRegex(ValueError, "can only read"):
                    query_flags(g, [{"name": "q", "sql": sql}])
            self.assertFalse(target.exists())
            self.assertEqual(query_flags(g, [{"name": "q", "sql": "SELECT id AS target FROM files"}]), [])


class ActionTest(unittest.TestCase):
    def test_action_pins_what_it_installs_and_skips_comments_on_forks(self):
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("--require-hashes", action)
        self.assertNotIn('pip install --quiet "$SOURCE', action)  # codefactory runs from the action's own files
        self.assertIn("typescript@5.9.3", action)
        self.assertNotIn("project-typescript", action)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", action)
        pins = (ROOT / "action-requirements.txt").read_text(encoding="utf-8")
        for name in ("tree-sitter==", "tree-sitter-language-pack=="):
            block = pins.split(name, 1)[1].split("\n\n")[0]
            self.assertIn("--hash=sha256:", block)


class StaleCacheTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Windows reports the creation time, not the change time")
    def test_a_copy_that_keeps_the_old_time_is_still_a_change(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "app.py"
            f.write_text("x = 1\n", encoding="utf-8")
            old = time.time() - 60
            os.utime(f, (old, old))
            before = cache.fingerprint(Path(d), [])
            time.sleep(0.01)
            f.write_text("x = 2\n", encoding="utf-8")  # same size
            os.utime(f, (old, old))  # and the old modification time (cp -p, tar, rsync -t)
            self.assertNotEqual(before, cache.fingerprint(Path(d), []))  # the change time still moved

    def test_files_changed_this_moment_are_not_cached(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.py").write_text("x = 1\n", encoding="utf-8")
            recent: list = []
            cache.fingerprint(Path(d), [], recent)
            self.assertEqual(recent, [True])
            cache.save_cache(Path(d), [], {"files": []})
            self.assertFalse((Path(d) / ".codefactory" / "graph.json").exists())


if __name__ == "__main__":
    unittest.main()
