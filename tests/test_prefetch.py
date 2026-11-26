"""The change prefetch: a prompt hook that hands an agent the definitions, callers, tests, string registrations and
doc mentions of what the prompt names, from an index built ahead of time, leaving out files changed since."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from codefactory.cli import build, main
from codefactory.prefetch import answer, bare, names, write_index


def project() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "app").mkdir()
    (root / "tests").mkdir()
    (root / "app" / "cli.py").write_text(
        textwrap.dedent("""
        import argparse
        from app.trades import recent


        def _cmd_forward_test(args):
            for t in recent(args.n):
                print(t)


        def _cmd_health(args):
            print("ok")


        def health():
            return 1


        def _list(items):
            return list(items)


        def main(argv=None):
            p = argparse.ArgumentParser()
            sub = p.add_subparsers(dest="cmd")
            sub.add_parser("forward-test")
            sub.add_parser("health")
            handlers = {"forward-test": _cmd_forward_test, "health": _cmd_health}
            a = p.parse_args(argv)
            handlers[a.cmd](a)
        """)
    )
    (root / "app" / "trades.py").write_text("def recent(n):\n    return list(range(n))\n")
    (root / "tests" / "test_cli.py").write_text(
        "from app.cli import _cmd_forward_test\n\n\ndef test_forward():\n    _cmd_forward_test(None)\n"
    )
    (root / "README.md").write_text("# app\n\nRun `app forward-test` to see recent trades.\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def context(root: Path, prompt: str) -> str:
    return answer(root, json.loads((root / ".codefactory" / "prefetch.json").read_text()), prompt)


class PrefetchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = project()
        write_index(cls.root, build(cls.root, ["python"]).to_dict())

    def test_names(self):
        self.assertEqual(bare("_cmd_forward_test"), "forward_test")
        self.assertEqual(bare("forwardTest"), "forward_test")
        keys, phrases = names("Add --limit to the `app forward-test` command")
        self.assertIn("forward_test", keys)
        self.assertIn("app forward-test", phrases)

    def test_a_command_is_located_with_callers_calls_tests_strings_and_docs(self):
        text = context(self.root, "Add a --limit N option to the `app forward-test` command.")
        self.assertIn("`_cmd_forward_test` app/cli.py:6-8", text)
        self.assertIn("recent app/trades.py:1", text)  # what it calls
        self.assertIn("tests: tests/test_cli.py", text)
        self.assertIn('app/cli.py:26: sub.add_parser("forward-test")', text)  # where the command is registered
        self.assertIn("README.md:3", text)

    def test_a_short_word_names_the_command_not_every_function_called_that(self):
        text = context(self.root, "Make `app health` print the version too.")
        self.assertIn("_cmd_health", text)
        self.assertNotIn("`health` app/cli.py", text)
        self.assertNotIn("_list", context(self.root, "Make `app list` sort by date."))

    def test_nothing_named_nothing_added(self):
        self.assertEqual(context(self.root, "Why is the sky blue?"), "")

    def test_a_changed_file_is_left_out(self):
        root = project()
        write_index(root, build(root, ["python"]).to_dict())
        with open(root / "app" / "cli.py", "a") as f:
            f.write("\n# moved\n")
        text = context(root, "Add a --limit N option to the `app forward-test` command.")
        self.assertNotIn("app/cli.py", text)
        self.assertIn("README.md:3", text)  # unchanged files still answer

    def test_a_rewrite_with_the_same_bytes_is_still_fresh(self):  # a checkout or reset rewrites files it restores
        root = project()
        write_index(root, build(root, ["python"]).to_dict())
        path = root / "app" / "cli.py"
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        self.assertIn("_cmd_forward_test", context(root, "Change the `app forward-test` command."))

    def test_hook(self):
        root = project()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["prefetch", str(root), "--lang", "python"])
        prompt = json.dumps({"prompt": "Add --limit to the `app forward-test` command."})
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(prompt)), contextlib.redirect_stdout(out), contextlib.chdir(root):
            self.assertEqual(main(["prefetch", "--hook"]), 0)
        hook = json.loads(out.getvalue())["hookSpecificOutput"]
        self.assertEqual(hook["hookEventName"], "UserPromptSubmit")
        self.assertIn("_cmd_forward_test", hook["additionalContext"])

    def test_hook_never_fails_the_prompt(self):
        root = project()  # no index yet
        for stdin in ("not json", json.dumps({"prompt": "Change `app forward-test`."})):
            out = io.StringIO()
            with mock.patch("sys.stdin", io.StringIO(stdin)), contextlib.redirect_stdout(out), contextlib.chdir(root):
                self.assertEqual(main(["prefetch", "--hook"]), 0)
            self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
