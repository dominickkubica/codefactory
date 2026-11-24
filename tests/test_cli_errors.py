"""The command line fails politely: messages a user can act on, never a traceback (unless --debug)."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from codefactory import cli
from tests.test_rules import project


def run(*args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as e:  # argparse and explicit exits
            code = e.code if isinstance(e.code, int) else (err.write(str(e.code)) and 1)
    return code, out.getvalue(), err.getvalue()


class CliErrorTest(unittest.TestCase):
    def test_bad_factory_toml(self):
        root = project({"factory.toml": "[rules\nforbid = 1\n", "a.py": "x = 1\n"})
        code, _, err = run("flags", str(root), "--no-cache")
        self.assertEqual(code, 2)
        self.assertIn("factory.toml isn't valid TOML", err)
        self.assertNotIn("Traceback", err)

    def test_bad_rule(self):
        root = project({"factory.toml": '[rules]\nforbid = ["ui db"]\n', "a.py": "x = 1\n"})
        code, _, err = run("flags", str(root), "--no-cache")
        self.assertEqual(code, 2)
        self.assertIn("write it as 'ui -> db'", err)

    def test_missing_folder(self):
        code, _, err = run("flags", "/no/such/folder")
        self.assertNotEqual(code, 0)
        self.assertIn("is not a folder", err)

    def test_unexpected_error_is_short_unless_debug(self):
        root = project({"a.py": "x = 1\n"})
        with mock.patch.object(cli, "load_graph", side_effect=KeyError("boom")):
            code, _, err = run("flags", str(root))
            self.assertEqual(code, 2)
            self.assertIn("unexpected error (KeyError", err)
            self.assertIn("--debug", err)
            with self.assertRaises(KeyError):
                cli.main(["--debug", "flags", str(root)])

    def test_help_has_examples(self):
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("examples:", out)
        self.assertIn("codefactory review", out)


if __name__ == "__main__":
    unittest.main()
