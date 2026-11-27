# codefactory: ignore-file secret — samples of the patterns
"""Organisation scale: owners from CODEOWNERS, custom rules, shared policy, the accept audit trail and the dashboard."""

import contextlib
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.checks import scan_sources
from codefactory.cli import build, main
from codefactory.config import load_config
from codefactory.owners import load


def tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root


class OwnersTest(unittest.TestCase):
    def test_codeowners_patterns_last_match_wins(self):
        root = tree({".github/CODEOWNERS": """
            * @org/everyone
            /src/ @org/app
            *.sql @org/data
            docs/**/guide.md @org/writers
            /src/payments/ @org/payments @alice
            """})  # fmt: skip
        o = load(root)
        self.assertEqual(o.of("README.md"), ["@org/everyone"])
        self.assertEqual(o.of("src/app.py"), ["@org/app"])
        self.assertEqual(o.of("src/payments/charge.py"), ["@org/payments", "@alice"])
        self.assertEqual(o.of("db/schema.sql"), ["@org/data"])  # no slash: matches at any depth
        self.assertEqual(o.of("docs/a/b/guide.md"), ["@org/writers"])
        self.assertEqual(o.source, ".github/CODEOWNERS")

    def test_owners_reach_findings(self):
        root = tree({"CODEOWNERS": "/app/ @team-app\n", "app/x.py": "def unused_helper():\n    return 1\n"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["flags", str(root), "--json", "--no-cache"])
        self.assertEqual(json.loads(out.getvalue())[0]["owners"], ["@team-app"])


class PolicyTest(unittest.TestCase):
    def test_custom_rules_and_shared_policy(self):
        root = tree({
            "policy/org.toml": """
                [thresholds]
                long_function = 40

                [[rule]]
                id = "no-print"
                pattern = "\\\\bprint\\\\("
                files = ["**/*.py"]
                severity = "info"
                message = "Use the logger"
                """,
            "factory.toml": 'extends = "policy/org.toml"\n\n[thresholds]\nlarge_file = 300\n',
            "app.py": "def main():\n    print('hi')\n    return 1\n",
        })  # fmt: skip
        cfg = load_config(root)
        self.assertEqual((cfg.long_function, cfg.large_file), (40, 300))  # tables merge: both kept
        flags = [f for f in build(root, cache=False).flags if f.kind == "custom"]
        self.assertEqual([(f.target, f.line, f.detail) for f in flags], [("app.py::main", 2, "no-print")])
        self.assertIn("Use the logger", flags[0].message)

    def test_bad_rules_are_explained(self):
        root = tree({"factory.toml": '[[rule]]\nid = "x"\npattern = "("\n'})
        with self.assertRaises(ValueError):
            load_config(root)


class LanguageAwareChecksTest(unittest.TestCase):
    def test_eval_only_where_it_is_a_builtin_and_test_fixtures(self):
        root = tree({
            "build.go": "package b\n\nfunc check() bool { return eval(x, tags) }\n",
            "run.py": "result = eval(user_input)\n",
            "tls_test.go": "var key = `-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----`\n",
            "api_test.py": 'TOKEN = "' + "ghp_" + "ADodOJhzzRL5q2IlhAVE05vSWgcaift4t10D" + '"\n',
        })  # fmt: skip
        s = scan_sources(root, ["build.go", "run.py", "tls_test.go", "api_test.py"])
        self.assertEqual([e.file for e in s["eval"].hits], ["run.py"])
        self.assertEqual([e.file for e in s["secret"].hits], ["api_test.py"])  # a real token format, even in a test
        (root / "api_test.py").write_text('TOKEN = "' + "ghp_" + "a" * 36 + '"\n', encoding="utf-8")  # a stand-in
        self.assertFalse(scan_sources(root, ["api_test.py"])["secret"].hits)


class DashboardTest(unittest.TestCase):
    def test_org_dashboard_and_history(self):
        a = tree({"app.py": "def unused():\n    return 1\n"})
        b = tree({"lib.py": "def f():\n    return 2\n", "CODEOWNERS": "* @team-b\n"})
        out = Path(tempfile.mkdtemp()) / "dash.html"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["org", str(a), str(b), "-o", str(out), "--no-cache"]), 0)
            main(["org", str(a), "-o", str(out), "--no-cache"])  # same day: replaces, doesn't add
        page = out.read_text(encoding="utf-8")
        self.assertIn(a.name, page)
        self.assertIn("<title>codefactory dashboard</title>", page)
        history = (a / ".codefactory" / "history.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()
