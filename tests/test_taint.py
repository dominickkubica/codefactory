"""Data flow for Python: request values traced into dangerous calls, and the look-alikes that aren't flows."""

import unittest
from pathlib import Path

from codefactory.cli import build

APP = Path(__file__).parent / "fixtures" / "taintapp"


class TaintTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flows = [f for f in build(APP, cache=False).flags if f.kind == "taint"]
        cls.flows = {(f.target.split("::")[-1], f.detail): f for f in flows}

    def test_proven_flows(self):
        self.assertEqual(
            set(self.flows),
            {("find_user", "sql"), ("fetch", "ssrf"), ("download", "path"), ("ping", "shell"), ("report", "sql")},
        )

    def test_the_chain_names_the_route_and_the_helper(self):
        msg = self.flows[("find_user", "sql")].message
        self.assertIn("parameter `name` of GET /users → users → find_user(name) → conn.execute()", msg)
        self.assertIn("request.args.get('q', '')", self.flows[("ping", "shell")].message)  # via a helper returning it

    def test_look_alikes_are_not_flows(self):
        names = {name for name, _ in self.flows}
        # a bound SQL parameter, an int() conversion, a Depends() connection, an int-typed id, a path read from the database
        for safe in ("find_user_safe", "page", "shot", "stored_path"):
            self.assertNotIn(safe, names)
        self.assertEqual(sum(1 for name, _ in self.flows if name == "find_user"), 1)  # GET /page's int() isn't a second

    def test_severity_in_the_review(self):
        from codefactory.review import Review

        r = Review(build(APP, cache=False).to_dict(), APP)
        r.security()
        f = next(f for f in r.findings if f.title.startswith("Request data reaches dangerous calls"))
        self.assertEqual(f.severity, "Critical")  # SQL and shell flows


if __name__ == "__main__":
    unittest.main()
