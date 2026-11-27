"""Data flow for JavaScript and TypeScript: request values traced into dangerous calls (Express, Koa, Next.js, Nest),
and the look-alikes from real repositories that aren't flows."""

import unittest
from pathlib import Path

from codefactory.cli import build
from codefactory.jstaint import available

APP = Path(__file__).parent / "fixtures" / "jstaintapp"


@unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
class JsTaintTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flows = [f for f in build(APP, cache=False).flags if f.kind == "taint"]
        cls.found = {(f.target.split("::")[0], f.line, f.detail) for f in cls.flows}

    def test_proven_flows(self):
        self.assertEqual(
            self.found,
            {
                ("app/api/proxy/route.ts", 4, "ssrf"),
                ("app/api/proxy/route.ts", 5, "redirect"),
                ("app/api/proxy/route.ts", 9, "sql"),
                ("server.js", 8, "shell"),  # through a helper
                ("server.js", 13, "shell"),
                ("server.js", 22, "sql"),
                ("server.js", 25, "redirect"),
                ("server.js", 31, "path"),
                ("server.js", 33, "ssrf"),
                ("server.js", 34, "template"),
                ("server.js", 36, "code"),
                ("users.controller.ts", 7, "sql"),  # a Nest @Body() parameter
            },
        )

    def test_the_chain_names_the_route_and_the_helper(self):
        msgs = {(f.target.split("::")[0], f.line): f.message for f in self.flows}
        self.assertIn("req.query.x in GET /ls → runIt() → exec()", msgs[("server.js", 8)])
        self.assertIn("parameter `dto` of POST /users/:id → update", msgs[("users.controller.ts", 7)])
        self.assertIn("in GET /api/proxy", msgs[("app/api/proxy/route.ts", 4)])

    def test_look_alikes_are_not_flows(self):
        # execFile with an argument list, parseInt, a bound SQL parameter, a tagged sql`` template, a local redirect, an
        # allow-listed redirect, a fixed host, a JSON response, RegExp.exec, a Nest parameter through ParseIntPipe…
        # …and every case in lookalikes.ts: a compared host, two handlers' variables, looked-up records, a service's
        # answer, relative and query-only redirects, fixed bases, validators, @Req() as a whole, client `context`
        self.assertFalse({f for f in self.found if f[0] in ("lookalikes.ts", "client/relay.ts")})

    def test_the_review_reports_them_as_proven_flows(self):
        from codefactory.review import Review

        g = build(APP, cache=False)
        r = Review(g.to_dict(), APP)
        r.run()
        titles = [f.title for f in r.findings]
        self.assertTrue(any(t.startswith("Request data reaches dangerous calls (12 proven flows)") for t in titles), titles)


if __name__ == "__main__":
    unittest.main()
