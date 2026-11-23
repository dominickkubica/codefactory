"""SARIF 2.1.0 output and GitHub annotations."""
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from codefactory.cli import build, main
from codefactory.sarif import build_sarif, github_annotations
from tests.test_rules import project

SHOP = Path(__file__).parent / "fixtures" / "shop"


def run(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class SarifTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = build(SHOP).to_dict()
        cls.doc = build_sarif(cls.graph, SHOP)
        cls.run_ = cls.doc["runs"][0]
        cls.results = cls.run_["results"]

    def test_shape(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        driver = self.run_["tool"]["driver"]
        self.assertEqual(driver["name"], "codefactory")
        rule_ids = {r["id"] for r in driver["rules"]}
        self.assertTrue({r["ruleId"] for r in self.results} <= rule_ids)  # every result's rule is described
        for r in driver["rules"]:
            self.assertIn(r["defaultConfiguration"]["level"], ("error", "warning", "note"))
            self.assertTrue(r["help"]["text"] and r["shortDescription"]["text"])
        for res in self.results:
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%")
            self.assertGreaterEqual(loc["region"]["startLine"], 1)
            self.assertNotIn("\\\\", loc["artifactLocation"]["uri"])

    def test_levels_and_links(self):
        cycle = next(r for r in self.results if r["ruleId"] == "cycle")
        self.assertEqual(cycle["level"], "error")
        loop = next(r for r in self.results if r["ruleId"] == "io_in_loop" and r["level"] == "warning")
        self.assertEqual(loop["locations"][0]["physicalLocation"]["region"]["startLine"], 6)
        dup = next(r for r in self.results if r["ruleId"] == "duplicate")
        self.assertIn("](1)", dup["message"]["text"])  # links to the other copy
        self.assertEqual(dup["relatedLocations"][0]["id"], 1)

    def test_fingerprints_unique_and_stable_across_line_moves(self):
        fps = [r["partialFingerprints"]["codefactory/v1"] for r in self.results]
        self.assertEqual(len(fps), len(set(fps)))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "shop"
            shutil.copytree(SHOP, root, ignore=shutil.ignore_patterns(".codefactory"))
            p = root / "shop" / "core" / "pricing.py"
            p.write_text("# a comment that moves every line down\n\n" + p.read_text(), encoding="utf-8")
            moved = build_sarif(build(root).to_dict(), root)["runs"][0]["results"]
        def fp_of(results, rule, uri):
            return {r["partialFingerprints"]["codefactory/v1"] for r in results if r["ruleId"] == rule
                    and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == uri}
        self.assertEqual(fp_of(self.results, "duplicate", "shop/core/pricing.py"), fp_of(moved, "duplicate", "shop/core/pricing.py"))

    def test_source_checks_suppressions_and_baseline(self):
        root = project({
            "app/db.py": """
                import subprocess

                def backup(path):
                    subprocess.run(f"cp {path} /tmp", shell=True)

                def old():  # codefactory: ignore unused — called by the CLI by name
                    return 1
            """,
        })
        doc = build_sarif(build(root).to_dict(), root)
        res = doc["runs"][0]["results"]
        shell = next(r for r in res if r["ruleId"] == "shell")
        self.assertEqual(shell["level"], "error")
        rule = next(r for r in doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "shell")
        self.assertEqual(rule["properties"]["security-severity"], "8.1")
        quiet = next(r for r in res if "suppressions" in r)
        self.assertEqual(quiet["ruleId"], "unused")
        self.assertEqual(quiet["suppressions"][0]["justification"], "called by the CLI by name")
        # with a baseline, results say new or unchanged
        self.assertEqual(run("baseline", str(root))[0], 0)
        (root / "app" / "more.py").write_text("def unused_too():\n    return 2\n", encoding="utf-8")
        code, out = run("sarif", str(root), "-o", str(root / "out.sarif"))
        states = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r.get("baselineState")
                  for r in json.loads((root / "out.sarif").read_text())["runs"][0]["results"] if r["ruleId"] == "unused"}
        self.assertEqual(states["app/more.py"], "new")

    def test_github_annotations(self):
        text = github_annotations(self.graph, self.graph["flags"])
        self.assertIn("::error file=shop/core/pricing.py,line=1,title=codefactory cycle::", text)
        self.assertIn("::warning file=shop/api/reports.py,line=6,", text)
        code, out = run("flags", str(SHOP), "--github", "--min", "warn")
        self.assertTrue(all(line.startswith("::") for line in out.strip().splitlines()))


if __name__ == "__main__":
    unittest.main()
