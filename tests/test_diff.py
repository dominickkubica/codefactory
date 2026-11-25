"""`codefactory diff`: what a change adds and fixes, compared with a base commit."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from codefactory.cli import main

BASE = """def total(items):
    out = 0
    for i in items:
        if i["price"] > 0:
            out += i["price"] * i.get("qty", 1)
        else:
            out -= 1
    return out


def total_copy(items):
    out = 0
    for i in items:
        if i["price"] > 0:
            out += i["price"] * i.get("qty", 1)
        else:
            out -= 1
    return out


def main():
    return total([]) + total_copy([])
"""
HEAD = """# a comment that moves everything down


def total(items):
    out = 0
    for i in items:
        if i["price"] > 0:
            out += i["price"] * i.get("qty", 1)
        else:
            out -= 1
    return out


def find(conn, name):
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")


def main():
    return total([]) + len(find(None, "x"))
"""


class DiffTest(unittest.TestCase):
    def test_new_and_fixed_findings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
            (root / "app.py").write_text(BASE, encoding="utf-8")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "base"], check=True)
            subprocess.run([*git, "checkout", "-qb", "feature"], check=True)
            (root / "app.py").write_text(HEAD, encoding="utf-8")  # uncommitted work counts too
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = main(["diff", d, "--base", "main", "--json", "--fail-on", "warn"])
            result = json.loads(out.getvalue())
            new = {(i["kind"], i["function"]) for i in result["new"]}
            fixed = {(i["kind"], i["function"]) for i in result["fixed"]}
            self.assertEqual(new, {("sql_built", "")})  # moved code (total, main) isn't new
            self.assertIn(("duplicate", "total"), fixed)
            self.assertEqual(code, 1)  # sql_built is warn
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["diff", d, "--base", "main"]), 0)  # --fail-on never (the default) never fails
            self.assertEqual(result["changed"], ["app.py"])

    def test_config_findings_on_both_sides_are_not_new(self):
        # the base is unpacked inside .codefactory/: checks that skip that folder must still read the base's files
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
            (root / "Dockerfile").write_text("FROM node:latest\nCMD node app.js\n", encoding="utf-8")
            (root / "app.json").write_text(json.dumps({"expo": {"ios": {"infoPlist": {
                "NSCameraUsageDescription": "Scan barcodes"}}}}), encoding="utf-8")  # fmt: skip
            (root / "scan.ts").write_text("export const open = () => launchCameraAsync();\n", encoding="utf-8")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "base"], check=True)
            (root / "scan.ts").write_text("export const open = () => launchCameraAsync({});\n", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(["diff", d, "--base", "main", "--json"])
            result = json.loads(out.getvalue())
            self.assertEqual([i["kind"] for i in result["new"]], [])  # docker findings exist on both sides
            self.assertEqual([i["kind"] for i in result["fixed"]], [])  # the camera string was declared on both


if __name__ == "__main__":
    unittest.main()
