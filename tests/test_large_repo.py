"""Lessons from reviewing Django (1.15M lines): someone else's bundled code isn't the project's, and a lockfile matters
less when package.json holds only development tools."""

import json
import tempfile
import unittest
from pathlib import Path

from codefactory.checks import scan_sources, source_files
from codefactory.cli import build
from codefactory.review import Review


def repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


class LargeRepoLessonsTest(unittest.TestCase):
    def test_vendored_and_minified_code_gets_no_line_checks(self):
        root = repo({
            "app/static/js/vendor/jquery/jquery.js": "el.innerHTML = html;\n",
            "app/static/js/lib.min.js": "el.innerHTML = html;\n",
            "app/static/js/own.js": "el.innerHTML = html;\n",
        })  # fmt: skip
        files = source_files(root, build(root, cache=False).to_dict())
        self.assertEqual(files, ["app/static/js/own.js"])
        self.assertEqual([e.file for e in scan_sources(root, files)["raw_html"].hits], ["app/static/js/own.js"])

    def test_no_lockfile_is_low_when_package_json_holds_only_dev_tools(self):
        def lockfile_severity(package: dict) -> str:
            root = repo({"package.json": json.dumps(package), "app.py": "x = 1\n"})
            r = Review(build(root, cache=False).to_dict(), root)
            r.delivery()
            return next(f.severity for f in r.findings if f.title == "No lockfile")

        self.assertEqual(lockfile_severity({"devDependencies": {"eslint": "^9"}}), "Low")
        self.assertEqual(lockfile_severity({"dependencies": {"react": "^19"}}), "High")


if __name__ == "__main__":
    unittest.main()
