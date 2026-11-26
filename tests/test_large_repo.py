"""Lessons from reviewing large public repositories (Django, FastAPI, excalidraw, gin): someone else's bundled or
generated code isn't the project's, documentation samples aren't its product, public build variables aren't secrets,
a Go module without a main package is a library, and a lockfile matters less when package.json holds only development
tools."""

import json
import tempfile
import unittest
from pathlib import Path

from codefactory.checks import scan_repo, scan_sources, source_files
from codefactory.cli import build
from codefactory.profile import detect
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

    def test_a_tutorials_sample_key_is_low_and_its_variants_are_not_tasks(self):  # FastAPI's docs_src
        body = 'SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"\n\n\n' + "".join(
            f"def read_items(q):\n    items = [q] * {n}\n    if q:\n        items.append(q)\n    return items\n\n\n" for n in (1,)
        )
        root = repo({"docs_src/security/tutorial004.py": body, "docs_src/security/tutorial004_non_an.py": body,
                     "app.py": "def main():\n    return 1\n"})  # fmt: skip
        g = build(root, cache=False)
        self.assertFalse([f for f in g.flags if f.kind == "duplicate" and f.severity != "info"])
        self.assertFalse([f for f in g.flags if f.kind == "unused" and "docs_src" in f.target])
        r = Review(g.to_dict(), root)
        r.security()
        found = {f.title: f.severity for f in r.findings}
        self.assertEqual(found.get("Credentials committed in source", "Low"), "Low")
        self.assertEqual(found.get("Signing key written in the code", "Low"), "Low")

    def test_public_build_variables_in_an_env_file_are_not_secrets(self):  # excalidraw's .env.production
        public = repo({".env.production": "VITE_APP_API_KEY=abcdef123456\nVITE_APP_EXPORT_PUBLIC_KEY='MIIBIjANBgkq'\n"})
        self.assertEqual(scan_repo(public)["env_files"], [])
        private = repo({".env": "DATABASE_PASSWORD=hunter2hunter2\n"})
        self.assertEqual(scan_repo(private)["env_files"], [".env"])

    def test_generated_code_gets_no_line_checks(self):  # emscripten bindings
        root = repo({"bindings.js": "// emscripten bindings, generated\nconst f = new Function(body);\neval(x);\n",
                     "own.js": "eval(x);\n"})  # fmt: skip
        self.assertEqual([e.file for e in scan_sources(root, ["bindings.js", "own.js"])["eval"].hits], ["own.js"])

    def test_a_go_module_without_a_main_package_is_a_library(self):  # gin
        files = {"go.mod": "module example.com/web\n\ngo 1.22\n",
                 "router.go": 'package web\n\nimport "net/http"\n\nfunc Serve() { http.HandleFunc("/x", nil) }\n'}  # fmt: skip
        root = repo(files)
        self.assertEqual(detect(root, build(root, cache=False).to_dict()).kind, "library")
        files["cmd/server/main.go"] = "package main\n\nfunc main() {}\n"
        root = repo(files)
        self.assertNotEqual(detect(root, build(root, cache=False).to_dict()).kind, "library")

    def test_a_shell_built_in_a_release_script_ranks_lower_than_in_the_product(self):  # excalidraw's scripts/
        def shell_severity(path: str) -> str:
            root = repo({path: "const { execSync } = require('child_process');\n"
                               "function publish(tag) { execSync(`yarn publish --tag ${tag}`); }\n"})  # fmt: skip
            r = Review(build(root, cache=False).to_dict(), root)
            r.security()
            return next(f.severity for f in r.findings if f.title.startswith("Shell commands built"))

        order = ["Low", "Medium", "High", "Critical"]
        self.assertLess(order.index(shell_severity("scripts/release.js")), order.index(shell_severity("src/publish.js")))

    def test_a_security_linters_suppression_is_respected_but_never_for_credentials(self):  # Caddy's test helper
        root = repo({"helper.go": "package helper\n\nimport \"crypto/tls\"\n\n"
                                  "var c = &tls.Config{InsecureSkipVerify: true} //nolint:gosec\n"
                                  "var d = &tls.Config{InsecureSkipVerify: true}\n",
                     "keys.py": 'TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # nosec\n'})  # fmt: skip
        found = scan_sources(root, ["helper.go", "keys.py"])
        self.assertEqual([e.line for e in found["tls_off"].hits], [6])
        self.assertTrue(found["secret"].hits)

    def test_copies_only_between_samples_are_not_merge_tasks(self):  # NestJS's sample/ apps
        boot = (
            "def bootstrap(port, debug):\n    app = make(port)\n    if debug:\n        app.use(log)\n"
            "        app.use(trace)\n    for name in ('a', 'b', 'c'):\n        app.mount(name, load(name))\n"
            "    app.settings['timeout'] = 30\n    app.settings['retries'] = 3\n    app.listen(port)\n    return app\n"
        )
        root = repo({"sample/01-cats/main.py": boot, "sample/02-dogs/main.py": boot,
                     "src/a.py": boot.replace("bootstrap", "start").replace("30", "60").replace("'c'", "'d', 'e'"),
                     "src/b.py": boot.replace("bootstrap", "begin").replace("30", "60").replace("'c'", "'d', 'e'")})  # fmt: skip
        r = Review(build(root, cache=False).to_dict(), root)
        r.architecture()
        copied = next((f for f in r.findings if f.title.startswith("Copied logic")), None)
        self.assertIsNotNone(copied)
        self.assertNotIn("sample/", " ".join(copied.evidence))


if __name__ == "__main__":
    unittest.main()
