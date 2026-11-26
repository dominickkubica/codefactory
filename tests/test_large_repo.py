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

    def test_an_example_in_a_docstring_is_documentation_not_configuration(self):  # Flask's Config docstring
        root = repo({"config.py": 'class Config:\n    """Load it from a module::\n\n        SECRET_KEY = \'development key\'\n'
                                  '        app.config.from_object(__name__)\n    """\n\n\nSECRET_KEY = "a-real-hardcoded-key-1234"\n'})  # fmt: skip
        hits = scan_sources(root, ["config.py"])["secret_key_literal"].hits
        self.assertEqual([e.line for e in hits], [9])

    def test_tls_checks_chosen_by_a_setting_are_an_option_not_an_override(self):  # httpie's --verify
        root = repo({"ssl_.py": "import ssl\n\ndef context(verify):\n"
                                "    return dict(cert_reqs=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)\n\n"
                                "def always():\n    return dict(cert_reqs=ssl.CERT_NONE)\n"})  # fmt: skip
        self.assertEqual([e.line for e in scan_sources(root, ["ssl_.py"])["tls_off"].hits], [7])

    def test_a_required_reason_api_is_code_not_a_comment_or_a_property(self):  # Loop's Swift headers and models
        from codefactory.privacy import scan as privacy_scan

        files = {"App/Store.swift": "//  NSUserDefaults+Status.swift\nimport Foundation\n"
                                    "struct Context { var creationDate: Date\n  init(d: Date) { self.creationDate = d } }\n",
                 "App.xcodeproj/project.pbxproj": ""}  # fmt: skip
        root = repo(files)
        self.assertFalse(privacy_scan(root, ["App/Store.swift"])["ios_privacy_manifest"].hits)
        files["App/Prefs.swift"] = 'import Foundation\nlet seen = UserDefaults.standard.bool(forKey: "seen")\n'
        root = repo(files)
        hits = privacy_scan(root, ["App/Store.swift", "App/Prefs.swift"])["ios_privacy_manifest"].hits
        self.assertEqual([(e.file, e.line) for e in hits], [("App/Prefs.swift", 2)])

    def test_a_dependency_injection_provider_isnt_untested_logic(self):  # Now in Android's DaosModule
        root = repo({"di/DaosModule.kt": "@Module\ninternal object DaosModule {\n    @Provides\n"
                                         "    fun providesTopicsDao(db: Db): TopicDao = db.topicDao()\n\n"
                                         "    fun countTopics(db: Db): Int = db.topicDao().count()\n}\n"})  # fmt: skip
        r = Review(build(root, cache=False).to_dict(), root)
        self.assertTrue(r._di_provider({"file": "di/DaosModule.kt", "line": 4}))
        self.assertTrue(r._di_provider({"file": "di/DaosModule.kt", "line": 3}))  # (an analyzer starting at the annotation)
        self.assertFalse(r._di_provider({"file": "di/DaosModule.kt", "line": 6}))

    def test_tls_checks_off_in_a_branch_of_a_verify_setting_are_an_option(self):  # requests' adapters.py
        root = repo({"adapters.py": "def cert_verify(conn, verify):\n    if verify:\n        conn.cert_reqs = 'CERT_REQUIRED'\n"
                                    "    else:\n        conn.cert_reqs = 'CERT_NONE'\n    reqs = 'CERT_REQUIRED'\n"
                                    "    if verify is False:\n        reqs = 'CERT_NONE'\n\n\n"
                                    "def always(conn):\n    conn.cert_reqs = 'CERT_NONE'\n"})  # fmt: skip
        self.assertEqual([e.line for e in scan_sources(root, ["adapters.py"])["tls_off"].hits], [12])

    def test_a_mac_targets_code_needs_no_ios_privacy_manifest(self):  # localsend's macos/ Runner
        from codefactory.privacy import scan as privacy_scan

        root = repo({"app/macos/Runner/AppDelegate.swift": "import Cocoa\nlet m = UserDefaults.standard.bool(forKey: \"m\")\n",
                     "app/ios/Runner/AppDelegate.swift": "import UIKit\nclass AppDelegate {}\n"})  # fmt: skip
        files = ["app/macos/Runner/AppDelegate.swift", "app/ios/Runner/AppDelegate.swift"]
        self.assertFalse(privacy_scan(root, files)["ios_privacy_manifest"].hits)

    def test_corpus_round_5_lessons(self):  # celery, scrapy, poetry, sentry-python, pydantic
        from codefactory.audit import scan_config
        from codefactory.infra import scan as infra_scan

        root = repo({
            # celery: t/ holds the tests; its fixture keys and an import or a warning about CERT_NONE aren't findings
            "t/unit/security/keys.py": 'KEY1 = """-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"""\n',
            "backends/redis.py": 'from ssl import CERT_NONE\n\nW = """\nSetting ssl_cert_reqs=CERT_NONE is insecure.\n"""\n',
            # scrapy: a ruff/bandit security code in noqa is the authors' decision
            "cache.py": "import pickle\n\ndef load(f):\n    return pickle.load(f)  # noqa: S301\n",
            # sentry-python: tiktoken isn't a token
            "tox.ini": "[testenv]\ndeps =\n    py3.9-langchain-notiktoken-v0.1.20: aiohttp1234\n",
            # pydantic: a CI run's throwaway service password
            ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    env:\n"
                                        "      MINIO_ROOT_PASSWORD: polarpolar12\n    steps:\n      - run: make test\n",
            # poetry: zizmor's own suppression on a pull_request_target trigger
            ".github/workflows/docs.yml": "on:\n  pull_request_target:  # zizmor: ignore[dangerous-triggers]\n"
                                          "jobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n"
                                          "      - uses: actions/checkout@v4\n        with:\n"
                                          "          ref: ${{ github.event.pull_request.head.sha }}\n",
        })  # fmt: skip
        files = ["t/unit/security/keys.py", "backends/redis.py", "cache.py"]
        found = scan_sources(root, files)
        self.assertFalse(found["tls_off"].hits)
        self.assertFalse(found["eval"].hits)
        infra = infra_scan(root, set())
        self.assertFalse(infra["config_secret"].hits)
        self.assertEqual([e.file for e in infra["ci_test_secret"].hits], [".github/workflows/ci.yml"])
        self.assertFalse(scan_config(root)["gha_pr_target"].hits)
        r = Review(build(root, cache=False).to_dict(), root)
        r.security()
        self.assertEqual({f.title: f.severity for f in r.findings}.get("Credentials committed in source", "Low"), "Low")

    def test_corpus_round_5_more(self):  # express, vite, svelte, wagtail, saleor
        files = {
            # wagtail: a project template's placeholder
            "project_template/settings.py": 'SECRET_KEY = "{{ secret_key }}"\n',
            # saleor: a yes/no peek at a token in a file that verifies them; returning unverified claims stays
            "jwt_utils.py": "import jwt\n\ndef is_ours(token):\n    try:\n"
            "        payload = jwt.decode(token, options={'verify_signature': False})\n"
            "    except jwt.PyJWTError:\n        return False\n    return payload.get('iss') == 'us'\n\n"
            "def claims(token):\n    return jwt.decode(token, options={'verify_signature': False})\n\n"
            "def verify(token, key):\n    return jwt.decode(token, key, algorithms=['HS256'])\n",
        }
        root = repo(files)
        found = scan_sources(root, list(files))
        self.assertFalse(found["secret_key_literal"].hits)
        self.assertEqual([e.line for e in found["jwt_unverified"].hits], [11])

        # express: a published npm package is a library, and a library ships no lockfile by convention
        express = repo({"package.json": json.dumps({"name": "web", "files": ["lib/"]}),
                        "lib/app.js": "const http = require('http');\nmodule.exports = function app() {};\n"})  # fmt: skip
        self.assertEqual(detect(express, build(express, cache=False).to_dict()).kind, "library")

        # vite: a playground's circular imports test circularity on purpose
        loop = repo({"playground/circular/a.py": "from playground.circular import b\n",
                     "playground/circular/b.py": "from playground.circular import a\n",
                     "playground/__init__.py": "", "playground/circular/__init__.py": ""})  # fmt: skip
        self.assertFalse([f for f in build(loop, cache=False).flags if f.kind == "cycle"])

    def test_the_typescript_analyzer_running_out_of_memory_falls_back_instead_of_crashing(self):  # n8n
        import subprocess
        from unittest import mock

        from codefactory.analyzers import typescript

        oom = subprocess.CompletedProcess([], 134, "", "FATAL ERROR: Reached heap limit - JavaScript heap out of memory")
        with (
            mock.patch.object(typescript.shutil, "which", return_value="node"),
            mock.patch.object(typescript, "find_typescript", return_value="ts"),
            mock.patch.object(typescript.subprocess, "run", return_value=oom),
            self.assertRaisesRegex(typescript.TypeScriptUnavailable, "ran out of memory"),
        ):
            typescript._run_helper(Path("."), [])
        self.assertGreaterEqual(typescript.heap_mb(), 4096)

    def test_corpus_round_5_profiles(self):  # ripgrep, bat, axum, laravel/framework, devise, okhttp, traefik
        def kind(files: dict[str, str]) -> str:
            root = repo(files)
            return detect(root, build(root, cache=False).to_dict()).kind

        cargo = '[package]\nname = "x"\n'
        self.assertEqual(kind({"Cargo.toml": cargo + '[[bin]]\nname = "rg"\npath = "crates/core/main.rs"\n',
                               "crates/core/main.rs": "fn main() {}\n"}), "command-line tool")  # fmt: skip
        self.assertEqual(kind({"Cargo.toml": cargo, "src/bin/bat/main.rs": "fn main() {}\n"}), "command-line tool")
        self.assertEqual(kind({"Cargo.toml": cargo, "src/lib.rs": "pub fn f() {}\n"}), "library")
        self.assertEqual(kind({"composer.json": json.dumps({"name": "laravel/framework"}), "src/A.php": "<?php\n"}), "library")
        self.assertNotEqual(kind({"composer.json": json.dumps({"name": "a/b", "type": "project"})}), "library")
        self.assertEqual(kind({"devise.gemspec": "Gem::Specification.new do |s|\n  s.name = 'devise'\nend\n",
                               "lib/devise.rb": "module Devise; end\n"}), "library")  # fmt: skip
        libs = {f"m{i}/build.gradle.kts": 'plugins { id("java-library") }\n' for i in range(3)}
        self.assertEqual(kind({**libs, "build.gradle.kts": 'plugins { id("com.android.application") apply false }\n',
                               "android-test/src/main/AndroidManifest.xml": "<manifest><application/></manifest>\n"}),
                         "library")  # fmt: skip
        self.assertEqual(kind({"go.mod": "module x\n\ngo 1.22\n", "cmd/x/main.go": "package main\n\nfunc main() {}\n",
                               "webui/package.json": json.dumps({"dependencies": {"react": "19.0.0"}})}),
                         "command-line tool")  # fmt: skip

    def test_corpus_round_5_credentials(self):  # appwrite, superset, outline, tldraw, phoenix, directus, gitea, immich
        from codefactory.infra import scan as infra_scan

        files = {
            "src/Exception.php": "<?php\nconst USER_OAUTH2_BAD_REQUEST = 'user_oauth2_bad_request_x';\n",
            "src/embedded.ts": "export const GUEST_TOKEN = 'api/v1/security/guest_token/x';\n",
            "src/passkeys.ts": 'export enum P { GooglePasswordManager = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" }\n',
            "src/constants.ts": "export const POSTHOG_TOKEN = 'phc_i8oKgMzgV38sn3GfjswW9mevQ3gFlo7bJXekZFeDN6'\n",
            "lib/endpoint.ex": 'defmodule E do\n  @moduledoc """\n  config :app, E,\n'
            '    secret_key_base: "kjoy3o1zeidquwy1398juxzldjlksahdk3"\n  """\nend\n',
            "packages/e2e-auth-server/test-keys.ts": "export const KEY = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n`;\n",
            "src/real.ts": "export const API_TOKEN = 'a8Fk3Lq9Zx2Wm7Rt5Yp1Nc4Vb6'\n",
        }
        root = repo({**files,
                     "app/lang/translations/zh-CN.yaml": "enter_password_to_enable_tfa: 输入您的密码以启用双重认证1234\n",
                     "Makefile": "TEST_MSSQL_PASSWORD ?= MwantsaSecurePassword1\n",
                     "config/testdata/conf.yml": "secret_key: 11111111111111111111\n"})  # fmt: skip
        hits = [e.file for e in scan_sources(root, list(files))["secret"].hits]
        self.assertEqual(hits, ["src/real.ts"])
        self.assertFalse(infra_scan(root, set())["config_secret"].hits)

    def test_tls_off_in_a_case_of_a_setting_or_with_its_own_verification(self):  # mastodon, traefik
        root = repo({
            "database.js": "switch (env.DB_SSLMODE) {\ncase 'no-verify':\n  config.ssl = { rejectUnauthorized: false };\n"
                           "  break;\n}\nconst always = { rejectUnauthorized: false };\n",
            "connect.go": "package c\n\nfunc t() *Transport {\n\treturn &Transport{\n\t\tInsecureSkipVerify: true,\n"
                          "\t\tRootCAs: roots(),\n\t}\n}\n",
        })  # fmt: skip
        hits = scan_sources(root, ["database.js", "connect.go"])["tls_off"].hits
        self.assertEqual([(e.file, e.line) for e in hits], [("database.js", 6)])

    def test_an_import_loop_through_a_package_entry_file_is_debt_not_a_load_failure(self):  # FastAPI's _compat
        root = repo({"pkg/__init__.py": "from .shared import helper\nfrom .v2 import Model\n",
                     "pkg/shared.py": "def helper():\n    return 1\n",
                     "pkg/v2.py": "from pkg import helper\n\nclass Model:\n    pass\n",
                     "app/a.py": "from app import b\n", "app/b.py": "from app import a\n", "app/__main__.py": ""})  # fmt: skip
        cycles = {f.target: f.severity for f in build(root, cache=False).flags if f.kind == "cycle"}
        self.assertEqual(cycles.get("pkg/v2.py"), "warn")
        self.assertEqual(cycles.get("app/a.py"), "high")

    def test_example_servers_and_cache_writes_arent_unprotected_endpoints(self):  # tldraw, cal.com, directus, outline
        from codefactory.checks import scan_repo

        root = repo({
            "templates/simple-server-example/server.py": "from flask import Flask\napp = Flask(__name__)\n\n"
                "@app.put('/uploads/<id>')\ndef upload(id):\n    open(id, 'w').write('x')\n",
            "api/routes.py": "from flask import Flask\napp = Flask(__name__)\n\n"
                "def track_metric(r):\n    r.set('hits', 1)\n\n@app.get('/items')\ndef items():\n    track_metric(redis)\n"
                "    return []\n",
            ".env.test": "DATABASE_PASSWORD=test-password-1234\n",
            "jar.ts": "const c = { secure: typeof cookie.secure === 'boolean' ? cookie.secure : false };\n",
        })  # fmt: skip
        r = Review(build(root, cache=False).to_dict(), root)
        self.assertEqual(r._writing_entries(), [])
        self.assertEqual(scan_repo(root)["env_files"], [])
        self.assertFalse(scan_sources(root, ["jar.ts"])["insecure_cookie"].hits)

    def test_corpus_round_5_code_patterns(self):  # laravel, outline, actual, trpc
        files = {
            "src/Lock.php": "<?php\nreturn (bool) $this->redis->eval($script, 1, $name);\n",
            "server/Converter.ts": "const data = yaml.load(match[1]);\n",
            "server/load.py": "import yaml\ndata = yaml.load(f)\n",
            "src/flush.ts": "void send('storage-flush').catch(() => undefined);\nawait fs.unlink(p).catch(() => undefined);\n",
            "examples/chat/app.tsx": "try { go() } catch {}\n",
        }
        root = repo(files)
        found = scan_sources(root, list(files))
        self.assertEqual([e.file for e in found["eval"].hits], ["server/load.py"])
        self.assertFalse([e for e in found["swallowed"].hits if e.file in ("src/flush.ts", "examples/chat/app.tsx")])

    def test_local_development_defaults_in_an_env_file_arent_secrets(self):  # appwrite's .env
        root = repo({".env": "_APP_REVIEWS_SECRET=reviews-secret-for-local-development\n"
                             "_APP_VCS_GITHUB_PRIVATE_KEY=disabled\n_APP_OPENSSL_KEY_V1=your-secret-key\n"})  # fmt: skip
        self.assertEqual(scan_repo(root)["env_files"], [])
        (root / ".env").write_text("_APP_JOBS_SECRET=41a51c959d1027bd9f40e86217ddad\n", encoding="utf-8")
        self.assertEqual(scan_repo(root)["env_files"], [".env"])


if __name__ == "__main__":
    unittest.main()
