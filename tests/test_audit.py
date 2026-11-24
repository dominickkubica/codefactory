# codefactory: ignore-file secret, secret_key_literal, weak_random, jwt_unverified, cors_any — samples of the patterns
"""Security checks on configuration, crypto, CI, containers, mobile settings, git history and dependencies."""

import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from codefactory import deps
from codefactory.audit import scan
from codefactory.checks import scan_sources


def tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root


class SourceChecksTest(unittest.TestCase):
    def test_config_and_crypto_with_their_look_alikes(self):
        root = tree({"app.py": '''
            import hashlib, random
            DEBUG = True
            SECRET_KEY = "dev-only-but-committed-9f8e7d"
            app.add_middleware(CORSMiddleware, allow_origins=["*"])
            response.set_cookie("session", sid, secure=False)
            payload = jwt.decode(token, options={"verify_signature": False})
            reset_token = str(random.randint(100000, 999999))
            password_hash = hashlib.md5(password.encode()).hexdigest()
            cache_key = hashlib.md5(url.encode()).hexdigest()
            colour = random.choice(COLOURS)
            draft_token = random.random()
            '''})  # fmt: skip
        found = {k: [e.line for e in c.hits] for k, c in scan_sources(root, ["app.py"]).items() if c.hits}
        for key, line in [("debug_on", 3), ("secret_key_literal", 4), ("cors_any", 5), ("insecure_cookie", 6),
                          ("jwt_unverified", 7), ("weak_random", 8), ("weak_hash", 9)]:  # fmt: skip
            self.assertEqual(found.get(key), [line], key)

    def test_tokens_in_unencrypted_storage(self):
        root = tree({"a.ts": 'await AsyncStorage.setItem("authToken", t);\nawait AsyncStorage.setItem("theme", "dark");\n'})
        self.assertEqual([e.line for e in scan_sources(root, ["a.ts"])["sensitive_storage"].hits], [1])


class RepositoryChecksTest(unittest.TestCase):
    def test_workflows_dockerfiles_and_mobile_config(self):
        root = tree({
            ".github/workflows/pr.yml": """
                on:
                  pull_request_target:
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@v4
                        with:
                          ref: ${{ github.event.pull_request.head.sha }}
                      - uses: someone/deploy-action@v2
                      - uses: other/tool@0123456789abcdef0123456789abcdef01234567
                      - run: echo "${{ github.event.issue.title }}"
                """,
            "Dockerfile": "FROM python\nENV API_KEY=abc123secretvalue\nRUN pip install .\n",
            "worker/Dockerfile": "FROM node:22-slim\nUSER node\n",
            "app.json": '{"expo": {"ios": {"infoPlist": {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": true}}}}}',
        })  # fmt: skip
        out, _ = scan(root, set())
        got = {k: [(e.file, e.line) for e in c.hits] for k, c in out.items() if c.hits}
        self.assertEqual(out["gha_pr_target"].data, {".github/workflows/pr.yml": "checkout"})
        self.assertEqual(got["gha_injection"], [(".github/workflows/pr.yml", 12)])
        self.assertEqual([e.text for e in out["gha_unpinned"].hits], ["someone/deploy-action@v2"])  # SHA-pinned is fine
        self.assertEqual(got["docker_root"], [("Dockerfile", 1)])  # worker/Dockerfile has a USER
        self.assertEqual(got["docker_latest"], [("Dockerfile", 1)])
        self.assertEqual(got["docker_secret"], [("Dockerfile", 2)])
        self.assertEqual(got["mobile_cleartext"], [("app.json", 1)])

    def test_a_deleted_secret_is_still_in_history(self):
        root = tree({"config.py": 'STRIPE = "sk_live_' + "4eC39HqLyjWDarjtT1zdp7dc" + '"\n'})
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "add config"], check=True)
        (root / "config.py").write_text('import os\nSTRIPE = os.environ["STRIPE"]\n', encoding="utf-8")
        subprocess.run([*git, "commit", "-qam", "use the environment"], check=True)
        out, note = scan(root, set())
        self.assertEqual([e.file for e in out["history_secret"].hits], ["config.py"])
        self.assertIn("sk_live_", out["history_secret"].hits[0].text)
        self.assertEqual(note, "")


class DependenciesTest(unittest.TestCase):
    def test_lockfiles(self):
        root = tree({
            "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/jest": {"version": "29.0.0", "dev": True}}}),
            "poetry.lock": '[[package]]\nname = "requests"\nversion = "2.19.0"\n',
            "requirements.txt": "flask==2.0.0\nrich>=13\n",
            "Gemfile.lock": "GEM\n  specs:\n    rack (2.0.1)\n",
            "go.sum": "github.com/gin-gonic/gin v1.6.0 h1:abc=\ngithub.com/gin-gonic/gin v1.6.0/go.mod h1:def=\n",
        })  # fmt: skip
        got = {(p.ecosystem, p.name, p.version, p.dev) for p in deps.packages(root)}
        self.assertEqual(got, {("npm", "lodash", "4.17.15", False), ("npm", "jest", "29.0.0", True),
                               ("PyPI", "requests", "2.19.0", False), ("PyPI", "flask", "2.0.0", False),
                               ("RubyGems", "rack", "2.0.1", False), ("Go", "github.com/gin-gonic/gin", "1.6.0", False)})  # fmt: skip

    def test_osv_results(self):
        pkgs = [deps.Package("npm", "lodash", "4.17.15", "package-lock.json")]
        detail = {"summary": "Prototype Pollution in lodash", "database_specific": {"severity": "HIGH"},
                  "affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]}  # fmt: skip
        with mock.patch.object(deps, "_post", return_value={"results": [{"vulns": [{"id": "GHSA-p6mc-m468-83gw"}]}]}), \
             mock.patch.object(deps, "_get", return_value=detail):  # fmt: skip
            (v,) = deps.vulnerabilities(pkgs)
        self.assertEqual((v.id, v.severity, v.fixed, v.summary), ("GHSA-p6mc-m468-83gw", "HIGH", "4.17.19", detail["summary"]))


if __name__ == "__main__":
    unittest.main()
