"""Regressions found by assessing public repositories (Spring PetClinic, HTTPie, Actual Budget, the FastAPI full-stack
template, LoopKit). Each test is the smallest copy of what the real repository did."""

import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.audit import scan_config
from codefactory.brief import View
from codefactory.cli import build
from codefactory.hotspots import generated
from codefactory.profile import detect
from codefactory.security import surface
from codefactory.taint import taint_flags


def repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def graph(root: Path) -> dict:
    return build(root, cache=False).to_dict()


class SurfaceTest(unittest.TestCase):
    @unittest.skipUnless(__import__("codefactory.analyzers.generic", fromlist=["available"]).available(), "needs tree-sitter")
    def test_spring_annotations_on_the_method_line(self):
        # tree-sitter starts a Java method at its annotation, so looking only above it found nothing (PetClinic: 0 of 17)
        root = repo({"src/main/java/org/x/samples/vet/VetController.java": """
            package org.x.samples.vet;
            @Controller
            class VetController {

                @GetMapping("/vets.html")
                public String showVetList(Model model) { return "vets"; }

                @PostMapping("/vets/new")
                public String add(Vet vet) { return "ok"; }
            }
            """, "pom.xml": "<project><artifactId>petclinic</artifactId><artifactId>spring-boot-starter-thymeleaf</artifactId>"
                            "<plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></project>"})  # fmt: skip
        g = graph(root)
        entries = surface(root, g, View(g)).entries
        self.assertEqual(sorted((e.method, e.path) for e in entries), [("GET", "/vets.html"), ("POST", "/vets/new")])
        p = detect(root, g)  # a Java package called `samples` isn't an examples folder; Thymeleaf pages make it a web app
        self.assertEqual(p.kind, "web app")

    def test_mock_patch_in_tests_isnt_a_route(self):
        # HTTPie: `@mock.patch('httpie.cli...')` read as Flask PATCH routes made a CLI look like a web service
        root = repo({
            "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    http = httpie.__main__:main\n",
            "httpie/core.py": "def main():\n    return 0\n",
            "tests/test_auth.py": "from unittest import mock\n\n@mock.patch('httpie.core.main')\ndef test_x(m):\n    pass\n",
        })  # fmt: skip
        g = graph(root)
        self.assertEqual(surface(root, g, View(g)).entries, [])
        self.assertEqual(detect(root, g).kind, "command-line tool")


class ProfileTest(unittest.TestCase):
    def test_monorepo_workspaces_and_a_native_shell(self):
        # Actual Budget: manifests in packages/*, and an iOS folder that only wraps the web app
        root = repo({
            "package.json": json.dumps({"workspaces": ["packages/*"]}),
            "packages/web/package.json": json.dumps({"dependencies": {"react": "19.0.0"}}),
            "packages/web/src/app.tsx": "export const App = () => null;\n",
            "packages/server/package.json": json.dumps({"dependencies": {"express": "5.0.0", "bcrypt": "5.0.0"}}),
            "packages/server/app.js": "const app = require('express')();\napp.post('/sync', (req, res) => res.end());\n",
            "packages/mobile/ios/App/AppDelegate.swift": "import UIKit\nclass AppDelegate: UIResponder {}\n",
            ".github/workflows/docs-deploy.yml": "jobs:\n  d:\n    steps:\n      - run: npx vercel deploy\n",
        })  # fmt: skip
        p = detect(root, graph(root))
        self.assertEqual(p.kind, "web app")
        self.assertIn("mobile app", p.also)
        self.assertIn("accounts and passwords", p.sensitive)  # bcrypt from packages/server/package.json
        self.assertNotEqual(p.deployment, "deployed server")  # deploying the docs isn't deploying the product

    def test_generated_files_arent_hotspots(self):
        for path in ("frontend/src/client/types.gen.ts", "api/user_pb2.py", "x/y.pb.go", "src/generated/api.ts"):
            self.assertTrue(generated(path), path)
        self.assertFalse(generated("src/general.ts"))


class AuditTest(unittest.TestCase):
    def test_ci_injection_only_in_what_runs(self):
        # Actual Budget passed the PR body through an env var (the safe way) and was flagged; the FastAPI template's
        # checkout `ref: ${{ github.head_ref }}` was flagged too. Neither is run by a shell.
        root = repo({".github/workflows/pr.yml": """
            on: pull_request_target
            jobs:
              check:
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.base.sha }}
                  - name: description
                    env:
                      PR_BODY: ${{ github.event.pull_request.body }}
                      HEAD_SHA: ${{ github.event.pull_request.head.sha }}
                    run: |
                      echo "$PR_BODY" | wc -c
                  - run: echo "${{ github.event.pull_request.title }}"
            """})  # fmt: skip
        found = scan_config(root)
        self.assertEqual([e.line for e in found["gha_injection"].hits], [15])  # only the title pasted into run:
        self.assertEqual(found["gha_pr_target"].data[".github/workflows/pr.yml"], "trigger")  # base checkout: safe

    def test_vendored_bundles_arent_leaked_keys(self):
        root = repo({"README.md": "x\n"})
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run([*git, "init", "-q"], check=True)
        (root / ".yarn/releases").mkdir(parents=True)
        (root / ".yarn/releases/yarn-4.cjs").write_text('var a={token:"' + "Ab1" * 10 + '"};\n', encoding="utf-8")
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-qm", "yarn"], check=True)
        (root / ".yarn/releases/yarn-4.cjs").unlink()
        subprocess.run([*git, "commit", "-qam", "drop"], check=True)
        from codefactory.audit import scan

        self.assertEqual(scan(root, set())[0]["history_secret"].hits, [])


class TaintTest(unittest.TestCase):
    def test_uuid_params_and_orm_sessions(self):
        # FastAPI template: `user_id: uuid.UUID` reached `session.delete(user)`, reported as a dangerous flow
        root = repo({"app/routes.py": """
            import uuid
            from fastapi import APIRouter
            router = APIRouter()

            @router.delete("/{user_id}")
            def delete_user(session, user_id: uuid.UUID):
                user = session.get(User, user_id)
                session.delete(user)

            @router.get("/fetch")
            def fetch(url: str):
                import requests
                return requests.get(url, timeout=5).text
            """})  # fmt: skip
        flows = taint_flags(build(root, cache=False), root)
        self.assertEqual([f.target.split("::")[-1] for f in flows], ["fetch"])  # the real one stays


if __name__ == "__main__":
    unittest.main()
