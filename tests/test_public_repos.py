"""Regressions found by assessing public repositories. Round 1: Spring PetClinic, HTTPie, Actual Budget, the FastAPI
full-stack template, LoopKit. Round 2: Maybe (Rails), Healthchecks (Django), Now in Android, PocketBase, Gotify, Our
World in Data's ETL. Round 3: Taxonomy (Next.js), Monica (Laravel), Vaultwarden (Rust), eShop (ASP.NET), LocalSend
(Flutter), MarkText (Electron), Alamofire (Swift package), Plausible (Phoenix), nanoGPT. Each test is the smallest copy
of what the real repository did."""

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


def _js_parser() -> bool:
    """TypeScript's compiler (Node.js and the typescript package), or tree-sitter: Node.js alone isn't enough."""
    from tests.test_typescript import available as typescript

    return typescript() or __import__("codefactory.analyzers.generic", fromlist=["available"]).available()


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
    @unittest.skipUnless(
        _js_parser(), "the server's routes need a JavaScript parser (Node.js with TypeScript, or the language pack)"
    )
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


class RoundTwoTest(unittest.TestCase):
    def test_django_url_maps_to_one_handler(self):
        # Healthchecks: every function called `index` anywhere became a handler of each URL (932 "endpoints")
        root = repo({
            "hc/front/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('', views.index)]\n",
            "hc/front/views.py": "def index(request):\n    return None\n",
            "hc/api/views.py": "def index(request):\n    return None\n",
            "hc/other/views.py": "def index(request):\n    return None\n",
        })  # fmt: skip
        g = graph(root)
        entries = surface(root, g, View(g)).entries
        self.assertEqual([(e.path, e.file) for e in entries], [("/", "hc/front/views.py")])

    @unittest.skipUnless(__import__("codefactory.analyzers.generic", fromlist=["available"]).available(), "needs tree-sitter")
    def test_rails_auth_from_parent_and_concern(self):
        # Maybe: API controllers inherit `before_action :authenticate_request!`; the rest get `authenticate_user!` from
        # an `Authentication` concern included by ApplicationController; registration skips it on purpose
        root = repo({
            "app/controllers/concerns/authentication.rb": "module Authentication\n  extend ActiveSupport::Concern\n"
                "  included do\n    before_action :authenticate_user!\n  end\nend\n",
            "app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\n"
                "  include Localize, Authentication\nend\n",
            "app/controllers/categories_controller.rb": "class CategoriesController < ApplicationController\n"
                "  def create\n    @category.save\n  end\nend\n",
            "app/controllers/api/v1/base_controller.rb": "class Api::V1::BaseController < ApplicationController\n"
                "  before_action :authenticate_request!\nend\n",
            "app/controllers/api/v1/chats_controller.rb": "class Api::V1::ChatsController < Api::V1::BaseController\n"
                "  def create\n    @chat.save\n  end\nend\n",
            "app/controllers/registrations_controller.rb": "class RegistrationsController < ApplicationController\n"
                "  skip_authentication only: :create\n  def create\n    @user.save\n  end\nend\n",
        })  # fmt: skip
        g = graph(root)
        auth = {e.path: e.auth for e in surface(root, g, View(g)).entries}
        self.assertEqual(auth["categories#create"], "before_action :authenticate_user! (from ApplicationController)")
        self.assertTrue(auth["chats#create"].startswith("before_action :authenticate_request!"))
        self.assertEqual(auth["registrations#create"], "")
        p = detect(root, g)
        self.assertEqual(p.users, "multi-user")

    def test_android_room_and_pipelines(self):
        # Now in Android: Room via the Gradle version catalog and @Database is on-device storage (local-first)
        root = repo({
            "gradle/libs.versions.toml": '[libraries]\nroom-runtime = { group = "androidx.room", name = "room-runtime" }\n',
            "app/build.gradle.kts": "plugins { alias(libs.plugins.nowinandroid.android.application) }\n",
            "core/db/NiaDatabase.kt": "@Database(entities = [Topic::class], version = 1)\nabstract class NiaDatabase\n",
        })  # fmt: skip
        p = detect(root, graph(root))
        self.assertEqual((p.kind, p.deployment), ("mobile app", "local-first"))
        # OWID's ETL: three FastAPI endpoints in an internal app don't make a pipeline repository a web service
        root = repo({
            "pyproject.toml": '[project]\nname = "etl"\ndependencies = ["pandas", "fastapi"]\n',
            "apps/wizard/api.py": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/health')\ndef health():\n"
                                  "    return 1\n",
            "etl/steps.py": "import pandas as pd\n\ndef run():\n    return pd.DataFrame()\n",
        })  # fmt: skip
        p = detect(root, graph(root))
        self.assertEqual((p.kind, p.deployment, p.users), ("data pipeline", "user's machine", "single user"))
        self.assertIn("web service", p.also)

    def test_contact_fields_in_a_rails_schema(self):
        root = repo({"Gemfile": "gem 'rails'\n", "db/schema.rb": 'create_table "users" do |t|\n  t.string "email"\nend\n'})
        self.assertIn("contact details", detect(root, graph(root)).sensitive)

    def test_same_package_files_are_linked(self):
        from codefactory.hotspots import _same_package

        self.assertTrue(_same_package("config/config.go", "config/keys.go"))  # Gotify: one Go package, no imports needed
        self.assertFalse(_same_package("config/config.go", "ui/src/config.ts"))

    def test_redirects_this_app_builds(self):
        # Healthchecks: a redirect to reverse(...) + "?query", and one checked by _allow_redirect(), aren't open redirects
        root = repo({"hc/views.py": """
            from django.shortcuts import redirect
            from django.urls import reverse
            from django.views.decorators.http import require_POST
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/a")
            def after_login(request):
                nxt = request.GET.get("next")
                if nxt and _allow_redirect(nxt):
                    return redirect(nxt)
                url = reverse("hc-checks")
                url += "?" + request.headers.get("Referer", "")
                return redirect(url)

            @app.get("/b")
            def go(request):
                return redirect(request.GET.get("to"))
            """})  # fmt: skip
        flows = taint_flags(build(root, cache=False), root)
        self.assertEqual([f.target.split("::")[-1] for f in flows], ["go"])

    def test_placeholders_comments_and_cleared_html(self):
        from codefactory.checks import _scan

        root = repo({
            "forms/apple.go": "// Usually wrapped within -----BEGIN PRIVATE KEY----- X -----END PRIVATE KEY-----.\n",
            "tests/test_digest.py": 'TOKEN = "xoxb-not-a-real-token-1234567"\n',
            "web/ui.js": 'el.innerHTML = "";\n// set innerHTML = html at the end\nbox.innerHTML = html;\n',
            "hc/extras.py": "def e():\n    return mark_safe(''.join(f'&#{ord(c)};' for c in settings.SUPPORT_EMAIL))\n",
        })  # fmt: skip
        found = _scan(root, ["forms/apple.go", "tests/test_digest.py", "web/ui.js", "hc/extras.py"])
        self.assertEqual(found["secret"].hits, [])
        self.assertEqual([(e.file, e.line) for e in found["raw_html"].hits], [("web/ui.js", 3)])

    def test_passwords_alone_dont_make_storage_findings_high(self):
        from codefactory.profile import Profile
        from codefactory.rerank import rerank
        from codefactory.review import Finding

        p = Profile(kind="web service", sensitive={"accounts and passwords": ["bcrypt"]})
        f = Finding("Personal data in unencrypted storage", "Medium", "Security", [], "", "", "S")
        self.assertEqual((rerank([f], p), f.severity), ([], "Medium"))  # PocketBase: a remembered test email


TS = unittest.skipUnless(__import__("codefactory.analyzers.generic", fromlist=["available"]).available(), "needs tree-sitter")


class RoundThreeTest(unittest.TestCase):
    @TS
    def test_routes_and_auth_in_five_more_frameworks(self):
        root = repo({
            "routes/web.php": "<?php\nRoute::get('/about', [Page::class, 'about']);\n"
                "Route::middleware(['auth', 'verified'])->group(function () {\n"
                "    Route::post('/contacts', [ContactController::class, 'store']);\n});\n",
            "src/api/core.rs": "use rocket::request::FromRequest;\npub struct Headers;\n"
                "impl<'r> FromRequest<'r> for Headers {\n    fn from_request() { decode_login(token) }\n}\n\n"
                "#[post(\"/ciphers\", data = \"<data>\")]\nasync fn post_ciphers(data: Json<C>, headers: Headers) {}\n\n"
                "#[get(\"/alive\")]\nfn alive() -> &'static str { \"ok\" }\n",
            "Api/Orders.cs": "public static class Orders {\n  public static void Map(WebApplication app) {\n"
                "    var api = app.MapGroup(\"/api/orders\").RequireAuthorization();\n"
                "    api.MapPost(\"/\", Create);\n    app.MapGet(\"/health\", () => \"ok\");\n  }\n}\n",
            "lib/web/router.ex": "defmodule Web.Router do\n  scope \"/\", Web do\n    pipe_through [:browser]\n"
                "    get \"/sites\", SiteController, :index\n    get \"/\", PageController, :home\n  end\nend\n",
            "lib/web/site_controller.ex": "defmodule Web.SiteController do\n  plug Web.RequireAccountPlug\nend\n",
        })  # fmt: skip
        g = graph(root)
        got = {(e.framework, e.path): bool(e.auth) for e in surface(root, g, View(g)).entries}
        self.assertEqual(got, {
            ("Laravel", "/about"): False, ("Laravel", "/contacts"): True,
            ("Rust", "/ciphers"): True, ("Rust", "/alive"): False,
            ("ASP.NET", "/"): True, ("ASP.NET", "/health"): False,
            ("Phoenix", "/sites"): True, ("Phoenix", "/"): False,
        })  # fmt: skip

    def test_next_handler_checks_and_webhook_signatures(self):
        root = repo({
            "package.json": json.dumps({"dependencies": {"next": "14.0.0"}}),
            "app/api/posts/[postId]/route.ts": "export async function DELETE(req: Request) {\n"
                "  if (!(await verifyCurrentUserHasAccessToPost('x'))) return new Response(null, { status: 403 })\n"
                "  await db.post.delete({ where: { id: 'x' } })\n}\n",
            "app/api/webhooks/stripe/route.ts": "export async function POST(req: Request) {\n"
                "  const event = stripe.webhooks.constructEvent(body, signature, secret)\n  await db.user.update({})\n}\n",
        })  # fmt: skip
        g = graph(root)
        self.assertTrue(all(e.auth for e in surface(root, g, View(g)).entries))

    def test_profiles_of_packages_examples_and_scripts(self):
        # Alamofire: a Swift package whose Example/ app isn't the product; Vaultwarden: a Playwright harness's
        # package.json isn't the product either; nanoGPT: no manifest, scripts importing torch
        root = repo({
            "Package.swift": 'let package = Package(name: "Alamofire", products: [.library(name: "Alamofire")])\n',
            "Source/Request.swift": "import Foundation\npublic class Request {}\n",
            "Example/Source/AppDelegate.swift": "import UIKit\nclass AppDelegate: UIResponder {}\n",
        })  # fmt: skip
        p = detect(root, graph(root))
        self.assertEqual(p.kind, "library")
        root = repo({"train.py": "import torch\n\nif __name__ == '__main__':\n    torch.manual_seed(0)\n"})
        self.assertEqual(detect(root, graph(root)).kind, "data pipeline")
        root = repo({
            "app/pubspec.yaml": "dependencies:\n  flutter:\n    sdk: flutter\n", "pubspec.yaml": "flutter:\n",
            "app/lib/gen/strings_ar.g.dart": "String get symptom => 'x';\n",
            "app/lib/fingerprint.dart": "final a = Icons.medication;\nfinal b = Icons.medication;\n",
            "app/lib/troubleshoot.dart": "final symptomText = t.symptom;\n",
        })  # fmt: skip
        self.assertNotIn("health and fitness", detect(root, graph(root)).sensitive)  # LocalSend
        root = repo({"composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}),
                     "database/migrations/2024_create_contacts.php": "<?php\n$table->string('first_name');\n"})  # fmt: skip
        self.assertIn("contact details", detect(root, graph(root)).sensitive)  # Monica

    @TS
    def test_collections_arent_databases_but_repositories_are(self):
        root = repo({
            "src/cache.rs": "fn cached(k: String) {\n    CLIENT_CACHE.insert(k, 1);\n    for x in xs { MAP.insert(x, 1); }\n}\n",
            "src/Owner.java": "class OwnerController {\n  private final OwnerRepository owners;\n"
                "  void saveAll(java.util.List<Owner> list) {\n    for (Owner o : list) { owners.save(o); }\n  }\n}\n",
        })  # fmt: skip
        g = graph(root)
        io = {f["qualname"]: f.get("io", []) for f in g["functions"]}
        self.assertEqual(io.get("cached"), [])  # Vaultwarden: a HashMap insert isn't a write to the database
        self.assertTrue(io.get("OwnerController.saveAll"))  # PetClinic: a Spring Data repository is

    def test_format_checks_ignored_catches_and_env_templates(self):
        from codefactory.checks import _holds_secret, _scan
        from codefactory.intent import swallow_intent

        root = repo({"cert.rs": 'assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));\n',
                     "real.py": 'KEY = """-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"""\n',
                     ".env.docker": "APP_KEY=\nAPP_DEBUG=false\nDB_PASSWORD=changethis\n",
                     ".env": "API_TOKEN=9f8e7d6c5b4a39281706\n"})  # fmt: skip
        found = _scan(root, ["cert.rs", "real.py"])
        self.assertEqual([e.file for e in found["secret"].hits], ["real.py"])  # LocalSend's check isn't a key
        self.assertFalse(_holds_secret(root / ".env.docker"))  # Monica: a template
        self.assertTrue(_holds_secret(root / ".env"))
        self.assertEqual(swallow_intent("} catch (_: Exception) {}", ""), "explained")  # Kotlin: ignored by name


if __name__ == "__main__":
    unittest.main()
