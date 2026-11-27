"""Lessons from measuring precision on the corpus (docs/ACCURACY.md, "Precision on real code"): 729 reported
locations from 76 public repositories, each labeled by reading the code. Every false-positive pattern found there is
pinned here, next to a true case that must stay reported."""

import unittest

from codefactory.analyzers.generic import available
from codefactory.apple import scan as apple_scan
from codefactory.audit import scan_config
from codefactory.checks import internet_http, looks_random, scan_sources
from codefactory.cli import build
from codefactory.infra import scan as infra_scan
from codefactory.paths import deliberate_copies, is_dev_setup
from codefactory.privacy import scan as privacy_scan
from codefactory.review import Review
from tests.test_large_repo import repo


def hits(found, key):
    return [(e.file, e.line) for e in found[key].hits]


class ContextTest(unittest.TestCase):
    def test_development_setups_are_not_the_product(self):
        for path in (".devcontainer/Dockerfile", "docker-compose.dev.yml", "compose.override.yml", "frontend/Dockerfile.playwright",
                     "examples/basics/.codesandbox/Dockerfile", "packages/x/benchmark/docker-compose.yml", "integration/docker-compose.yml"):  # fmt: skip
            self.assertTrue(is_dev_setup(path), path)
        for path in ("Dockerfile", "docker-compose.yml", "deploy/docker-compose.prod.yml", "server/Dockerfile"):
            self.assertFalse(is_dev_setup(path), path)

    def test_a_compose_file_that_only_starts_databases_is_a_developers(self):
        dbs = "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n    environment:\n" \
              "      POSTGRES_PASSWORD: Xk9vQ2mZ7pLw4RtY\n"  # fmt: skip
        app = dbs + "  app:\n    build: .\n"
        self.assertFalse(infra_scan(repo({"docker-compose.yml": dbs}), set())["compose_exposed"].hits)
        found = infra_scan(repo({"docker-compose.yml": app}), set())
        self.assertTrue(found["compose_exposed"].hits)
        self.assertTrue(found["compose_secret"].hits)  # a random-looking password in a compose file that runs the app

    def test_a_placeholder_password_is_not_a_secret(self):
        for value in ("magical_password", "petclinic", "testpass", "clickhouse", "secretpassword", "superset", "Forge123"):
            self.assertFalse(looks_random(value), value)
        self.assertTrue(looks_random("Xk9vQ2mZ7pLw4RtY"))
        app = "services:\n  app:\n    build: .\n    environment:\n      POSTGRES_PASSWORD: magical_password\n"
        self.assertFalse(infra_scan(repo({"docker-compose.yml": app}), set())["compose_secret"].hits)

    def test_ci_service_passwords_are_not_reported(self):
        wf = "jobs:\n  t:\n    services:\n      db:\n        env:\n          SA_PASSWORD: Forge123Xk9vQ2mZ\n"
        found = infra_scan(repo({".github/workflows/ci.yml": wf}), set())
        self.assertFalse(found["ci_test_secret"].hits or found["config_secret"].hits)

    def test_dockerfiles_that_dont_ship(self):
        root = repo({
            "Dockerfile": "FROM node:22 AS build\nRUN npm ci\nFROM node:22-alpine\nCMD [\"node\", \"x.js\"]\n",
            "dev/Dockerfile": "FROM node:22\n",
            "docs/Dockerfile": "FROM python:3.12\n",
            "web/Dockerfile": "FROM node:22 AS dev\n",
            "svc/Dockerfile": "FROM gcr.io/distroless/nodejs22-debian12:nonroot\n",
        })  # fmt: skip
        self.assertEqual([e.file for e in scan_config(root)["docker_root"].hits], ["Dockerfile"])


class SecretsTest(unittest.TestCase):
    def test_stand_in_keys_in_tests_and_public_keys_with_a_note(self):
        stripe = "sk_" + "live_"
        root = repo({
            "src/a.spec.ts": f'const k = "{stripe}AAAAAAAAAAAAAAAAAAAAAAAA";\n',
            "src/flow.go": "// The secret is safe to embed in version control: it's a native app's public client.\n"
                           'const oauthClientSecret = "34ddeff2b558a23d38fba8a6de74f086ede1cc0b"\n',
            "src/real.py": f'STRIPE = "{stripe}4eC39HqLyjWDarjtT1zdp7dc"\n',
        })  # fmt: skip
        self.assertEqual([e.file for e in scan_sources(root, ["src/a.spec.ts", "src/flow.go", "src/real.py"])["secret"].hits],
                         ["src/real.py"])  # fmt: skip


class PatternTest(unittest.TestCase):
    def scan(self, files):
        return scan_sources(repo(files), list(files))

    def test_names_that_only_look_like_eval(self):
        found = self.scan({
            "date_parser.py": "class EvalText:\n    def eval(self) -> str:\n        return self.s\n",
            "condition.ts": "class Condition {\n  eval(object) {\n    return 1;\n  }\n}\n",
            "loader.ts": "const esmImport = new Function('specifier', 'return import(specifier)');\n",
            "sample.py": "exec(open('configurator.py').read())\n",
            "opts.py": "from ruamel.yaml import YAML\nyaml = YAML(typ='safe')\ndata = yaml.load(text)\n",
            "bad.py": "result = eval(user_input)\n",
        })  # fmt: skip
        self.assertEqual(hits(found, "eval"), [("bad.py", 1)])

    def test_html_from_nothing_outside(self):
        found = self.scan({
            "theme.ts": "el.innerHTML = patchTheme(nightfox())\n",
            "html.tsx": "container.innerHTML = sanitizedBody\nconst x = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />\n",
            "errors.ts": "const m = { 1: `v-html will override element children.` }\n",
            "bad.ts": "el.innerHTML = userHtml\n",
        })  # fmt: skip
        self.assertEqual(hits(found, "raw_html"), [("bad.ts", 1)])

    def test_plain_http_that_no_one_requests(self):
        for line in ('xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"', "'http://superset:8088'", "'http://10.1.15.216:2283/api'",
                     '"http://example.com/test"', 'id: "http://purl.org/dc/terms/created"', '<a href="http://mitm.it/">',
                     "credits: ['http://kmandov.github.io/d3-horizon-chart/']"):  # fmt: skip
            self.assertFalse(internet_http(line), line)
        self.assertTrue(internet_http('SOURCE = "http://databank.worldbank.org/data/x.xlsx"'))

    def test_swallowed_errors_that_become_values_or_are_expected(self):
        found = self.scan({
            "poll.ts": "async function f() {\n  const db = await getDb(\n    id,\n  ).catch(() => null)\n  return Boolean(db)\n}\n",
            "probe.py": "def f():\n    try:\n        import greenlet\n    except Exception:\n        pass\n",
            "parse.ts": "function f(t) {\n  let v = t;\n  try {\n    v = JSON.parse(t);\n  } catch {}\n  return v;\n}\n",
            "bad.ts": "function g(t) {\n  try {\n    return JSON.parse(t);\n  } catch (e) {}\n}\n",
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "swallowed")], ["bad.ts"])

    def test_sql_with_escaped_or_constant_parts(self):
        found = self.scan({
            "a.ts": 'import db from "./db";\nawait connection.execute("CREATE DATABASE IF NOT EXISTS " + escapedDBName);\n'
                    'function q(key: "name" | "email") {\n  return db.query(`SELECT * FROM t WHERE ${key} = $1`, [v]);\n}\n'
                    'db.raw(`CREATE ${isUnique ? "UNIQUE " : ""}INDEX ?? ON ??`, [n, t]);\n'
                    'db.query(`SELECT * FROM t WHERE id IN (${sub.getQuery()})`);\n'
                    'db.query("SELECT * FROM users WHERE name = \'" + name + "\'");\n',
        })  # fmt: skip
        self.assertEqual(hits(found, "sql_built"), [("a.ts", 8)])

    def test_tls_off_behind_a_users_option(self):
        found = self.scan({
            "a.js": "if (notification.unsafeTls) {\n  config.httpsAgent = new https.Agent({\n    rejectUnauthorized: false,\n  });\n}\n",
            "b.ts": "const t = {\n  tls: env.SMTP_SECURE\n    ? undefined\n    : {\n        rejectUnauthorized: false,\n      },\n};\n",
            "c.py": "MAP = {\n    'CERT_NONE': CERT_NONE,\n}\nW_SSL_CERT_NONE = \"\"\"Setting ssl_cert_reqs=CERT_NONE\"\"\"\n",
            "bad.go": "var t = &tls.Config{InsecureSkipVerify: true}\n",
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "tls_off")], ["bad.go"])

    def test_unverified_jwt_peeks(self):
        found = self.scan({
            "saleor.py": "def is_saleor_token(token):\n    payload = jwt.decode(token, options={'verify_signature': False})\n"
                         "    return payload.get('owner') == 'saleor'\n",
            "teams.py": "def handle(h):\n    # Only use the unverified issuer to reject unsupported tokens; the SDK authenticates it later.\n"
                        "    claims = jwt.decode(h, options={'verify_signature': False})\n",
            "bad.py": "def decode(token):\n    return jwt.decode(token, options={'verify_signature': False})\n",
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "jwt_unverified")], ["bad.py"])

    def test_rm_rf_on_a_variable_set_in_the_same_file(self):
        found = infra_scan(repo({"docs/Makefile": "BUILDDIR = _build\nclean:\n\trm -rf $(BUILDDIR)/*\n",
                                 "run.sh": "#!/bin/sh\nrm -rf $TARGET/\n"}), set())  # fmt: skip
        self.assertEqual([e.file for e in found["shell_rm_var"].hits], ["run.sh"])


class PythonFlowTest(unittest.TestCase):
    def test_flows_that_dont_reach_the_sink(self):
        root = repo({
            "views.py": (
                "from flask import request, redirect\n"
                "from django.urls import reverse\n\n\n"
                "def stamp(connection, table):\n"
                "    user_id = request.json['id']\n"
                "    connection.execute(table.insert().values(user_id=user_id))\n\n\n"  # SQLAlchemy Core: bound values
                "def response_add(request, obj):\n"
                "    preserved_filters = request.GET.get('_changelist_filters')\n"
                "    redirect_url = request.path\n"
                "    redirect_url = add_preserved_filters({'preserved_filters': preserved_filters}, redirect_url)\n"
                "    return redirect(redirect_url)\n\n\n"
                "def find_page(request):\n"
                "    page = find_object(request.GET['html_path'])\n"
                "    url = reverse('detail_page', kwargs={'page_id': page.pk})\n"
                "    return redirect(f\"{url}?{request.GET.urlencode()}\")\n\n\n"
                "def static(request):\n"
                "    safe_path = build_safe_abspath('/srv/app', request.args['path'])\n"
                "    return open(safe_path).read()\n\n\n"
                "def bad(request):\n"
                "    return redirect(request.args['next'])\n"
            ),
        })  # fmt: skip
        flows = [f for f in build(root, cache=False).flags if f.kind == "taint"]
        self.assertEqual([f.target.split("::")[-1] for f in flows], ["bad"])


class PlatformTest(unittest.TestCase):
    def test_swift_casts_that_cant_fail(self):
        root = repo({
            "App/AppDelegate.swift": "let split = window!.rootViewController as! UISplitViewController\n"
                                     "let cell = tableView.dequeueReusableCell(withIdentifier: \"c\") as! Cell\n"
                                     "let id = Bundle.main.object(forInfoDictionaryKey: \"AppGroupId\") as! String\n"
                                     "let n = json[\"count\"] as! Int\n",
            "LoopTests/Mock.swift": "let d = x as! String\n",
        })  # fmt: skip
        self.assertEqual(hits(apple_scan(root, ["App/AppDelegate.swift", "LoopTests/Mock.swift"]), "swift_force"),
                         [("App/AppDelegate.swift", 4)])  # fmt: skip

    def test_personal_data_words_that_arent(self):
        root = repo({
            "services/doctor.go": 'logger.Warn("Regenerated hooks for %s", repo.FullName())\n',
            "lib/discover.go": 'slog.Debug("finder", "device", deviceID)\n',
            "Server/Host.cs": 'logger.LogInformation("Kestrel listening on {IpAddress}", ipAddress);\n',
            "src/commands/grant.ts": "console.debug('Admin access has been revoked from', email);\n",
            "pydantic/networks.py": 'def f():\n    """\n    print(user.email)\n    """\n',
            "src/auth.ts": "logger.log(`Registering new user: ${email}`);\n",
        })  # fmt: skip
        files = [
            "services/doctor.go",
            "lib/discover.go",
            "Server/Host.cs",
            "src/commands/grant.ts",
            "pydantic/networks.py",
            "src/auth.ts",
        ]
        self.assertEqual([e.file for e in privacy_scan(root, files)["privacy_log"].hits], ["src/auth.ts"])


class StructureTest(unittest.TestCase):
    def test_copies_made_on_purpose(self):
        self.assertTrue(deliberate_copies(["steps/2024-12-06/x.py", "steps/2026-05-22/x.py"]))
        self.assertTrue(deliberate_copies(["priv/static/phoenix.js", "priv/static/phoenix.mjs"]))
        self.assertTrue(deliberate_copies(["gui/vendor/daterangepicker/a.js", "gui/vendor/daterangepicker/b.js"]))
        self.assertFalse(deliberate_copies(["crates/dump/src/reader/v2/mod.rs", "crates/dump/src/reader/v3/mod.rs"]))

    def test_unused_code_named_where_calls_cant_be_followed(self):
        root = repo({
            "src/list.ts": "export {};\nfunction getWarehouses() { return 1; }\nconst p = { searchListMethod: 'getWarehouses' };\n",
            "src/elapsed.ts": "function formatElapsed() { return 1; }\nexport {};\n",
            "src/Panel.vue": "<script setup>\nimport { formatElapsed } from './elapsed';\n</script>\n",
            "src/dead.ts": "function reallyDead() { return 1; }\nexport {};\n",
        })  # fmt: skip
        g = build(root, cache=False)
        dead = {f.target.split("::")[-1] for f in g.flags if f.kind == "unused" and f.severity == "warn"}
        self.assertIn("reallyDead", dead)
        self.assertFalse(dead & {"getWarehouses", "formatElapsed"})

    def test_a_method_without_callers_is_a_hint_not_unused_code(self):
        root = repo({"svc.py": "class Handler(logging.Handler):\n    def emit(self, record):\n        return 1\n"})
        r = Review(build(root, cache=False).to_dict(), root)
        r.run()
        self.assertFalse([f for f in r.findings if f.title.startswith("Unused code")])

    def test_a_test_named_for_the_file_reaches_it(self):  # feature tests reach controllers through the router
        root = repo({
            "app/crud.py": "import sqlite3\n\n\ndef create_item(conn, x):\n    conn.execute('INSERT INTO t VALUES (?)', (x,))\n"
                           "    conn.commit()\n",
            "app/other.py": "import sqlite3\n\n\ndef purge(conn):\n    conn.execute('DELETE FROM t')\n    conn.commit()\n",
            "tests/test_crud.py": "def test_create(client):\n    assert client.post('/items').status_code == 200\n",
        })  # fmt: skip
        r = Review(build(root, cache=False).to_dict(), root)
        reached = {fid.split("::")[-1] for fid in r.reached}
        self.assertIn("create_item", reached)
        self.assertNotIn("purge", reached)

    def test_an_import_only_for_javadoc_is_not_a_dependency(self):
        root = repo({
            "p/Converter.java": "package p;\nimport p.Body;\n/** See {@link Body}. */\npublic interface Converter { int x(); }\n",
            "p/Body.java": "package p;\nimport p.Converter;\n/** Uses a {@link Converter}. */\npublic @interface Body { }\n",
        })  # fmt: skip
        g = build(root, cache=False)
        self.assertFalse([e for e in g.edges if e.kind == "import"])

    def test_an_import_loop_shows_a_real_chain(self):
        root = repo({"a.py": "import b\nimport c\n", "b.py": "import a\n", "c.py": "x = 1\n"})
        msg = next(f.message for f in build(root, cache=False).flags if f.kind == "cycle")
        self.assertIn("a.py → b.py → a.py", msg)


class EndpointTest(unittest.TestCase):
    def open_writes(self, files):
        root = repo(files)
        r = Review(build(root, cache=False).to_dict(), root)
        r.run()
        return next((f for f in r.findings if f.title.startswith("Endpoints that change data")), None)

    def test_inline_app_middleware_that_checks_the_session(self):
        app = ("const express = require('express');\nconst fs = require('fs');\nconst app = express();\n"
               "app.use((req, res, next) => {\n  if (req.path === '/health') return next();\n"
               "  return validateSessionMiddleware(req, res, next);\n});\n"
               "app.post('/sync', (req, res) => { fs.writeFileSync('x', req.body); res.end(); });\n"
               "app.listen(3000, '0.0.0.0');\n")  # fmt: skip
        self.assertIsNone(self.open_writes({"server.js": app}))
        self.assertIsNotNone(self.open_writes({"server.js": app.replace("validateSessionMiddleware(req, res, next)", "next()")}))

    def test_a_read_or_a_setup_route_is_not_an_open_write(self):
        app = ("const express = require('express');\nconst fs = require('fs');\nconst app = express();\n"
               "app.get('/version', (req, res) => { fs.writeFileSync('cache', 'x'); res.end(); });\n"
               "app.post('/api/setup', (req, res) => { fs.writeFileSync('db', req.body); res.end(); });\n"
               "app.listen(3000, '0.0.0.0');\n")  # fmt: skip
        self.assertIsNone(self.open_writes({"server.js": app}))

    @unittest.skipUnless(available(), "needs the language pack (PHP is parsed with tree-sitter)")
    def test_utopia_php_routes_and_their_scope_labels(self):  # appwrite: 745 routes nobody saw
        from codefactory.brief import View
        from codefactory.security import surface

        root = repo({
            "app/controllers/general.php": "<?php\nHttp::get('/v1/ping')\n    ->label('scope', 'public')\n    ->action(fn () => 1);\n",
            "src/Modules/Documents/Create.php": "<?php\nclass Create extends Action {\n  public function __construct() {\n"
                                                "    $this->setHttpMethod(Action::HTTP_REQUEST_METHOD_POST)\n"
                                                "      ->setHttpPath('/v1/databases/:id/documents')\n"
                                                "      ->label('scope', 'documents.write');\n  }\n}\n",
        })  # fmt: skip
        g = build(root, cache=False).to_dict()
        found = {(e.method, e.path, e.auth) for e in surface(root, g, View(g)).entries if e.framework == "Utopia"}
        self.assertEqual(found, {("GET", "/v1/ping", ""), ("POST", "/v1/databases/:id/documents", "scope documents.write")})

    def entries(self, files):
        from codefactory.brief import View
        from codefactory.security import surface

        root = repo(files)
        g = build(root, cache=False).to_dict()
        return {(e.framework, e.method, e.path, bool(e.auth)) for e in surface(root, g, View(g)).entries}

    def test_nest_routes_class_guards_and_public_routes_under_a_global_guard(self):
        found = self.entries({
            "src/users.controller.ts": "@Controller('users')\n@UseGuards(JwtAuthGuard)\nexport class UsersController {\n"
                                       "  @Post()\n  create(@Body() dto: any) { return this.repo.save(dto); }\n}\n",
            "src/open.controller.ts": "@Controller('open')\nexport class OpenController {\n  @Post('x')\n  write() { return 1; }\n}\n",
        })  # fmt: skip
        self.assertEqual(found, {("NestJS", "POST", "/users", True), ("NestJS", "POST", "/open/x", False)})
        found = self.entries({
            "src/app.module.ts": "providers: [{ provide: APP_GUARD, useClass: AuthGuard }]\n",
            "src/open.controller.ts": "@Controller('open')\nexport class OpenController {\n  @Post('x')\n  write() { return 1; }\n\n"
                                      "  @Public()\n  @Post('signup')\n  signup() { return 1; }\n}\n",
        })  # fmt: skip
        self.assertEqual(found, {("NestJS", "POST", "/open/x", True), ("NestJS", "POST", "/open/signup", False)})

    def test_next_middleware_and_its_matcher(self):
        found = self.entries({
            "middleware.ts": "export async function middleware(req) { const t = await getToken({ req }); }\n"
                             "export const config = { matcher: ['/api/admin/:path*'] };\n",
            "app/api/admin/users/route.ts": "export async function POST(req: Request) { await db.user.create({}); }\n",
            "app/api/public/route.ts": "export async function POST(req: Request) { await db.user.create({}); }\n",
        })  # fmt: skip
        self.assertEqual(found, {("Next.js", "POST", "/api/admin/users", True), ("Next.js", "POST", "/api/public", False)})


if __name__ == "__main__":
    unittest.main()
