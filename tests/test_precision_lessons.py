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
            "src/gh.go": "var (\n\toauthClientID = \"178c6fc778ccc68e1d6a\"\n\t// This value is safe to be embedded in version control\n"
                         "\toauthClientSecret = \"34ddeff2b558a23d38fba8a6de74f086ede1cc0b\"\n)\n",
            "src/consts.py": 'ENV_GRANT_TOKEN = "N8N_RUNNERS_GRANT_TOKEN"\n',
        })  # fmt: skip
        files = ["src/a.spec.ts", "src/flow.go", "src/real.py", "src/gh.go", "src/consts.py"]
        self.assertEqual([e.file for e in scan_sources(root, files)["secret"].hits], ["src/real.py"])


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

    def test_commands_and_html_built_only_from_fixed_strings(self):
        found = self.scan({
            "release.mjs": "const botName = 'github-actions[bot]';\nconst baseBranch = 'master';\n"
                           "await exec(`git config user.name '${botName}'`);\nawait exec(`git fetch origin ${baseBranch}`);\n",
            "command.rb": 'msg = " Please append `--trace` to the `#{cmd.name}` command "\n',
            "icons.js": "const svgSprite = '<svg><symbol id=\"a\"></symbol></svg>';\ndiv.innerHTML = svgSprite\n",
            "page.tsx": "const pageStatus = code === 404 ? '404' : '200';\n"
                        "const s = <script dangerouslySetInnerHTML={{ __html: `window.status = '${pageStatus}'` }} />;\n",
            "sim.js": "picker.innerHTML = `<option>${esc(name)}</option>`\n",
            "pdf.ts": "template.innerHTML = contentHtml\n",
            "bad.js": "await exec(`git checkout ${process.argv[2]}`);\nel.innerHTML = `<b>${userName}</b>`;\n",
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "shell")], ["bad.js"])
        self.assertEqual([f for f, _ in hits(found, "raw_html")], ["bad.js"])

    def test_hashes_that_only_name_things_and_more_expected_failures(self):
        found = self.scan({
            "models.py": "def bucket_for_email(email):\n    salted = (email + settings.SECRET_KEY).encode()\n"
                         "    hashed = hashlib.sha1(salted).hexdigest()\n    return TokenBucket.authorize(hashed)\n",
            "pw.py": "def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n",
            "copy.tsx": "function copy(t) {\n  navigator.clipboard.writeText(t).catch(() => {})\n}\n",
            "panel.tsx": "const items = ids.map((id) => emojis.fetch(id).catch(() => undefined));\n",
            "init.py": "def setup():\n    try:\n        import greenlet\n        check(greenlet.__version__)\n    except Exception:\n        pass\n",
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "weak_hash")], ["pw.py"])
        self.assertFalse(hits(found, "swallowed"))
        for line in ('"docs_url": "http://www.vertica.com/",', "examples: [{ example: '\"Check out http://n8n.io\".extractUrl()' }]",
                     'add_preloaded("http://w3id.org/security/v1") do'):  # fmt: skip
            self.assertFalse(internet_http(line), line)

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

    def test_sql_that_is_only_text_or_isnt_sql(self):
        found = self.scan({
            "v195.go": 'func f(sess *Session) error {\n\tif _, err := sess.Exec("INSERT INTO idx (repo_id, sha) " +\n'
                       '\t\t"SELECT repo_id, sha FROM commit_status"); err != nil {\n\t\treturn err\n\t}\n\treturn nil\n}\n',
            "loader.go": 'func g(tx *Tx, fixture F) error {\n\t_, err = tx.Exec("DELETE FROM " + fixture.tableNameQuoted)\n'
                         '\tif err != nil {\n\t\treturn err\n\t}\n\treturn nil\n}\n',
            "Builder.php": "<?php\nif (! is_numeric($amount)) { throw new Exception(); }\n"
                           "$columns[$column] = $this->raw(\"{$this->grammar->wrap($column)} + $amount\");\n",
            "Server.kt": 'fun s() {\n  queue.execute("MockWebServer ${raw.remoteSocketAddress}", cancelable = false) {\n    select()\n  }\n}\n',
            "bad.go": 'func h(db *DB, owner string) {\n\tdb.Query("SELECT * FROM items WHERE owner = \'" + owner + "\'")\n}\n',
        })  # fmt: skip
        self.assertEqual([f for f, _ in hits(found, "sql_built")], ["bad.go"])

    def test_tls_off_behind_a_users_option(self):
        found = self.scan({
            "a.js": "if (notification.unsafeTls) {\n  config.httpsAgent = new https.Agent({\n    rejectUnauthorized: false,\n  });\n}\n",
            "b.ts": "const t = {\n  tls: env.SMTP_SECURE\n    ? undefined\n    : {\n        rejectUnauthorized: false,\n      },\n};\n",
            "c.py": "MAP = {\n    'CERT_NONE': CERT_NONE,\n}\nW_SSL_CERT_NONE = \"\"\"Setting ssl_cert_reqs=CERT_NONE\"\"\"\n",
            "redis.py": "CERTS = {\n    'none': CERT_NONE,\n}\ndef f(r):\n    if r == CERT_NONE:\n        warn()\n",
            "httpie.py": "def ciphers(cls):\n    return [c for c in cls._create_ssl_context(verify=False).get_ciphers()]\n",
            "quest.ts": "function tls(skipVerification: boolean) {\n  if (skipVerification) return { rejectUnauthorized: false };\n}\n",
            "server.ts": "createServer({\n  requestCert: true,\n  rejectUnauthorized: false,\n}, h);\n",
            "relay.go": "var c = &tls.Config{\n\tClientAuth: tls.RequestClientCert,\n\tInsecureSkipVerify: true,\n}\n",
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

    def test_more_casts_that_cant_fail(self):
        root = repo({"App/Bg.swift": "if task is BGAppRefreshTask {\n  handle(task: task as! BGAppRefreshTask)\n}\n"
                                     "let v = object(forInfoDictionaryKey: \"CFBundleShortVersionString\") as! String\n"
                                     "let n = payload[\"n\"] as! Int\n"})  # fmt: skip
        self.assertEqual(hits(apple_scan(root, ["App/Bg.swift"]), "swift_force"), [("App/Bg.swift", 5)])

    def test_fetch_that_isnt_a_request_and_a_global_axios_timeout(self):
        root = repo({
            "src/hooks.ts": "async function fetch() {\n  return send('status');\n}\n",
            "src/assets.ts": "export async function f(url: string) {\n  const dataUrl = url;\n  const res = await fetch(dataUrl);\n}\n",
            "server/server.ts": "import axios from 'axios';\naxios.defaults.timeout = 300_000;\n",
            "server/discord.ts": "import axios from 'axios';\nawait axios.post(url, payload);\n",
            "src/api.ts": "export const get = () => fetch('/api/x');\n",
        })  # fmt: skip
        files = ["src/hooks.ts", "src/assets.ts", "server/server.ts", "server/discord.ts", "src/api.ts"]
        self.assertEqual([e.file for e in scan_sources(root, files)["fetch_no_timeout"].hits], ["src/api.ts"])

    def test_images_that_test_or_build(self):
        root = repo({
            "packages/http/Dockerfile.fpm": "FROM php:8.5-fpm-alpine AS final\nCOPY tests/ /app/tests/\nCOPY phpunit.xml /app/\n",
            "webui/buildx.Dockerfile": "FROM node:26-alpine\nRUN yarn build\n",
            "server/Dockerfile": "FROM node:22-alpine\nCMD [\"node\", \"x.js\"]\n",
        })  # fmt: skip
        self.assertEqual([e.file for e in scan_config(root)["docker_root"].hits], ["server/Dockerfile"])

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

    @unittest.skipUnless(available(), "needs the language pack")
    def test_calls_that_share_io_names_but_arent_io(self):
        root = repo({
            "svc/conv.go": "package svc\n\nimport \"sync\"\n\nvar once sync.Once\n\nfunc Convert(c string) string {\n"
                           "\tonce.Do(setup)\n\treturn c\n}\n\nfunc All(cs []string) {\n\tfor _, c := range cs {\n"
                           "\t\tConvert(c)\n\t}\n}\n\nfunc setup() {}\n",
            "app/Schema.php": "<?php\nclass Schema {\n  public static function build($cs) {\n    foreach ($cs as $c) {\n"
                              "      self::fail($c);\n    }\n  }\n  public static function fail($c) {\n"
                              "    throw Error::query($c);\n  }\n}\n",
        })  # fmt: skip
        flagged = [f for f in build(root, cache=False).flags if f.kind == "io_in_loop"]
        self.assertFalse(flagged, [f.message for f in flagged])

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

    def test_imported_names_and_property_reads_are_uses(self):
        root = repo({
            "src/hooks.ts": "export {};\nfunction useDeleteEscalation() { return 1; }\nfunction reallyDead() { return 2; }\n",
            "src/routes/$id/View.tsx": "import { useDeleteEscalation } from '@/lib/hooks';\n",
        })  # fmt: skip
        dead = {f.target.split("::")[-1] for f in build(root, cache=False).flags if f.kind == "unused" and f.severity == "warn"}
        self.assertEqual(dead & {"useDeleteEscalation", "reallyDead"}, {"reallyDead"})

    def test_build_outputs_dont_take_part_in_copies(self):
        body = "  let total = 0;\n  for (const x of xs) {\n    if (x > 0) total += x * 2;\n    else total -= x;\n  }\n" * 2
        root = repo({
            "assets/js/sum.js": "export function sum(xs) {\n" + body + "  return total;\n}\n",
            "priv/static/app.js": "function sum(xs) {\n" + body + "  return total;\n}\n",
        })  # fmt: skip
        self.assertFalse([f for f in build(root, cache=False).flags if f.kind in ("duplicate", "similar")])

    def test_copies_that_are_variants_or_constructors(self):
        from codefactory.review import _variants

        self.assertTrue(_variants(["r/bases/aria/ui/chart.tsx", "r/bases/base/ui/chart.tsx", "r/bases/radix/ui/chart.tsx"]))
        self.assertFalse(_variants(["a/x.py", "b/y.py", "c/x.py"]))
        self.assertTrue(Review._copied({"kind": "similar", "title": "Merge A.A, B.B (100% similar, ~12 lines)",
                                        "where": [{"file": "a.cs", "name": "TranscodingProfile.TranscodingProfile"},
                                                  {"file": "b.cs", "name": "TrickplayInfoDto.TrickplayInfoDto"}]}) is False)  # fmt: skip

    @unittest.skipUnless(available(), "needs the language pack")
    def test_csharp_projects_bound_dependencies(self):
        root = repo({
            "Core/Core.csproj": "<Project></Project>\n",
            "Server/Server.csproj": '<Project><ItemGroup><ProjectReference Include="../Core/Core.csproj" /></ItemGroup></Project>\n',
            "Core/Paths.cs": "using Server;\nnamespace Core { public class Paths { public Manager M; } }\n",
            "Server/Manager.cs": "using Core;\nnamespace Server { public class Manager { public Paths P; } }\n",
        })  # fmt: skip
        self.assertFalse([f for f in build(root, cache=False).flags if f.kind == "cycle"])

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

    def test_a_package_under_a_source_folder_is_named_from_its_top(self):
        root = repo({  # streamlit: lib/streamlit/… is imported as streamlit.…, and the long form still works
            "lib/pkg/__init__.py": "", "lib/pkg/elements/__init__.py": "",
            "lib/pkg/util.py": "def clean_text(t):\n    return t.strip()\n\n\ndef other(t):\n    return t\n",
            "lib/pkg/elements/text.py": "from pkg.util import clean_text\n\n\ndef show(x):\n    return clean_text(x)\n",
            "tests/test_x.py": "import lib.pkg.util\nfrom pkg.elements.text import show\n\n\ndef test_a():\n"
                               "    show(1)\n    lib.pkg.util.other(2)\n",
            "a/lib/x/__init__.py": "", "a/lib/x/m.py": "def f():\n    pass\n",  # two packages called x: not merged
            "b/lib/x/__init__.py": "", "b/lib/x/m.py": "def f():\n    pass\n",
        })  # fmt: skip
        g = build(root, cache=False)
        self.assertFalse([f.target for f in g.flags if f.kind == "unused" and f.target.startswith("lib/")])
        self.assertEqual(len({f.module for f in g.files if f.id.endswith("x/m.py")}), 2)

    def test_a_published_packages_api_is_used_by_its_users(self):
        root = repo({  # @immich/sdk, svelte/easing: exported from the entry, called only by the package's users
            "packages/sdk/package.json": '{"name": "@x/sdk", "main": "./build/index.js"}',
            "packages/sdk/src/index.ts": "export * from './client.js';\nexport { onlyThis } from './more';\n",
            "packages/sdk/src/client.ts": "export function deletePeople() {\n  return 1;\n}\n",
            "packages/sdk/src/more.ts": "export function onlyThis() {\n  return 1;\n}\nexport function notThis() {\n  return 2;\n}\n",
            "packages/sdk/src/use.ts": "import './more';\nexport const z = 1;\n",
            "apps/web/package.json": '{"name": "web", "private": true}',
            "apps/web/src/index.ts": "export * from './lib';\n", "apps/web/src/lib.ts": "export function appOnly() {\n  return 1;\n}\n",
        })  # fmt: skip
        unused = sorted(f.target for f in build(root, cache=False).flags if f.kind == "unused")
        self.assertEqual(unused, ["apps/web/src/lib.ts::appOnly", "packages/sdk/src/more.ts::notThis"])

    @unittest.skipUnless(available(), "Kotlin needs the language pack")
    def test_compose_previews_are_run_by_the_ide(self):
        root = repo({"ui/Card.kt": (
            "package ui\n\n@Composable\nfun Card() {\n    Text(\"x\")\n}\n\n@Preview\n@Composable\nprivate fun CardPreview() {\n"
            "    Card()\n}\n\n@DevicePreviews\n@Composable\nprivate fun CardDevices() {\n    Card()\n}\n\n"
            "@Composable\nprivate fun Orphan() {\n    Text(\"y\")\n}\n")})  # fmt: skip
        unused = [f.target for f in build(root, cache=False).flags if f.kind == "unused"]
        self.assertEqual(unused, ["ui/Card.kt::Orphan"])

    def test_names_that_are_not_files_make_no_import_loop(self):
        root = repo({  # C# `using` names a namespace; PHP needs the folder; a bare Ruby require is a gem
            "Svc/A.cs": "using Svc.Model;\nnamespace Svc { class A { } }\n",
            "Svc/Model.cs": "using Svc;\nnamespace Svc.Model { class Model { } }\n",
            "src/Net/DNS.php": "<?php\nuse Other\\Checks\\DNS;\nclass DNS {}\n",
            "lib/Validator/DNS.php": "<?php\nuse App\\Net\\DNS;\nclass DNS {}\n",
            "config/prometheus_exporter.rb": "require 'prometheus_exporter'\n",
            "app/prometheus_exporter.rb": "require_relative '../config/prometheus_exporter'\n",
        })  # fmt: skip
        self.assertFalse([f for f in build(root, cache=False).flags if f.kind == "cycle"])


class EndpointTest(unittest.TestCase):
    def open_writes(self, files):  # (a hint now, not a finding: still computed the same way)
        root = repo(files)
        r = Review(build(root, cache=False).to_dict(), root)
        r.run()
        return next((f for f in r.findings + r.hints if f.title.startswith("Endpoints that change data")), None)

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
            "src/Modules/Policies/Update.php": "<?php\nclass Update extends Action {\n  public function __construct() {\n"
                                               "    $this->setHttpMethod(Action::HTTP_REQUEST_METHOD_PATCH)\n"
                                               "      ->setHttpPath('/v1/project/policies/:id')\n"
                                               "      ->label('scope', ['policies.write', 'project.policies.write']);\n  }\n}\n",
        })  # fmt: skip
        g = build(root, cache=False).to_dict()
        found = {(e.method, e.path, e.auth) for e in surface(root, g, View(g)).entries if e.framework == "Utopia"}
        self.assertEqual(
            found,
            {
                ("GET", "/v1/ping", ""),
                ("POST", "/v1/databases/:id/documents", "scope documents.write"),
                ("PATCH", "/v1/project/policies/:id", "scope policies.write"),
            },
        )

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

    def test_pundit_devise_sign_in_and_rust_test_routers(self):
        from codefactory.review import SIGN_IN
        from codefactory.security import _RailsControllers

        root = repo({
            "app/controllers/admin/base_controller.rb": "module Admin\n  class BaseController < ApplicationController\n"
                                                        "    after_action :verify_authorized\n  end\nend\n",
            "app/controllers/admin/checks_controller.rb": "module Admin\n  class ChecksController < BaseController\n"
                                                          "    def destroy\n      authorize check, :restore?\n    end\n  end\nend\n",
        })  # fmt: skip
        files = ["app/controllers/admin/base_controller.rb", "app/controllers/admin/checks_controller.rb"]
        rails = _RailsControllers(root, files, {})
        text = (root / files[1]).read_text()
        self.assertTrue(rails.guard(text)[0])
        self.assertTrue(SIGN_IN.search("sessions#create Auth::SessionsController.create"))
        self.assertFalse(
            self.entries({"config/routes/admin.rb": "namespace :admin do\n  delete '/ignored_server_checks/:key'\nend\n"})
        )
        root = repo(
            {
                "src/lib.rs": 'pub fn real() {}\n\n#[cfg(test)]\nmod tests {\n    fn app() { Router::new().route("/", post(h)); }\n}\n'
            }
        )
        r = Review(build(root, cache=False).to_dict(), root)
        self.assertTrue(r._comment_line("src/lib.rs", 5))
        self.assertFalse(r._comment_line("src/lib.rs", 1))

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
