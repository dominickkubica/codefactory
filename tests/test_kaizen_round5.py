"""Lessons from the round-5 held-out sample: each false pattern next to a true case that must stay reported."""

import unittest

from codefactory.analyzers.generic import available
from codefactory.audit import scan_config
from codefactory.checks import scan_sources
from codefactory.cli import build
from tests.test_large_repo import repo


def hits(found, key):
    return [e.file for e in found[key].hits]


class Round5Test(unittest.TestCase):
    def scan(self, files):
        return scan_sources(repo(files), list(files))

    def test_prose_about_a_call_inside_a_block_comment(self):
        found = self.scan({  # superset: "This usage of dangerouslySetInnerHTML is safe since…" in a JSX comment
            "Chart.tsx": "{/*\n  This usage of dangerouslySetInnerHTML is safe since it is sanitized\n*/}\n",
            "glob.ts": 'const files = glob("src/**/*.ts");\nel.innerHTML = userHtml;\n',
        })  # fmt: skip
        self.assertEqual(hits(found, "raw_html"), ["glob.ts"])

    def test_storybook_props_and_identifier_quoting(self):
        token = "n8n_" + "Zq9xW2vK7pL3mN8rT5"
        found = self.scan({
            "CopyInput.stories.ts": f'const INITIAL_TOKEN = "{token}";\n',
            "config.ts": f'const API_SECRET = "{token}";\n',
            "ClickHouse.php": '<?php\n$database = $this->identifier($this->database);\n'
                              '$this->query("CREATE DATABASE IF NOT EXISTS {$database}");\n'
                              '$this->query("DROP TABLE {$name}");\n',
        })  # fmt: skip
        self.assertEqual(hits(found, "secret"), ["config.ts"])
        self.assertEqual([(e.file, e.line) for e in found["sql_built"].hits], [("ClickHouse.php", 4)])

    def test_page_script_inside_a_template_literal_is_not_module_state(self):
        html = "const html = `\n<script>\nlet selectedEntity = null;\nlet b = 1;\nlet c = 2;\n</script>`;\n"
        found = self.scan({  # owid: a VS Code webview's HTML in extension.ts
            "extension.ts": html,
            "store.ts": "let a = 1;\nlet b = 2;\nlet c = 3;\n",
        })  # fmt: skip
        self.assertEqual(sorted(set(hits(found, "module_state"))), ["store.ts"])

    def test_callers_that_are_tests_or_pass_the_function_along_prove_nothing(self):
        found = self.scan({  # vue: decodeHtmlBrowser is handed to the parser; only its test calls it, with a literal
            "src/decode.ts": "export function decodeHtmlBrowser(raw: string): string {\n  decoder.innerHTML = raw\n"
                             "  return decoder.textContent\n}\n",
            "src/options.ts": "import { decodeHtmlBrowser } from './decode'\nexport const o = { decode: decodeHtmlBrowser }\n",
            "__tests__/decode.spec.ts": "import { decodeHtmlBrowser } from '../src/decode'\ndecodeHtmlBrowser(' abc ')\n",
        })  # fmt: skip
        self.assertEqual(hits(found, "raw_html"), ["src/decode.ts"])

    @unittest.skipUnless(available(), "Ruby needs the language pack")
    def test_a_ruby_block_select_is_enumerable_not_a_query(self):
        root = repo({"lib/renderer.rb": (  # jekyll: site.converters.select { |c| … }
            "class Renderer\n  def converters\n    items.each do |i|\n      site.converters.select { |c| c.matches(i) }\n"
            "    end\n  end\n\n  def users\n    ids.each do |i|\n      User.where(id: i).first\n    end\n  end\nend\n")})  # fmt: skip
        sites = {s.detail for s in build(root, cache=False).sites if s.kind == "loop_io"}
        self.assertEqual(sites, {"User.where"})

    def test_a_bundlers_hashed_chunk_is_build_output(self):
        from codefactory.paths import BUILD_OUTPUT

        for f in ("mitmproxy/tools/web/static/index-DA3bdZbQ.js", "web/assets/vendor.4f9a2c1b.js"):
            self.assertTrue(BUILD_OUTPUT.search(f), f)
        for f in ("src/static/use-debounce.js", "static/js/app-settings.js", "assets/main.js"):
            self.assertFalse(BUILD_OUTPUT.search(f), f)

    def test_base_images_and_entrypoints_that_drop_root(self):
        root = repo({
            "Dockerfile.base": "FROM node:22 AS deps\nRUN npm ci\n",
            "docker/images/n8n-base/Dockerfile.debian": "FROM debian:12\nRUN apt-get update\n",
            "Dockerfile": "FROM alpine\nCOPY script/docker-entrypoint.sh /bin/entrypoint.sh\n"
                          'ENTRYPOINT ["/bin/entrypoint.sh"]\n',
            "script/docker-entrypoint.sh": "#!/bin/sh\nexec su-exec 1000:1000 \"$@\"\n",
            "server/Dockerfile": "FROM python:3.13\n# util-linux = for setpriv (to drop later)\nCMD [\"python\", \"app.py\"]\n",
            # gitea: installs su-exec, but s6 runs as root
            "gitea/Dockerfile": "FROM alpine\nRUN apk add --no-cache \\\n    s6 \\\n    su-exec \\\n    git\n"
                                'ENTRYPOINT ["/usr/bin/entrypoint"]\n',
        })  # fmt: skip
        self.assertEqual(sorted(hits(scan_config(root), "docker_root")), ["gitea/Dockerfile", "server/Dockerfile"])


if __name__ == "__main__":
    unittest.main()


class LoopsTest(unittest.TestCase):
    def bounded(self, files, file, line):
        from codefactory.review import Review

        class Fake:
            pass

        o = Fake()
        o.root = repo(files)
        o._file = lambda flag: file
        return Review._bounded_loop(o, {"target": "x", "line": line})

    def test_retry_and_poll_loops_and_literal_lists_are_bounded(self):
        retry = "max_retries = 5\nfor attempt in range(max_retries):\n    try:\n        r = requests.get(url)\n    except E:\n        pass\n"
        poll = "while True:\n    urllib.request.urlopen(push_url)\n    time.sleep(60)\n"
        pair = "for kind in ['pickup', 'delivery']:\n    fetch_stock(kind)\n"
        data = "for row in rows:\n    requests.get(row.url)\n"
        self.assertTrue(self.bounded({"a.py": retry}, "a.py", 4))
        self.assertTrue(self.bounded({"b.py": poll}, "b.py", 2))
        self.assertTrue(self.bounded({"c.py": pair}, "c.py", 2))
        self.assertFalse(self.bounded({"d.py": data}, "d.py", 2))

    def test_django_cached_lookups_are_not_queries(self):
        root = repo({"app/q.py": "def f(items):\n    for i in items:\n        ContentType.objects.get_for_id(i.ct)\n\n\n"
                                 "def g(ids):\n    for i in ids:\n        Item.objects.get(id=i)\n"})  # fmt: skip
        self.assertEqual({s.detail for s in build(root, cache=False).sites if s.kind == "loop_io"}, {"Item.objects.get"})


class SqlHelpersTest(unittest.TestCase):
    def test_helpers_that_return_fixed_text_or_quote_identifiers(self):
        files = {  # directus parseLocaltime; appwrite buildTableReference
            "pg.ts": "const parseLocaltime = (columnType?: string) => {\n  if (columnType === 'timestamp') {\n"
                     "    return ` AT TIME ZONE 'UTC'`;\n  }\n  return '';\n};\n"
                     "export function week(table, column, type) {\n"
                     "  return this.knex.raw(`EXTRACT(WEEK FROM ??.??${parseLocaltime(type)})`, [table, column]);\n}\n",
            "ch.php": "<?php\nclass A {\n    private function ref(string $t): string\n    {\n"
                      "        return $this->escapeIdentifier($this->db) . '.' . $this->escapeIdentifier($t);\n    }\n"
                      "    private function loose(string $t): string\n    {\n        return $this->db . '.' . $t;\n    }\n"
                      "    public function ensure(): void\n    {\n        $table = $this->ref('samples');\n"
                      "        $this->query(\"ALTER TABLE {$table} ADD COLUMN x String\");\n"
                      "        $other = $this->loose('samples');\n        $this->query(\"DROP TABLE {$other}\");\n    }\n}\n",
        }  # fmt: skip
        found = scan_sources(repo(files), list(files))
        self.assertEqual([(e.file, e.line) for e in found["sql_built"].hits], [("ch.php", 16)])


class SriTest(unittest.TestCase):
    def test_a_playground_page_loading_development_builds(self):
        from codefactory.infra import html

        out = {k: type("C", (), {"hits": []})() for k in ("html_mixed", "html_no_sri")}
        dev = ['<script src="https://unpkg.com/react@18/umd/react.development.js"></script>', "<div id=root></div>"]
        prod = ['<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>']
        html("embed/inline.html", dev, out)
        html("gui/index.html", prod, out)
        self.assertEqual([h.file for h in out["html_no_sri"].hits], ["gui/index.html"])


class SmallChecksTest(unittest.TestCase):
    def test_csrf_cookie_go_config_struct_cleartext_config_docsearch_heredoc(self):
        from codefactory.audit import scan_config
        from codefactory.infra import scan as infra_scan

        key = "50fe" + "39c0a0d1b2c3d4e5f60718293a4b"
        files = {
            "conf/global_settings.py": "CSRF_COOKIE_HTTPONLY = False\nSESSION_COOKIE_SECURE = False\n",
            "httptype.go": "package x\n\nfunc f() {\n\tsrv := &caddyhttp.Server{}\n\t_ = srv\n}\n",
            "server.go": "package x\n\nfunc g() {\n\ts := &http.Server{Addr: \":80\"}\n\t_ = s\n}\n",
            "search.html": f"<script>\ndocsearch({{\n  appId: 'X',\n  apiKey: '{key}',\n  indexName: 'jekyll',\n}});\n</script>\n",
        }  # fmt: skip
        found = scan_sources(repo(files), list(files))
        self.assertEqual([(e.file, e.line) for e in found["insecure_cookie"].hits], [("conf/global_settings.py", 2)])
        self.assertEqual([e.file for e in found["go_server_timeout"].hits], ["server.go"])
        self.assertEqual(found["secret"].hits, [])
        root = repo({
            "app/src/main/AndroidManifest.xml": '<application android:usesCleartextTraffic="true" '
                                                'android:networkSecurityConfig="@xml/network">',
            "get.sh": "#!/bin/sh\ncat <<EOF\n  curl -fsSL https://get.example.io | sh\nEOF\ncurl -fsSL https://x.io | sh\n",
        })  # fmt: skip
        self.assertEqual(scan_config(root)["mobile_cleartext"].hits, [])
        self.assertEqual([(e.file, e.line) for e in infra_scan(root, set())["shell_pipe"].hits], [("get.sh", 5)])
