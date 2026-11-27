"""Lessons from the round-5 held-out sample: each false pattern next to a true case that must stay reported."""

import unittest

from codefactory.audit import scan_config
from codefactory.checks import scan_sources
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

    def test_base_images_and_entrypoints_that_drop_root(self):
        root = repo({
            "Dockerfile.base": "FROM node:22 AS deps\nRUN npm ci\n",
            "docker/images/n8n-base/Dockerfile.debian": "FROM debian:12\nRUN apt-get update\n",
            "Dockerfile": "FROM alpine\nCOPY script/docker-entrypoint.sh /bin/entrypoint.sh\n"
                          'ENTRYPOINT ["/bin/entrypoint.sh"]\n',
            "script/docker-entrypoint.sh": "#!/bin/sh\nexec su-exec 1000:1000 \"$@\"\n",
            "server/Dockerfile": "FROM python:3.13\nCMD [\"python\", \"app.py\"]\n",
            # gitea: installs su-exec, but s6 runs as root
            "gitea/Dockerfile": "FROM alpine\nRUN apk add --no-cache \\\n    s6 \\\n    su-exec \\\n    git\n"
                                'ENTRYPOINT ["/usr/bin/entrypoint"]\n',
        })  # fmt: skip
        self.assertEqual(sorted(hits(scan_config(root), "docker_root")), ["gitea/Dockerfile", "server/Dockerfile"])


if __name__ == "__main__":
    unittest.main()
