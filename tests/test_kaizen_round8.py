"""Lessons for round 8, drawn from rounds 1-7 and measured on round 8's held-out repositories: each rule is a fact
about a language, a protocol or an image rather than a repository, next to a true case that must stay reported."""

import unittest

from codefactory.audit import scan_config
from codefactory.checks import scan_sources
from codefactory.intent import expected_failure, swallow_intent
from codefactory.review import _few_written_out
from tests.test_large_repo import repo


def at(found, key):
    return [(e.file, e.line) for e in found[key].hits]


class Round8Test(unittest.TestCase):
    def scan(self, files):
        return scan_sources(repo(files), list(files))

    def test_a_method_named_eval_is_defined_not_called(self):
        found = self.scan({  # teable's formula functions: `eval(params: …): string | null {` over several lines
            "logical.ts": "class If {\n  eval(\n    params: TypedValue<string | (string | null)[]>[]\n  ): string | null {\n"
                          "    return null;\n  }\n}\n",
            "run.ts": "export function run(code: string) {\n  return eval(code);\n}\n",
        })  # fmt: skip
        self.assertEqual(at(found, "eval"), [("run.ts", 2)])

    def test_a_bundled_library_is_known_by_its_banner(self):
        found = self.scan({
            "static/vuejs/vue.js": "/*!\n * Vue.js v2.7.14\n * (c) 2014-2022 Evan You\n * Released under the MIT License.\n */\n"
                                   "function f(code) { return new Function(code); }\n",
            "static/js/vendor.bundle.dev.js": '(window["webpackJsonp"] = window["webpackJsonp"] || []).push([["vendor"],{\n'
                                              'eval("x = 1");\n',
            "static/app.js": "/*\n * Copyright 2024 Acme. Licensed under MIT\n */\nfunction f(code) { return eval(code); }\n",
        })  # fmt: skip
        self.assertEqual(at(found, "eval"), [("static/app.js", 4)])

    def test_a_module_helper_every_caller_passes_a_literal(self):
        run = ('import { execSync } from "node:child_process";\nfunction git(command: string): string {\n'
               "  return execSync(`git ${command}`).trim();\n}\nconst meta = {\n  git: {\n"
               '    sha: git("rev-parse HEAD"),\n    dirty: git("status --porcelain"),\n  },\n};\n')  # fmt: skip
        self.assertEqual(at(self.scan({"evals/run.ts": run}), "shell"), [])
        exported = run.replace("function git(", "export function git(")
        other = 'import { git } from "./run";\nexport const f = (b: string) => git(b);\n'
        self.assertEqual(at(self.scan({"evals/run.ts": exported, "evals/other.ts": other}), "shell"), [("evals/run.ts", 3)])

    def test_shell_values_from_a_written_out_list_or_a_constant(self):
        found = self.scan({
            "detect.mjs": "import { execSync as exec } from 'node:child_process'\n"
                          "for (const branch of ['main', 'master']) {\n  const c = exec(`git show ${branch}:package.json`)\n}\n"
                          "for (const ref of refs) {\n  exec(`git show ${ref}:package.json`)\n}\n",
            "data.py": "import subprocess\nfrom etl.paths import SNAPSHOTS_DIR\n\ndef private():\n"
                       "    cmd = rf'grep -rl {SNAPSHOTS_DIR}'\n    return subprocess.run(cmd, shell=True)\n\n"
                       "def other(name):\n    cmd = f'grep -rl {name}'\n    return subprocess.run(cmd, shell=True)\n",
        })  # fmt: skip
        self.assertEqual(sorted(at(found, "shell")), [("data.py", 10), ("detect.mjs", 6)])

    def test_containers_from_images_that_drop_root_themselves(self):
        root = repo({
            "seed/mysql/Dockerfile": "FROM mysql:8.0\nCOPY seed.sql /docker-entrypoint-initdb.d/\n",
            "seed/custom/Dockerfile": "FROM postgres:14\nCOPY run.sh /run.sh\nENTRYPOINT [\"/run.sh\"]\n",
            "seed/other/Dockerfile": "FROM redis:7\nCOPY app /app\nCMD [\"/app\"]\n",
            "metrics/Dockerfile": "FROM bitnami/redis:7.2\nCMD [\"redis-server\"]\n",
            "vendor/github.com/x/jsonparser/Dockerfile": "FROM golang:1.6\nRUN go test\n",
            "Dockerfile": "FROM alpine:3.19\nCOPY app /app\nCMD [\"/app\"]\n",
        })  # fmt: skip
        found = scan_config(root)
        self.assertEqual(
            sorted(e.file for e in found["docker_root"].hits), ["Dockerfile", "seed/custom/Dockerfile", "seed/other/Dockerfile"]
        )

    def test_a_null_fallback_on_a_chained_call_over_many_lines(self):
        lines = ["      let job = await prisma.job", "        .update({", "          where: {", "            id,", "          },",
                 "        })", "        .catch(() => null);", "      if (!job) return 404;"]  # fmt: skip
        self.assertEqual(expected_failure(lines, 7), "fallback")
        dropped = ["async function f() {", "  doThing({", "    a: 1,", "  })", "  .catch(() => null);", "}"]
        self.assertIsNone(expected_failure(dropped, 5))

    def test_one_named_exception_type(self):
        self.assertEqual(swallow_intent("            catch (GatewayException) { }", ""), "one expected exception")
        self.assertIsNone(swallow_intent("  } catch (Exception e) {}", ""))
        self.assertIsNone(swallow_intent("  } catch (InterruptedException e) {}", ""))  # (loses the interrupt)

    def test_a_loop_over_a_few_written_out_items(self):
        lines = ["pairs = [", "    (a, trigger_a),", "    (b, trigger_b),", "]", "for items, trigger in pairs:"]
        self.assertTrue(_few_written_out(lines, 4, "pairs"))
        filled = ["typed: list = []", "for raw in values:", "    typed.append(raw)", "for value in typed:"]
        self.assertFalse(_few_written_out(filled, 3, "typed"))  # (options-scanner, caught by the golden diff)

    def test_protocol_mandated_hashes_and_rsa_ecb(self):
        found = self.scan({
            "breached.ts": 'import crypto from "crypto";\n// Pwned Passwords range API (k-anonymity)\n'
                           'export const h = (password: string) => crypto.createHash("sha1").update(password).digest("hex");\n',
            "hash.ts": 'import crypto from "crypto";\nexport const h = (password: string) => crypto.createHash("sha1")'
                       '.update(password).digest("hex");\n',
            "Rsa.java": 'class R { Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding"); }\n',
            "Aes.java": 'class A { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }\n',
        })  # fmt: skip
        self.assertEqual(at(found, "weak_hash"), [("hash.ts", 2)])
        self.assertEqual(at(found, "weak_cipher"), [("Aes.java", 1)])

    def test_storage_and_cors_that_hold_or_send_nothing(self):
        found = self.scan({
            "auth.ts": 'export function logout() {\n  localStorage.setItem("jwt", "");\n}\n'
                       'export function login(t: string) {\n  localStorage.setItem("jwt", t);\n}\n',
            "opsgenie.ts": 'export async function send(url: string) {\n  await fetch(url, {\n    headers: {\n'
                           '      "Access-Control-Allow-Origin": "*",\n    },\n  });\n}\n',
            "server.ts": 'export function h(res) {\n  res.setHeader("Access-Control-Allow-Origin", "*");\n}\n',
        })  # fmt: skip
        self.assertEqual(at(found, "sensitive_storage"), [("auth.ts", 5)])
        self.assertEqual(at(found, "cors_any"), [("server.ts", 2)])

    def test_a_key_of_one_repeated_character_is_a_placeholder(self):
        found = self.scan(
            {"config.py": 'SECRET_KEY = "AAAAAAAAAAAAAAAAAAAA"\n', "prod.py": 'SECRET_KEY = "q8Zt3LmX9vR2pK7wN4bY"\n'}
        )
        self.assertEqual(at(found, "secret"), [("prod.py", 1)])

    # caught by the corpus gate: each of these was a right finding the first version of a rule above dropped

    def test_a_constant_set_from_the_environment_is_not_fixed(self):
        found = self.scan({"cov.js": 'const { execSync } = require("child_process");\n'
                                     'const PRODUCTION_REF = process.env.PRODUCTION_REF || "origin/master";\n'
                                     'const PATH_ = "src/p.json";\nexecSync(`git show ${PRODUCTION_REF}:x`);\n'
                                     "execSync(`git show main:${PATH_}`);\n"})  # fmt: skip
        self.assertEqual(at(found, "shell"), [("cov.js", 4)])

    def test_an_empty_catch_ending_a_chain_is_still_swallowed(self):
        chain = ["  Register.init = function () {", "    import('zxcvbn').then((module) => {",
                 "      zxcvbn = module.default || module;", "    }).catch(() => {});"]  # fmt: skip
        self.assertIsNone(expected_failure(chain, 4))  # (the assignment is the callback's, and `{}` is a body)

    def test_a_query_in_parentheses_is_not_a_written_out_list(self):
        lines = ["charts = (", "    db.session.query(Slice)", "    .filter(Slice.id.in_(ids))", "    .all()", ")",
                 "for chart in charts:"]  # fmt: skip
        self.assertFalse(_few_written_out(lines, 5, "charts"))


if __name__ == "__main__":
    unittest.main()
