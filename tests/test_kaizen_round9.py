"""Lessons for round 9, from rounds 1-8 and measured on round 9's held-out repositories: each rule is a fact about a
language, next to a true case that must stay reported."""

import unittest

from codefactory.analyzers.generic import available
from codefactory.audit import scan_config
from tests.test_large_repo import repo


def calls(lang: str, src: bytes, rel: str) -> list[tuple[str, bool]]:
    from tree_sitter_language_pack import get_parser

    from codefactory.analyzers.treewalk import walk

    out = walk(src, get_parser(lang), rel)
    return [(c[0], c[2]) for f in out["functions"] for c in f["calls"]]


@unittest.skipUnless(available(), "needs the language pack")
class LoopsTest(unittest.TestCase):
    def test_a_for_each_loop_evaluates_what_it_iterates_once(self):
        cases = {
            ("go", "m.go"): b"package m\nfunc F() {\n\tfor _, u := range db.Users() {\n\t\tsave(u)\n\t}\n}\n",
            ("java", "A.java"): b"class A { void f() { for (User u : repo.findAll()) { save(u); } } }\n",
            ("rust", "a.rs"): b"fn f() { for u in db.users() { save(u); } }\n",
            ("ruby", "a.rb"): b"def f\n  for u in User.all\n    save(u)\n  end\nend\n",
            ("php", "a.php"): b"<?php function f() { foreach ($repo->all() as $u) { save($u); } }\n",
            ("kotlin", "a.kt"): b"fun f() { for (u in repo.findAll()) { save(u) } }\n",
            ("csharp", "A.cs"): b"class A { void F() { foreach (var u in repo.All()) { Save(u); } } }\n",
        }
        for (lang, rel), src in cases.items():
            got = dict(calls(lang, src, rel))
            once = next(n for n in got if n.lower() in ("users", "findall", "all"))
            self.assertFalse(got[once], (lang, got))  # the iterable: once
            self.assertTrue(got["save" if "save" in got else "Save"], (lang, got))  # the body: per item

    def test_a_while_condition_and_a_c_style_condition_run_per_iteration(self):
        got = calls("go", b"package m\nfunc F() {\n\tfor i := 0; i < n(); i++ { x() }\n\tfor more() { y() }\n}\n", "m.go")
        self.assertEqual(got, [("n", True), ("x", True), ("more", True), ("y", True)])
        self.assertEqual(calls("java", b"class A { void f() { while (next()) { z(); } } }\n", "A.java"),
                         [("next", True), ("z", True)])  # fmt: skip

    def test_only_the_block_given_to_an_iteration_method_runs_per_item(self):
        src = b"def ids\n  filter_by_capacity(agents).map(&:user_id)\nend\ndef names\n  agents.map { |a| User.find(a.id) }\nend\n"
        got = calls("ruby", src, "app/inbox.rb")  # chatwoot: filter_by_capacity runs once, then .map over its result
        self.assertIn(("filter_by_capacity", False), got)
        self.assertIn(("find", True), got)


class ContainersTest(unittest.TestCase):
    def root_images(self, files):
        return sorted(e.file for e in scan_config(repo(files))["docker_root"].hits)

    def test_uwsgi_and_su_switch_user_at_run_time(self):
        files = {
            "uwsgi/Dockerfile": 'FROM python:3.12\nCOPY . /app\nCMD ["./bootstrap.sh"]\n',
            "uwsgi/bootstrap.sh": "#!/bin/sh\nexec uwsgi --http :9090 uwsgi.ini\n",
            "uwsgi/uwsgi.ini": "[uwsgi]\nmodule = app.wsgi\nuid = www-data\n",
            "su/Dockerfile": 'FROM alpine:3.20\nCOPY entrypoint.sh /\nENTRYPOINT ["/entrypoint.sh"]\n',
            "su/entrypoint.sh": '#!/bin/sh\nchown -R app /data\nexec su $USER -c "/app/server"\n',
            "build-su/Dockerfile": 'FROM postgres:16\nRUN su postgres -c "initdb"\nCMD ["/app"]\n',  # (build time)
            "rootini/Dockerfile": 'FROM python:3.12\nCMD ["uwsgi", "app.ini"]\n',
            "rootini/app.ini": "[uwsgi]\nuid = root\n",
        }  # fmt: skip
        self.assertEqual(self.root_images(files), ["build-su/Dockerfile", "rootini/Dockerfile"])

    def test_a_stage_built_on_a_development_image(self):
        files = {"docker/vite.Dockerfile": "FROM chatwoot:development\nCMD bin/vite dev\n",
                 "docker/Dockerfile": "FROM ruby:3.4-alpine\nCMD bundle exec rails s\n"}  # fmt: skip
        self.assertEqual(self.root_images(files), ["docker/Dockerfile"])


if __name__ == "__main__":
    unittest.main()
