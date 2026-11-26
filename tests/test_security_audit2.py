"""The rest of the security audit of codefactory (0.20.3): findings 4, 7, 9, 10, 13-18 and the robustness items.
Each test attacks the way the audit described."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codefactory import config, deps, paths, skill
from codefactory.checks import scan_sources, source_files
from codefactory.cli import build, main
from codefactory.patch import check as check_patch
from codefactory.security import _auth

ROOT = Path(__file__).parent.parent
KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
NO_LINKS = os.name == "nt"  # creating symbolic links on Windows needs developer mode


class OutputFileTest(unittest.TestCase):
    @unittest.skipIf(NO_LINKS, "symbolic links")
    def test_outputs_are_never_written_through_a_link(self):  # finding 4
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            victim = Path(other) / "authorized_keys"
            victim.write_text("keep me\n", encoding="utf-8")
            link = Path(d) / "codefactory-comment.md"
            link.symlink_to(victim)
            with self.assertRaises(OSError):
                paths.write_file(link, "attacker text")
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                main(["review", d, "-o", str(link)])
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")

    def test_the_action_keeps_its_comment_outside_the_checkout(self):  # finding 4 and the fail-on gate
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertNotIn("cat codefactory-comment.md", action)
        self.assertIn('--comment "$RUNNER_TEMP/codefactory-comment.md"', action)
        result = action.split("- name: Result", 1)[1]
        self.assertIn("if: always()", result)
        self.assertIn('exit "${STATUS:-1}"', result)  # no result recorded: fail, never pass


@unittest.skipIf(NO_LINKS, "symbolic links")
class LinkOutTest(unittest.TestCase):
    def test_files_linking_outside_the_repository_are_not_read(self):  # findings 7 and 16
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as home:
            secret = Path(home) / "credentials"
            secret.write_text(f'aws = "{KEY}"\nrequests==2.0.0\n', encoding="utf-8")
            root = Path(d)
            (root / "config.py").symlink_to(secret)
            (root / "requirements.txt").symlink_to(secret)
            (root / "inside.py").write_text("x = 1\n", encoding="utf-8")
            (root / "alias.py").symlink_to(root / "inside.py")  # a link within the repository is fine
            files = source_files(root, build(root, cache=False).to_dict())
            self.assertNotIn("config.py", files)
            self.assertIn("alias.py", files)
            self.assertEqual(scan_sources(root, files)["secret"].hits, [])
            self.assertEqual(deps.packages(root), [])  # nothing from the link is sent to OSV


class PatchTest(unittest.TestCase):
    def test_a_patch_cant_make_it_read_files_outside_its_folder(self):  # finding 9
        with tempfile.TemporaryDirectory() as d:
            outside = Path(d) / "host.py"
            outside.write_text(f'key = "{KEY}"\n', encoding="utf-8")
            rel = os.path.relpath(outside, tempfile.gettempdir()).replace(os.sep, "/")
            patch = f"--- a/../../../..{tempfile.gettempdir()}/{rel}\n+++ b/../../../..{tempfile.gettempdir()}/{rel}\n@@ -0,0 +1 @@\n+x = 1\n"
            result = check_patch(patch)
            self.assertEqual(result["new"], [])
            self.assertEqual(result["changed"], [])


class ViewerTest(unittest.TestCase):
    def test_finding_kinds_are_escaped_in_the_page(self):  # finding 10
        js = (ROOT / "codefactory" / "viewer" / "factory.js").read_text(encoding="utf-8")
        self.assertIn('data-kind="${esc(k)}"', js)
        self.assertIn("${esc(KIND[k] || k)}", js)
        self.assertIn('"\'": "&#39;"', js)

    def test_query_names_and_rule_ids_are_plain_text(self):  # finding 10
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "factory.toml").write_text('[[queries]]\nname = "<img src=x onerror=alert(1)>"\nsql = "SELECT 1"\n')
            with self.assertRaisesRegex(ValueError, "Query name"):
                config.load_config(Path(d))


class WorkflowTest(unittest.TestCase):
    def test_ci_is_pinned_read_only_and_keeps_no_token(self):  # finding 13
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", ci)
        uses = [ln.split("uses:", 1)[1].strip() for ln in ci.splitlines() if "uses:" in ln]
        for u in uses:
            if u != "./":
                self.assertRegex(u, r"@[0-9a-f]{40} # v", u)
        self.assertEqual(ci.count("persist-credentials: false"), ci.count("actions/checkout@"))
        for ln in ci.splitlines():
            if "pip install" in ln:
                self.assertTrue("--require-hashes" in ln or "--no-build-isolation --no-deps ." in ln, ln)
        self.assertTrue((ROOT / ".github" / "dependabot.yml").is_file())

    def test_release_build_backend_is_hash_pinned(self):  # finding 14
        rel = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("--require-hashes --no-deps -r build-requirements.txt", rel)
        self.assertNotIn("python -m build\n", rel)
        self.assertEqual(rel.count("python -m build --no-isolation"), 2)
        reqs = (ROOT / "build-requirements.txt").read_text(encoding="utf-8")
        for name in ("build==", "setuptools==", "packaging==", "pyproject-hooks=="):
            self.assertIn("--hash=sha256:", reqs.split(name, 1)[1].split("==", 1)[0] + reqs.split(name, 1)[1][:200])

    def test_major_tag_only_moves_forward(self):  # finding 15
        rel = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        script = rel.split('major="${TAG%%.*}"', 1)[1].split("pypi:", 1)[0]
        self.assertIn("sort -V | tail -1", script)
        with tempfile.TemporaryDirectory() as d:  # the same shell logic, on real tags
            git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "x"], check=True)
            for tag in ("v0.19.4", "v0.20.2", "v0.19.5"):
                subprocess.run([*git, "tag", tag], check=True)
            newest = subprocess.run(f'git -C "{d}" tag -l "v0.*.*" | sort -V | tail -1', shell=True,
                                    capture_output=True, text=True).stdout.strip()  # fmt: skip
            self.assertEqual(newest, "v0.20.2")  # so pushing v0.19.5 leaves v0 alone


class RobustnessTest(unittest.TestCase):
    def test_odd_lockfiles_dont_crash_the_review(self):  # finding 17
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/x": "1.0.0"}}))
            self.assertEqual(deps.packages(Path(d)), [])

    def test_bad_osv_answers_are_network_errors(self):  # finding 17
        import http.client

        pkg = deps.Package("x", "1.0", "PyPI", "requirements.txt")
        for bad in (http.client.IncompleteRead(b"{"), None):
            with mock.patch("urllib.request.urlopen") as urlopen:
                if bad is not None:
                    urlopen.return_value.__enter__.return_value.read.side_effect = bad
                else:
                    urlopen.return_value.__enter__.return_value.read.return_value = b"[1, 2]"  # JSON, not an object
                with self.assertRaises((OSError, ValueError)):
                    deps.vulnerabilities([pkg])
        with mock.patch.object(deps, "_post", return_value={"results": [{"vulns": [{"id": "X-1"}, "junk", {}]}]}), \
             mock.patch.object(deps, "_get", return_value={"summary": 5, "affected": "junk"}):  # fmt: skip
            self.assertEqual([v.id for v in deps.vulnerabilities([pkg])], ["X-1"])
        answer = {"results": [{"vulns": [{"id": "X-1"}]}]}
        with mock.patch.object(deps, "_post", return_value=answer), self.assertRaises(OSError):
            deps.vulnerabilities([pkg], budget=-1)  # out of time before asking: says so

    def test_backtracking_rules_are_refused(self):  # finding 17
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "factory.toml").write_text('[[rule]]\nid = "slow"\npattern = "(a+)+$"\n')
            with self.assertRaisesRegex(ValueError, "repeated group"):
                config.load_config(Path(d))

    def test_a_failed_rollback_is_said_plainly(self):  # finding 18
        fail = subprocess.CompletedProcess([], 1, stdout="", stderr="offline")
        with mock.patch.object(skill, "drop_git_install", return_value=True), \
             mock.patch("subprocess.run", return_value=fail), self.assertRaises(RuntimeError) as err:  # fmt: skip
            skill.update()
        self.assertIn("isn't installed now", str(err.exception))

    def test_database_sessions_and_csrf_arent_authentication(self):
        for not_auth in ("Depends(get_db_session)", "app.use(session({ secret }))", "SessionMiddleware", "csrf_token"):
            self.assertIsNone(_auth(not_auth), not_auth)
        for auth in ("Depends(get_current_user)", "login_required", "verify_jwt", "app.use(requireAuth)"):
            self.assertIsNotNone(_auth(auth), auth)

    def test_the_fingerprint_is_taken_before_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            from codefactory import cli
            from codefactory.cache import load_cached

            real = cli.build

            def edit_while_analyzing(*args, **kwargs):
                g = real(*args, **kwargs)
                (root / "a.py").write_text("def g():\n    return 22\n", encoding="utf-8")  # changed mid-run
                return g

            with mock.patch("codefactory.paths.RACY_NS", 0), mock.patch.object(cli, "build", edit_while_analyzing):
                cli.load_graph(root)
            with mock.patch("codefactory.paths.RACY_NS", 0):
                self.assertIsNone(load_cached(root, []))  # the edit isn't cached as analyzed


if __name__ == "__main__":
    unittest.main()
