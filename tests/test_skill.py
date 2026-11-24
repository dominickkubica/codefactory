"""The Claude Code skill and session hook keep codefactory current in a repository."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from codefactory import __version__, skill
from codefactory.cli import main


class SkillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_skill_is_stamped_after_front_matter(self):
        text = skill.install_skill(self.repo).read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\nname: codefactory"))
        self.assertIn(f"<!-- codefactory skill {__version__} -->", text)

    def test_refresh_rewrites_only_an_older_skill(self):
        self.assertFalse(skill.refresh_skill(self.repo))  # no skill: nothing written
        self.assertFalse(skill.skill_path(self.repo).exists())
        skill.install_skill(self.repo)
        self.assertFalse(skill.refresh_skill(self.repo))  # current: left alone
        path = skill.skill_path(self.repo)
        path.write_text(path.read_text(encoding="utf-8").replace(__version__, "0.0.1"), encoding="utf-8")
        self.assertTrue(skill.refresh_skill(self.repo))
        self.assertIn(f"skill {__version__} -->", path.read_text(encoding="utf-8"))

    def test_any_command_refreshes_a_stale_skill(self):
        path = skill.skill_path(self.repo)
        path.parent.mkdir(parents=True)
        path.write_text("---\nname: codefactory\n---\nold instructions\n", encoding="utf-8")
        (self.repo / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            main(["flags", str(self.repo), "--no-cache"])
        self.assertIn(f"skill {__version__} -->", path.read_text(encoding="utf-8"))

    def test_hook_merges_into_existing_settings_once(self):
        settings = self.repo / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps({"enabledPlugins": {"x": True}}), encoding="utf-8")
        skill.install_hook(self.repo)
        hook, _ = skill.install_hook(self.repo)  # twice: still one entry
        data = json.loads(settings.read_text(encoding="utf-8"))
        self.assertEqual(data["enabledPlugins"], {"x": True})
        self.assertEqual(len(data["hooks"]["SessionStart"]), 1)
        self.assertEqual(data["hooks"]["SessionStart"][0]["hooks"][0]["command"], skill.HOOK_COMMAND)
        self.assertNotIn(b"\r\n", hook.read_bytes())
        if os.name != "nt":
            self.assertTrue(os.access(hook, os.X_OK))

    def test_hook_refuses_invalid_settings(self):
        settings = self.repo / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text("{oops", encoding="utf-8")
        with self.assertRaises(ValueError):
            skill.install_hook(self.repo)

    @unittest.skipIf(os.name == "nt", "bash script")
    def test_hook_never_fails_a_session(self):
        hook, _ = skill.install_hook(self.repo)
        env = {**os.environ, "CLAUDE_PROJECT_DIR": str(self.repo), "HOME": self.tmp.name, "PATH": "/nonexistent"}
        proc = subprocess.run(["/bin/bash", str(hook)], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)  # no Python at all: quietly does nothing

    def test_update_reports_versions(self):
        ok = subprocess.CompletedProcess([], 0, stdout="9.9.9\n", stderr="")
        with mock.patch("subprocess.run", return_value=ok) as run:
            self.assertEqual(skill.update(), (__version__, "9.9.9"))
        self.assertIn(skill.SOURCE, run.call_args_list[0].args[0])
        bad = subprocess.CompletedProcess([], 1, stdout="", stderr="no network")
        with mock.patch("subprocess.run", return_value=bad), self.assertRaises(RuntimeError):
            skill.update()


if __name__ == "__main__":
    unittest.main()
