"""Hotspots from git history: complex code changed often, files that change together, code only one person changes."""

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from codefactory import hotspots
from codefactory.cli import build

BUSY = "def busy(x):\n" + "".join(f"    if x == {i}:\n        return {i}\n" for i in range(12)) + "    return -1\n"


class History:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        self.git("init", "-q", "-b", "main")
        self.n = 0

    def git(self, *args, who="Ana", email="ana@example.invalid", when=None):
        env = {**os.environ, "GIT_AUTHOR_NAME": who, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": who,
               "GIT_COMMITTER_EMAIL": email}  # fmt: skip
        if when:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
        subprocess.run(["git", "-C", str(self.root), *args], check=True, env=env, capture_output=True)

    def commit(self, files: dict[str, str], who="Ana", days_ago=1):
        for name, text in files.items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text, encoding="utf-8")
        self.n += 1
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - days_ago * 86400))
        self.git("add", ".")
        self.git("commit", "-qm", f"change {self.n}", who=who, email=f"{who.lower()}@example.invalid", when=when)


class HotspotsTest(unittest.TestCase):
    def test_hotspots_coupling_and_owners(self):
        h = History()
        h.commit({"app/busy.py": BUSY, "app/calm.py": BUSY.replace("busy", "calm"), "app/small.py": "def s():\n    return 1\n",
                  "app/schema.py": "FIELDS = 1\n" * 20, "web/client.js": "export const f = 1;\n" * 20}, days_ago=200)  # fmt: skip
        for i in range(8):  # busy.py: complex and changed all the time, mostly by Ana
            who = "Ana" if i < 7 else "Bo"
            h.commit({"app/busy.py": BUSY + f"\nVERSION = {i}\n"}, who=who, days_ago=100 - i * 10)
        for i in range(5):  # schema.py and client.js always change together, and neither imports the other
            h.commit({"app/schema.py": "FIELDS = 1\n" * 20 + f"X = {i}\n", "web/client.js": "export const f = 1;\n" * 20
                      + f"export const x = {i};\n"}, who="Cy", days_ago=60 - i)  # fmt: skip
        for i in range(6):  # a third and fourth person, so knowledge is measured; and a bot that doesn't count
            h.commit({"app/small.py": f"def s():\n    return {i}\n"}, who="Di" if i % 2 else "Ed", days_ago=30 - i)
        h.commit({"app/calm.py": BUSY.replace("busy", "calm") + "\n# bump\n"}, who="dependabot[bot]", days_ago=5)

        s = hotspots.analyze(h.root, build(h.root, cache=False).to_dict())
        self.assertEqual(s.hot[0].path, "app/busy.py")  # complex and changed most
        self.assertNotIn("app/calm.py", [x.path for x in s.hot])  # just as complex, but barely changed
        self.assertEqual(s.hot[0].commits, 9)
        pair = next(c for c in s.coupled if {c.a, c.b} == {"app/schema.py", "web/client.js"})
        self.assertFalse(pair.linked)
        self.assertEqual(pair.together, 6)
        self.assertEqual(s.owners[0][:2], ("app/busy.py", "ana"))
        self.assertNotIn("dependabotbot", s.history.people)
        text = "\n".join(hotspots.markdown(s))
        self.assertIn("Front-end and back-end files move together", text)

    def test_no_history(self):
        root = Path(tempfile.mkdtemp())
        (root / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
        s = hotspots.analyze(root, build(root, cache=False).to_dict())
        self.assertEqual(s.hot, [])
        self.assertIn("not a git repository", "\n".join(hotspots.markdown(s)))

    def test_sweeping_commits_dont_count(self):
        h = History()
        files = {f"m{i}.py": f"def f{i}():\n    return {i}\n" for i in range(60)}
        h.commit(files)
        h.commit({k: v + "\n" for k, v in files.items()})  # a 60-file reformat
        self.assertEqual(hotspots.read(h.root).commits, 0)


if __name__ == "__main__":
    unittest.main()
