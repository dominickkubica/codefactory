"""The project profile: what kind of project, where it runs, who uses it, what it holds; and ranking findings for it."""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.cli import build
from codefactory.profile import code_only, detect
from codefactory.rerank import RULES, rerank
from codefactory.review import Finding, Review


def repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def profile(files: dict[str, str]):
    root = repo(files)
    return detect(root, build(root, cache=False).to_dict())


EXPO = {
    "package.json": json.dumps({"dependencies": {"expo": "54.0.0", "react-native": "0.81.0", "expo-sqlite": "16.0.0",
                                                 "@kingstinct/react-native-healthkit": "9.0.0"}}),
    "src/db.ts": "import * as SQLite from 'expo-sqlite';\nexport async function save(db, w) {\n"
                 "  await db.runAsync(`INSERT INTO workouts (name) VALUES ('${w}')`);\n}\n",
    "src/screen.tsx": "// heart_rate and calories in a comment don't count\nexport const s = 'workouts';\n",
}  # fmt: skip
API = {
    "pyproject.toml": '[project]\nname = "svc"\ndependencies = ["fastapi", "passlib"]\n',
    "app/main.py": """
        from fastapi import Depends, FastAPI
        from passlib.hash import bcrypt
        app = FastAPI()

        def current_user(): ...

        @app.get("/me")
        def me(user=Depends(current_user)):
            return user

        @app.post("/notes")
        def add_note(text: str, conn=None):
            conn.execute("INSERT INTO notes VALUES (?)", (text,))
        """,
    "Dockerfile": "FROM python:3.12-slim\nUSER app\n",
}
CLI = {
    "pyproject.toml": '[project]\nname = "tool"\n[project.scripts]\ntool = "tool.main:run"\n',
    "tool/main.py": "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
}
LIBRARY = {
    "package.json": json.dumps({"name": "leftpadder", "main": "index.js"}),
    "index.js": "module.exports = (s, n) => s.padStart(n);\n",
}


class DetectTest(unittest.TestCase):
    def test_local_first_mobile_app(self):
        p = profile(EXPO)
        self.assertEqual((p.kind, p.deployment, p.users), ("mobile app", "local-first", "single user"))
        self.assertIn("health and fitness", p.sensitive)
        self.assertTrue(any("healthkit" in e for e in p.sensitive["health and fitness"]))
        self.assertEqual(p.summary(), "a mobile app, local-first, single user, holding health and fitness data")

    def test_deployed_api_with_accounts(self):
        p = profile(API)
        self.assertEqual(p.kind, "web service")
        self.assertEqual(p.deployment, "deployed server")
        self.assertEqual(p.users, "multi-user")
        self.assertIn("accounts and passwords", p.sensitive)

    def test_cli_and_library(self):
        self.assertEqual(profile(CLI).kind, "command-line tool")
        self.assertEqual(profile(CLI).deployment, "user's machine")
        self.assertEqual(profile(LIBRARY).kind, "library")

    def test_jvm_manifests(self):
        android = {"app/build.gradle": "plugins { id 'com.android.application' }\n", "app/src/A.kt": "class A\n"}
        self.assertEqual(profile(android).kind, "mobile app")
        lib = {"pom.xml": "<project><artifactId>util</artifactId><packaging>jar</packaging></project>", "U.java": "class U {}\n"}
        self.assertEqual(profile(lib).kind, "library")

    def test_words_in_comments_and_strings_dont_count(self):
        self.assertEqual(code_only("a = 1  # heart_rate\nb = 'calories'\nc = d"), "a = 1  \nb = \nc = d")
        p = profile({"main.py": "# this tracks workouts and calories\nprint('workouts')\n"})
        self.assertNotIn("health and fitness", p.sensitive)
        p = profile({"a.py": "workouts = []\n", "b.py": "def calories(): ...\n"})  # words in code, in two files
        self.assertIn("health and fitness", p.sensitive)

    def test_factory_toml_corrects_it(self):
        p = profile({**EXPO, "factory.toml": '[profile]\nusers = "multi-user"\nsensitive = ["financial"]\n'})
        self.assertEqual(p.users, "multi-user")
        self.assertEqual(list(p.sensitive), ["financial"])
        self.assertTrue(any(c.startswith("users:") for c in p.corrected))
        with self.assertRaises(ValueError):
            profile({**EXPO, "factory.toml": '[profile]\nkind = "spaceship"\n'})


class RerankTest(unittest.TestCase):
    def test_review_ranks_for_the_project(self):
        root = repo(EXPO)
        r = Review(build(root, cache=False).to_dict(), root)
        r.run()
        sql = next(f for f in r.findings if f.title.startswith("SQL assembled"))
        self.assertEqual(sql.severity, "Low")
        self.assertEqual(sql.data["ranked"]["from"], "Medium")
        text = r.markdown()
        self.assertIn("## 2. Project profile", text)
        self.assertIn("Ranked Low for this project (default Medium)", text)

    def test_one_rule_per_finding_and_direction(self):
        p = profile(EXPO)
        f = Finding("Plain-HTTP URLs in code", "Low", "Security", ["`a.ts:1` x"], "", "", "S")
        changes = rerank([f], p)
        self.assertEqual((f.severity, len(changes)), ("Medium", 1))
        same = Finding("Plain-HTTP URLs in code", "Medium", "Security", [], "", "", "S")
        self.assertEqual(rerank([same], p), [])  # already there: nothing to say

    def test_every_rule_names_a_real_finding(self):
        import re
        from pathlib import Path as P

        source = (P(__file__).parent.parent / "codefactory" / "review.py").read_text(encoding="utf-8")
        for rule in RULES:  # a renamed finding would silently stop being ranked
            prefix = re.sub(r"\\\\|\^|\(\?:|\)|\|.*", "", rule.title).split("(")[0].strip()
            self.assertIn(prefix[:20], source, rule.title)


if __name__ == "__main__":
    unittest.main()
