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

    def test_a_published_framework_is_a_library_not_the_service_its_views_make(self):  # Django, from its review
        files = {
            "pyproject.toml": '[project]\nname = "framework"\nclassifiers = [\n'
            '  "Topic :: Software Development :: Libraries :: Application Frameworks",\n]\n',
            "framework/views.py": """
                from flask import Flask
                app = Flask(__name__)

                @app.get("/i18n/setlang")
                def set_language():
                    return "ok"
            """,
        }
        p = profile(files)
        self.assertEqual(p.kind, "library")
        self.assertIn("web service", p.also)
        self.assertEqual(p.deployment, "user's machine")
        files["Dockerfile"] = "FROM python:3.13\n"  # deployed after all: then it's the service
        self.assertEqual(profile(files).kind, "web service")

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


class SmallAndStaticTest(unittest.TestCase):
    """From running on a set of personal repositories: Streamlit apps read as tools or pipelines, static sites as
    unknown, and a 400-line script was told its lack of CI is High."""

    def test_streamlit_app_is_a_web_app_reachable_on_the_lan(self):
        p = profile({"requirements.txt": "streamlit>=1.20\npandas\n",
                     "app.py": "import streamlit as st\nimport pandas as pd\n\nst.title('Lifts')\n"})  # fmt: skip
        self.assertEqual((p.kind, p.deployment, p.users), ("web app", "LAN server", "no sign-in"))
        self.assertIn("Streamlit", p.kind_evidence[0])
        g = profile({"app.py": "import gradio as gr\n\ngr.Interface(fn=len, inputs='text', outputs='text').launch()\n"})
        self.assertEqual((g.kind, g.deployment), ("web app", "local server"))  # no manifest: the import says it

    def test_static_website(self):
        p = profile({"index.html": "<html><body>hi</body></html>\n", "style.css": "body{}\n", ".nojekyll": ""})
        self.assertEqual((p.kind, p.deployment), ("static website", "static hosting"))
        self.assertIn(".nojekyll", p.kind_evidence[0])

    def test_small_projects_and_static_sites_rank_process_findings_lower(self):
        def ranked(files):
            root = repo(files)
            r = Review(build(root, cache=False).to_dict(), root)
            r.run()
            return {f.title: f.severity for f in r.findings if f.title.startswith("No ")}

        small = ranked({"requirements.txt": "streamlit\n", "app.py": "import streamlit as st\n\nst.write('hi')\n"})
        self.assertEqual((small["No continuous integration"], small["No automated tests"]), ("Low", "Medium"))
        static = ranked({"index.html": "<html></html>\n"})
        self.assertEqual((static["No continuous integration"], static["No automated tests"]), ("Low", "Low"))
        big = ranked({"requirements.txt": "streamlit\n", "app.py": "import streamlit as st\n" + "x = 1\n" * 2500})
        self.assertEqual(big["No continuous integration"], "High")  # big enough to be someone's codebase
        deployed = ranked({"requirements.txt": "flask\n", "Procfile": "web: gunicorn app:app\n",
                           "app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.post('/x')\ndef x():\n"
                                     "    return 'ok'\n"})  # fmt: skip
        self.assertEqual(deployed["No continuous integration"], "High")  # others depend on it


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
