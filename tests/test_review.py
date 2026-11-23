"""codefactory review: findings, structure and the AI evidence pack, on a small project with planted problems."""
import io
import unittest
from contextlib import redirect_stdout

from codefactory.cli import build, main
from codefactory.review import Review
from tests.test_rules import project

SECRET = "Zq8vN3pL0aR7tY2uW5xC9bM4kD6fH1jS"  # codefactory: ignore secret — made up: matches the generic "key = long random string" rule only


class ReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = project({
            "requirements.txt": "requests\nflask==3.0.0\n",
            "app/config.py": f'API_KEY = "{SECRET}"\n',
            "app/db.py": """
                import sqlite3
                import subprocess

                import requests

                def find(conn, name):
                    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()

                def remove_all(conn, ids):
                    for i in ids:
                        conn.execute("DELETE FROM users WHERE id = ?", (i,))

                def backup(path):
                    subprocess.run(f"cp {path} /tmp/backup", shell=True)

                def ping():
                    try:
                        return requests.get("https://api.example-service.io/health")
                    except Exception:
                        pass

                def wipe(path):
                    import os
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    if path.endswith(".db"):
                        return True
                    return False
            """,
            "app/views.py": "from app.db import find, ping\n\ndef page(conn, name):\n    ping()\n    return find(conn, name)\n",
        })
        r = Review(build(cls.root).to_dict(), cls.root)
        r.run()
        cls.r = r
        cls.titles = {f.title: f for f in r.findings}

    def find(self, part):
        return next((f for t, f in self.titles.items() if part in t), None)

    def test_security(self):
        self.assertEqual(self.find("Credentials").severity, "Critical")
        self.assertIn("app/config.py:1", self.find("Credentials").evidence[0])
        sql = self.find("SQL assembled")
        self.assertIn("app/db.py:8", sql.evidence[0])
        self.assertIn("name", sql.evidence[0])
        self.assertEqual(self.find("Shell commands").severity, "High")

    def test_reliability_testing_delivery(self):
        self.assertIsNotNone(self.find("Network calls without a timeout"))
        self.assertEqual(self.find("No automated tests").severity, "High")
        self.assertEqual(self.find("No continuous integration").severity, "High")
        self.assertIsNotNone(self.find("Unpinned Python requirements"))
        self.assertIsNotNone(self.find("No README"))

    def test_report_structure_and_grade(self):
        text = self.r.markdown()
        for part in ("# Technical review:", "## 1. Executive summary", "**Overall health: At risk.**", "Top 5 actions",
                     "## 2. System map", "## 3. Findings", "### Critical", "### High", "## 4. What is working",
                     "## 5. Testing and release gaps", "## 6. Open questions", "## Review limits",
                     "api.example-service.io"):
            self.assertIn(part, text)
        self.assertNotIn("score", text.split("## 2.")[0].lower().replace("scores", ""))  # a grade, not a number

    def test_evidence_pack(self):
        text = self.r.markdown(for_ai=True)
        self.assertIn("## Evidence pack for an AI reviewer", text)
        self.assertIn("`app/db.py:23` wipe", text)  # deletes files, swallows the error, untested
        self.assertIn("os.remove(path)", text)

    def test_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["review", str(self.root), "--no-cache"]), 0)
        self.assertIn("## 3. Findings", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
