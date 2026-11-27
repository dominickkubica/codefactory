"""Untested-code lessons: what tests run without calling it, and code this finding isn't about."""

import unittest

from codefactory.cli import build
from codefactory.review import Review
from tests.test_large_repo import repo


def untested(files):
    root = repo(files)
    r = Review(build(root, cache=False).to_dict(), root)
    r.run()
    f = next((f for f in r.findings if f.title.startswith("Important code no test reaches")), None)
    return " ".join(f.evidence) if f else ""


class UntestedTest(unittest.TestCase):
    def test_commands_tests_run_migrations_and_build_config(self):
        handle = "class Command(BaseCommand):\n    def handle(self, *args, **options):\n        Thing.objects.filter(old=True).delete()\n"
        found = untested({
            "app/management/commands/purge_things.py": handle,
            "app/management/commands/other_job.py": handle,
            "db/migrate/20260101_clean.py": "def up():\n    Thing.objects.filter(bad=True).delete()\n",
            "web/vite.config.ts": "import { readFileSync } from 'fs';\nexport const csp = () => readFileSync('a.json');\n",
            "tests/test_commands.py": "from django.core.management import call_command\n\n\ndef test_purge():\n"
                                      "    call_command('purge_things')\n",
        })  # fmt: skip
        self.assertIn("other_job.py", found)
        for name in ("purge_things.py", "20260101_clean.py", "vite.config.ts"):
            self.assertNotIn(name, found)


if __name__ == "__main__":
    unittest.main()
