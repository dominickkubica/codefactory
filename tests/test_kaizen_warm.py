"""While the type checker runs, a review's work that needs no graph is done ahead (warm.py): the source checks, the
data-flow pass's reading and parsing, the personal-data scan, the names the unused-code check looks for. The result is
the same as without it, and a file changed after it was read ahead is read again, never taken from what was read."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from codefactory import flags, jstaint, privacy
from codefactory.analyzers import analyze
from codefactory.checks import kept_on_disk
from codefactory.cli import build, load_graph
from codefactory.config import DEFAULT_IGNORE
from codefactory.export import audit
from codefactory.jstaint import available

APP = Path(__file__).parent / "fixtures" / "jstaintapp"
LOG = "export function signup(user: { email: string }) {\n  console.log('signed up', user.email);\n}\n"


def copy() -> Path:
    root = Path(tempfile.mkdtemp()) / "app"
    shutil.copytree(APP, root, ignore=shutil.ignore_patterns(".codefactory"))
    (root / "signup.ts").write_text(LOG, encoding="utf-8")
    return root.resolve()


def taint(root: Path) -> set:
    return {(f.target.split("::")[0], f.line, f.detail) for f in build(root, cache=False).flags if f.kind == "taint"}


@unittest.skipUnless(available(), "needs the language pack (tree-sitter)")
class WarmTest(unittest.TestCase):
    def test_the_review_is_the_same_with_the_head_start(self):
        root = copy()
        docs = []
        for review in (True, False):
            doc, _ = audit(load_graph(root, cache=False, review=review), root)
            docs.append(json.dumps(doc, sort_keys=True, default=str))
        self.assertEqual(docs[0], docs[1])

    def test_a_file_changed_after_it_was_read_ahead_is_read_again(self):
        root = copy()
        sources = kept_on_disk(root)
        before = taint(root)
        self.assertIn(("server.js", 13, "shell"), before)
        jstaint.prepare(root, [f for f in sources if Path(f).suffix in jstaint.EXT_LANG])
        privacy.prepare(root, sources)
        # then the files change: a flow and the personal data
        server = root / "server.js"
        lines = server.read_text(encoding="utf-8").splitlines(keepends=True)
        lines[12] = "  // (the call was here)\n"
        server.write_text("".join(lines), encoding="utf-8")
        (root / "signup.ts").write_text(LOG.replace("user.email", "'done'"), encoding="utf-8")
        self.assertEqual(before - {("server.js", 13, "shell")}, taint(root))
        self.assertFalse(privacy.scan(root, sources)["privacy_log"].hits)

    def test_a_name_quoted_after_the_files_were_read_ahead_is_seen(self):
        root = copy()
        g = analyze(root, list(DEFAULT_IGNORE))  # (no flags step: it would use what was read ahead itself)
        flags.prepare_mentions(root, kept_on_disk(root))
        self.assertNotIn("quotedLater", flags._READY[str(root)]["signup.ts"][1])
        (root / "signup.ts").write_text(LOG + "export const k = 'quotedLater';\n", encoding="utf-8")
        self.assertIn("quotedLater", flags._mentioned(g))

    def test_what_was_read_ahead_is_used_where_the_file_is_unchanged(self):
        root = copy()
        sources = kept_on_disk(root)
        plain = privacy.scan(root, sources)["privacy_log"].hits
        self.assertEqual([("signup.ts", 2)], [(e.file, e.line) for e in plain])
        privacy.prepare(root, sources)
        self.assertEqual(plain, privacy.scan(root, sources)["privacy_log"].hits)


if __name__ == "__main__":
    unittest.main()
