"""The graph cache is reused only while nothing that shapes the graph changed: any analyzed file (every language, not
just Python and TypeScript, which was a bug), the settings, and which parsers are installed (also a bug: installing the
language pack kept the graph that left those languages out)."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from codefactory.cache import fingerprint
from codefactory.config import DEFAULT_IGNORE


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        for name in ("app.py", "server.go", "Main.kt", "View.swift", "lib.rs", "Model.java", "users.rb", "README.md"):
            (self.root / name).write_text("x\n", encoding="utf-8")

    def changed(self, name: str) -> bool:
        before = fingerprint(self.root, DEFAULT_IGNORE)
        path = self.root / name
        path.write_text(path.read_text(encoding="utf-8") + "y\n", encoding="utf-8")
        later = time.time() + 5
        os.utime(path, (later, later))
        return fingerprint(self.root, DEFAULT_IGNORE) != before

    def test_every_analyzed_language_invalidates(self):
        for name in ("app.py", "server.go", "Main.kt", "View.swift", "lib.rs", "Model.java", "users.rb"):
            with self.subTest(name=name):
                self.assertTrue(self.changed(name))
        self.assertFalse(self.changed("README.md"))  # nothing analyzes it into the graph

    def test_installing_a_parser_invalidates(self):
        before = fingerprint(self.root, DEFAULT_IGNORE)
        with mock.patch("codefactory.analyzers.generic.available", return_value=False):
            without_pack = fingerprint(self.root, DEFAULT_IGNORE)
        with mock.patch("codefactory.analyzers.generic.available", return_value=True):
            with_pack = fingerprint(self.root, DEFAULT_IGNORE)
        self.assertNotEqual(without_pack, with_pack)
        self.assertIn(before, (without_pack, with_pack))


if __name__ == "__main__":
    unittest.main()
