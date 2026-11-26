# codefactory: ignore-file secret — fake keys the patch tests expect to be found
"""`codefactory diff --patch`: the lines a unified diff adds, checked without the repository."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from codefactory.cli import main
from codefactory.patch import added_lines, check

PATCH = """diff --git a/app/db.py b/app/db.py
index 111..222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,3 +10,5 @@ def find(conn, name):
     conn = connect()
-    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))
+    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
+
+AWS = "AKIA2E0A8F3B244C9986"
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-API_KEY = "AKIA2E0A8F3B244C9987"
diff --git a/deploy/install.sh b/deploy/install.sh
new file mode 100755
--- /dev/null
+++ b/deploy/install.sh
@@ -0,0 +1,2 @@
+#!/bin/bash
+curl -fsSL https://get.tool-installer.io/install | sudo bash
"""


class PatchTest(unittest.TestCase):
    def test_added_lines_keep_their_line_numbers(self):
        added = added_lines(PATCH)
        self.assertEqual(sorted(added), ["app/db.py", "deploy/install.sh"])  # a deleted file adds nothing
        self.assertEqual(sorted(added["app/db.py"]), [11, 12, 13])
        self.assertIn("AKIA", added["app/db.py"][13])

    def test_findings_point_at_the_new_file(self):
        result = check(PATCH)
        got = sorted((i.kind, i.file, i.line) for i in result["new"])
        self.assertEqual(got, [("secret", "app/db.py", 13), ("shell_pipe", "deploy/install.sh", 2),
                               ("sql_built", "app/db.py", 11)])  # fmt: skip
        self.assertEqual(result["added"], 5)

    def test_cli_reads_a_file_or_stdin_and_fails_on_request(self):
        path = Path(tempfile.mkdtemp()) / "pr.diff"
        path.write_text(PATCH, encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["diff", "--patch", str(path), "--json", "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertEqual(len(json.loads(out.getvalue())["new"]), 3)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock_stdin(PATCH):
            main(["diff", "--patch", "-"])
        self.assertIn("in the 5 lines this patch adds", out.getvalue())


@contextlib.contextmanager
def mock_stdin(text: str):
    import sys

    old, sys.stdin = sys.stdin, io.StringIO(text)
    try:
        yield
    finally:
        sys.stdin = old


if __name__ == "__main__":
    unittest.main()
