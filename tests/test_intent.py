# codefactory: ignore-file swallowed — samples of the patterns
"""Code that looks risky to a pattern but shows its intent isn't reported; look-alikes without that intent still are.
Every case came from a false positive on a real app."""

import tempfile
import unittest
from pathlib import Path

from codefactory.checks import scan_repo, scan_sources
from codefactory.intent import swallow_intent


class SwallowTest(unittest.TestCase):
    def test_deliberate(self):
        for line in [
            "tail = run.catch(() => {}); // a failed transaction doesn't block the ones after it",
            "await Notifications.dismissNotificationAsync(ID).catch(() => {});",
            "await SecureStore.deleteItemAsync(KEY).catch(() => {});",
            "await w.cancelAlerts().catch(() => {});",
            "const r = await db.getFirstAsync('SELECT 1').catch(() => null);",
            "except OSError: pass  # already gone",
        ]:
            self.assertIsNotNone(swallow_intent(line, "x = 1"), line)
        self.assertEqual(swallow_intent("load().catch(() => {});", "// the cache refills on the next start"), "explained")

    def test_still_reported(self):
        for line in [
            "save.current(value).catch(() => {});",
            "await deleteAccount(db).catch(() => {});",  # deleting the user's records is not cleanup
            "useEffect(() => { if (on) loadPro(db).catch(() => {}); }, [db]);",  # the `=` of `=>` isn't an assignment
            "getWeek(db).then(setData).catch(() => {});",
        ]:
            self.assertIsNone(swallow_intent(line, "x = 1"), line)


class SqlTest(unittest.TestCase):
    def scan(self, code: str) -> list:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "db.ts").write_text(code, encoding="utf-8")
            return scan_sources(Path(d), ["db.ts"])["sql_built"].hits

    def test_names_from_a_fixed_list_or_checked_are_safe(self):
        code = """export async function restore(db, rows, version) {
  const order = Object.keys(TABLES);
  for (const table of [...order].reverse()) {
    await db.runAsync(`DELETE FROM ${table}`);
  }
  for (const t of names) {
    if (known.has(t)) await db.runAsync(`DELETE FROM ${t} WHERE id = ?`, [1]);
  }
  const cols = Object.keys(rows[0]).filter((c) => allowed.has(c));
  await db.runAsync(`INSERT INTO x (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`, []);
  await db.execAsync(`PRAGMA user_version = ${version + 1}`);
  await db.execAsync(`PRAGMA user_version = ${Math.floor(version)}`);
  const out = { ...rows, exported_at: 1 };
}
"""
        self.assertEqual(self.scan(code), [])

    def test_unchecked_values_are_reported(self):
        code = """export async function find(db, name, table) {
  await db.getAllAsync(`SELECT * FROM foods WHERE name = '${name}'`);
  await db.runAsync(`DELETE FROM ${table}`);
}
"""
        self.assertEqual([h.line for h in self.scan(code)], [2, 3])


class RepoTest(unittest.TestCase):
    def ci(self, text: str) -> bool:
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".github" / "workflows").mkdir(parents=True)
            (Path(d) / ".github" / "workflows" / "ci.yml").write_text(text, encoding="utf-8")
            return scan_repo(Path(d))["ci_on_push"]

    def test_pull_request_only_ci(self):
        self.assertFalse(self.ci("on:\n  pull_request:\njobs: {}\n"))
        explained = "# Not on the push a merge makes: the PR already checked it, and minutes are limited.\non:\n  pull_request:\n"
        self.assertTrue(self.ci(explained))

    def test_wildcard_origin_isnt_a_plain_http_url(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.tsx").write_text('const a = ["https://*", "http://*"];\nconst b = "http://api.shop.com/x";\n')
            hits = scan_sources(Path(d), ["a.tsx"])["plain_http"].hits
        self.assertEqual([h.line for h in hits], [2])


if __name__ == "__main__":
    unittest.main()
