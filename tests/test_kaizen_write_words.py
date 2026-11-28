"""A loop's call is a write when the call says so: SQL text, or the verb itself (round 9, kestra). `getInputStream()`
held "put" and was called a write, on every loop that reached it (17 wrong "writes inside loops")."""

import unittest

from codefactory.efficiency import kind_of


class WriteWordsTest(unittest.TestCase):
    def test_reads_whose_names_hold_a_write_word(self):
        for sink in ("connection.getInputStream()", "stream.readAllBytes()", "offset.read"):
            self.assertNotEqual("write", kind_of(sink), sink)

    def test_writes_still_writes(self):
        for sink in ('cursor.execute("INSERT INTO t VALUES (1)")', 'db.query("update users set x = 1")', "redis.set",
                     "repo.saveAll", "session.add_all", "conn.commit",
                     "Issue.objects.bulk_update", "conn.WriteMessage", "Model.objects.bulk_create"):  # fmt: skip
            self.assertEqual("write", kind_of(sink), sink)


if __name__ == "__main__":
    unittest.main()
