"""Whether test code quotes a route's URL: the quoted stretches that can hold a URL are found by an index of their
`/`-separated segments (every literal part of a route follows a slash), not by searching the whole test code once per
part and every stretch once per route (teable: 7.6 s of a review, now 0.15 s). The answer is the old one's, checked
here against it on written cases and on random ones."""

import random
import re
import unittest

from codefactory.review import _QuotedTexts

PARAM = re.compile(r"\{[^}]*\}|<[^>]*>|:\w+|\*\w*")
QUOTES = "\"'`"


def old_has_url(blob: str, path: str) -> bool:
    """The search before the index: every stretch holding the route's longest literal part."""
    params = [bool(PARAM.fullmatch(p)) for p in path.split("/")]
    parts = [r"[^/\"'`?]+" if param else re.escape(p) for p, param in zip(path.split("/"), params, strict=True)]
    url = re.compile(r"[\"'`][^\"'`\s]*" + "/".join(parts) + r"/?(?:\?[^\"'`]*)?[\"'`]")
    if re.search(r"[\"'`]", path):
        return bool(url.search(blob))
    literal = [p for p, param in zip(path.split("/"), params, strict=True) if not param]
    if any(p not in blob for p in literal):
        return False
    key = max(literal, key=len, default="") or ("/" if "/" in path else "")
    texts = list(dict.fromkeys(re.split(r"[\"'`]", blob)[1:-1]))
    return bool(url.search("".join(f'"{t}"' for t in texts if key in t)))


BLOB = """
client.get("/api/users/42?expand=1")
fetch(`https://host.test/api/v2/tables/abc/records`)
post('/login/')
const note = "api users are /not/ a url here"
other.get("/api/userz")
reverse('x') + "/files/"
"""


class QuotedUrlTest(unittest.TestCase):
    def test_routes_quoted_in_tests(self):
        q = _QuotedTexts(BLOB)
        for path in ["/api/users/{id}", "/api/v2/tables/:table/records", "/login", "/files"]:
            self.assertTrue(q.has_url(path), path)

    def test_routes_not_quoted(self):
        q = _QuotedTexts(BLOB)
        # (/not/ is a segment, but not with /api/users around it; userz isn't users; tables needs /records after)
        for path in ["/api/users/{id}/posts", "/not/a", "/api/tables/x", "/users", "/logout"]:
            self.assertFalse(q.has_url(path), path)

    def test_same_answers_as_the_search_it_replaced(self):
        for path in ["/api/users/{id}", "/login", "/not", "/api/userz", "api/users", "/{id}", "/x?y", "/", "/files"]:
            self.assertEqual(old_has_url(BLOB, path), _QuotedTexts(BLOB).has_url(path), path)
        rnd = random.Random(7)
        words = ["api", "v1", "users", "u", "42", "files", "a?b", "x"]
        for _ in range(300):
            stretches = ["/".join(rnd.choice(words + ["", "{id}"]) for _ in range(rnd.randint(1, 4))) for _ in range(6)]
            pieces = []
            for s in stretches:
                open_, close = rnd.choice(QUOTES), rnd.choice(QUOTES)
                lead, scheme, tail = rnd.choice(["", "x", " "]), rnd.choice(["", "http://h"]), rnd.choice(["", "?q=1", "/"])
                pieces.append(lead + open_ + scheme + s + tail + close)
            blob = " ".join(pieces)
            path = rnd.choice(["/", ""]) + "/".join(rnd.choice(words + ["{id}", ":k"]) for _ in range(rnd.randint(1, 3)))
            q = _QuotedTexts(blob)
            self.assertEqual(old_has_url(blob, path), q.has_url(path), (blob, path))


if __name__ == "__main__":
    unittest.main()
