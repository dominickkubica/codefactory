"""Who owns a file, from CODEOWNERS (GitHub's format; GitLab's is compatible for these rules), so every finding can be
routed to the team that has to act on it.

Rules are gitignore-style patterns followed by owners; the last matching rule wins, as on GitHub. Supported: `*`,
`**`, `?`, a leading `/` (anchored to the root), a trailing `/` (a folder and everything in it), and a pattern without
a slash matching at any depth.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")


def _regex(pattern: str) -> re.Pattern:
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    p = pattern.strip("/")
    folder = pattern.endswith("/")
    out = ""
    i = 0
    while i < len(p):
        if p.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif p.startswith("**", i):
            out += ".*"
            i += 2
        elif p[i] == "*":
            out += "[^/]*"
            i += 1
        elif p[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(p[i])
            i += 1
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "/.*" if folder else "(?:/.*)?"
    return re.compile(f"^{prefix}{out}{suffix}$")


class Owners:
    def __init__(self, rules: list[tuple[re.Pattern, list[str]]], source: str):
        self.rules, self.source = rules, source

    def of(self, file: str) -> list[str]:
        return self._of(file.replace("\\", "/"))

    @lru_cache(maxsize=65536)  # noqa: B019 (one Owners per run; files repeat across findings)
    def _of(self, file: str) -> list[str]:
        for regex, owners in reversed(self.rules):
            if regex.match(file):
                return owners
        return []


def load(root: Path) -> Owners | None:
    for loc in LOCATIONS:
        path = root / loc
        if path.is_file():
            rules = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("["):  # comments; GitLab sections
                    continue
                pattern, *owners = line.split()
                rules.append((_regex(pattern), owners))
            return Owners(rules, loc)
    return None
