"""`codefactory diff --patch FILE`: check the lines a unified diff adds, without the repository.

For a patch from a pull request (`gh pr diff 42 > pr.diff`, `git diff main > change.diff`), a mailing-list patch, or
an AI agent's proposed change: every line check (credentials, SQL built from strings, shell, eval, raw HTML, weak
crypto, personal data in logs, Swift crashes, and the shell, YAML, HTML and config checks) runs on the added lines.
Graph findings (loops, copies, unused code) need the whole repository, so they're left to `codefactory diff --base`.

The added lines are written to a temporary folder at their real line numbers, so each finding points at the line in
the new file.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from .diff import Item

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(text: str) -> dict[str, dict[int, str]]:
    """file -> {line number in the new file: text} for every added line."""
    out: dict[str, dict[int, str]] = {}
    file, line = None, 0
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            name = raw[4:].strip().split("\t")[0]
            file = None if name == "/dev/null" else re.sub(r"^[ab]/", "", name)
            if file:
                out.setdefault(file, {})
        elif raw.startswith("--- ") or raw.startswith("diff ") or raw.startswith("index "):
            continue
        elif m := HUNK.match(raw):
            line = int(m.group(1))
        elif file is None:
            continue
        elif raw.startswith("+"):
            out[file][line] = raw[1:]
            line += 1
        elif raw.startswith(" ") or raw == "":
            line += 1
        # "-" lines are gone from the new file; "\ No newline" is a marker
    return {f: lines for f, lines in out.items() if lines}


def check(text: str) -> dict:
    from .apple import scan as apple_scan
    from .checks import _scan
    from .infra import scan as infra_scan
    from .privacy import scan as privacy_scan
    from .sarif import RULES

    added = added_lines(text)
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for file, lines in added.items():
            path = root / file
            if not path.resolve().is_relative_to(root.resolve()):
                continue  # a path that climbs out of the folder
            path.parent.mkdir(parents=True, exist_ok=True)
            body = [lines.get(n, "") for n in range(1, max(lines) + 1)]
            path.write_text("\n".join(body) + "\n", encoding="utf-8")
        files = sorted(added)
        checks = _scan(root, files)
        checks.update(privacy_scan(root, files))
        checks.update(apple_scan(root, files))
        checks.update(infra_scan(root))
    items = []
    for kind, c in checks.items():
        if kind not in RULES:
            continue
        for e in c.hits:
            if e.line in added.get(e.file, {}):
                items.append(Item(f"{kind}|{e.file}|{e.text}", kind, RULES[kind][3], e.file, e.line, "",
                                  f"{RULES[kind][1]}: {e.text}"))  # fmt: skip
    rank = {"high": 0, "warn": 1, "info": 2}
    items.sort(key=lambda i: (rank.get(i.severity, 3), i.file, i.line))
    return {"base": "the patch", "changed": files, "new": items, "fixed": [], "patch": True,
            "added": sum(len(v) for v in added.values())}  # fmt: skip
