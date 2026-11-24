"""Silencing issues that are intended, so the list stays worth reading.

In code, on the function's line, the flagged line, or the line above either (any comment style):
    // codefactory: ignore io_in_loop — one query per table, there are 7
    # codefactory: ignore unused, test_only: called by the router by name
    // codefactory: ignore — everything on this function
Anywhere in a file, for the whole file:
    // codefactory: ignore-file duplicate — generated code
In factory.toml:
    [[silence]]
    kind = "io_in_loop"            # or "*" (the default)
    where = "src/db/backup.ts"     # a file or file::function glob
    reason = "bounded by the number of tables"

Silenced issues leave the list but stay in the graph (Graph.silenced) with their reason, so nothing hides quietly.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path

from .config import Config
from .graph import Graph

MARK = re.compile(r"codefactory:\s*ignore(-file)?\b([^\n]*)", re.I)
KIND_WORD = re.compile(r"[a-z_]+")


def _parse(rest: str) -> tuple[set[str], str]:
    """'io_in_loop, unused — reason' -> ({io_in_loop, unused}, 'reason'). No kinds = every kind."""
    m = re.match(r"\s*([a-z_,\s]*?)\s*(?:[—–:]|\s-\s|$)(.*)", rest, re.I)
    kinds_part, reason = (m.group(1), m.group(2).strip()) if m else ("", rest.strip())
    kinds = {k.lower() for k in KIND_WORD.findall(kinds_part)} - {"all"}
    return kinds, reason.strip(" -—–:")


class _Sources:
    def __init__(self, root: Path):
        self.root, self.cache, self.rules = root, {}, {}

    def lines(self, file: str) -> list[str]:
        """The file's lines, or none when it has no codefactory comment at all (most files: nothing to look up)."""
        if file not in self.cache:
            try:
                text = (self.root / file).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            self.cache[file] = text.splitlines() if MARK.search(text) else []
        return self.cache[file]

    def file_rules(self, file: str) -> list[tuple[set[str], str]]:
        if file not in self.rules:
            self.rules[file] = [_parse(m.group(2)) for line in self.lines(file) if (m := MARK.search(line)) and m.group(1)]
        return self.rules[file]


def apply_suppressions(g: Graph, root: Path, cfg: Config) -> None:
    src = _Sources(root)
    by_id = {fn.id: fn for fn in g.functions}
    keep = []
    for f in g.flags:
        fn = by_id.get(f.target)
        file = fn.file if fn else f.target
        reason = _match(f, fn, file, src, cfg)
        if reason is None:
            keep.append(f)
        else:
            f.reason = reason or "marked as intended"
            g.silenced.append(f)
    g.flags = keep


def _match(f, fn, file: str, src: _Sources, cfg: Config) -> str | None:
    lines = src.lines(file)
    spots = {f.line, f.line - 1}
    if fn and fn.kind != "module":
        spots |= {fn.line, fn.line - 1}
    for ln in sorted(spots):
        if 1 <= ln <= len(lines) and (m := MARK.search(lines[ln - 1])) and not m.group(1):
            kinds, reason = _parse(m.group(2))
            if not kinds or f.kind in kinds:
                return reason
    for kinds, reason in src.file_rules(file):
        if not kinds or f.kind in kinds:
            return reason
    target = f"{file}::{fn.qualname}" if fn and fn.kind != "module" else file
    for rule in cfg.silence:
        if rule["kind"] in ("*", f.kind) and (fnmatch(target, rule["where"]) or fnmatch(file, rule["where"])):
            return rule["reason"]
    return None
