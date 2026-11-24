"""`codefactory accept`: record that a finding is intended, with the reason, in factory.toml.

A comment next to the code (`codefactory: ignore <kind> — why`) is the first choice, because the reason sits where
the next reader looks. `accept` is for when editing the code isn't wanted (generated code, a finding in a file you
don't own, a quick triage pass), and for review findings: it appends a [[silence]] rule that every command honours.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .sarif import RULES


def known_kinds() -> set[str]:
    return set(RULES)  # every graph and review finding has a SARIF rule


def rules_for_task(task: dict, graph: dict) -> list[tuple[str, str]]:
    """(kind, where) for every finding behind a plan task."""
    fn = {f["id"]: f for f in graph["functions"]}
    out = []
    for i in task["flags"]:
        flag = graph["flags"][i]
        f = fn.get(flag["target"])
        where = f"{f['file']}::{f['qualname']}" if f and f["kind"] != "module" else (f["file"] if f else flag["target"])
        out.append((flag["kind"], where))
    return sorted(set(out))


def normalize_where(where: str) -> str:
    """`src/a.py:42` -> `src/a.py` (a line moves; the file or function doesn't). Backslashes become slashes."""
    where = where.replace("\\", "/")
    return re.sub(r":\d+$", "", where)


def append_rules(root: Path, rules: list[tuple[str, str]], reason: str) -> Path:
    path = root / "factory.toml"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    blocks = []
    for kind, where in rules:
        # JSON strings are valid TOML basic strings (same escapes), so quoting can't break the file
        blocks.append(f"[[silence]]\nkind = {json.dumps(kind)}\nwhere = {json.dumps(where)}\nreason = {json.dumps(reason)}\n")
    sep = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
    path.write_text(text + sep + "\n".join(blocks), encoding="utf-8")
    return path
