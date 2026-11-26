"""The ratchet: save today's issues as a baseline (commit it), then fail only on issues that weren't there. The backlog
can be worked down at any pace; nothing new slips in.

An issue's identity is its kind, file and function (not its line, which moves as code above it changes), counted:
two io_in_loop issues in one function stay two.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path

NAME = "codefactory-baseline.json"


def issue_key(graph: dict, flag: dict, fns: dict | None = None) -> str:
    fns = fns if fns is not None else {f["id"]: f for f in graph["functions"]}
    fn = fns.get(flag["target"])
    where = f"{fn['file']}::{fn['qualname']}" if fn else flag["target"]
    return f"{flag['kind']}|{where}"


def baseline_path(repo_or_file: Path) -> Path:
    return repo_or_file / NAME if repo_or_file.is_dir() else repo_or_file


def write_baseline(graph: dict, path: Path) -> int:
    fns = {f["id"]: f for f in graph["functions"]}
    counts = Counter(issue_key(graph, f, fns) for f in graph["flags"])
    from .paths import write_file

    doc = {"version": 1, "created": date.today().isoformat(), "issues": dict(sorted(counts.items()))}
    write_file(path, json.dumps(doc, indent=1) + "\n")
    return sum(counts.values())


def read_baseline(path: Path) -> Counter | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return Counter(data.get("issues", {}))


def compare(graph: dict, base: Counter) -> tuple[list[dict], Counter]:
    """(issues not in the baseline, baseline issues no longer found)."""
    fns = {f["id"]: f for f in graph["functions"]}
    left = Counter(base)
    new = []
    for f in graph["flags"]:
        k = issue_key(graph, f, fns)
        if left[k] > 0:
            left[k] -= 1
        else:
            new.append(f)
    return new, +left
