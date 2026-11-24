"""Custom pattern rules from factory.toml ([[rule]]): a team's own checks, without writing code.

    [[rule]]
    id = "no-raw-print"
    pattern = "\\\\bprint\\\\("
    files = ["src/**/*.py"]
    severity = "info"
    message = "Use the logger: print output is lost in production"

Each match becomes a `custom` finding on the function that holds it, so silencing, the baseline, SARIF, the review
and `diff` treat it like any built-in check.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from .config import Config
from .graph import Flag, Graph


def custom_flags(g: Graph, root: Path, cfg: Config) -> list[Flag]:
    if not cfg.rules:
        return []
    by_file: dict[str, list] = {}
    for fn in g.functions:
        by_file.setdefault(fn.file, []).append(fn)
    out = []
    for f in g.files:
        rules = [
            r for r in cfg.rules if any(fnmatch(f.id, glob) or fnmatch(f.id, glob.replace("**/", "")) for glob in r["files"])
        ]
        if not rules:
            continue
        try:
            lines = (root / f.id).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        fns = by_file.get(f.id, [])
        for i, line in enumerate(lines, 1):
            for r in rules:
                if r["regex"].search(line):
                    holding = [fn for fn in fns if fn.kind != "module" and fn.line <= i <= fn.end]
                    module = next((fn for fn in fns if fn.kind == "module"), None)
                    owner = min(holding, key=lambda fn: fn.end - fn.line) if holding else module
                    target = owner.id if owner else f.id
                    msg = f"[{r['id']}] {r['message']}" + (f" Fix: {r['fix']}" if r["fix"] else "")
                    out.append(Flag("custom", r["severity"], target, msg, line=i, detail=r["id"]))
    return out
