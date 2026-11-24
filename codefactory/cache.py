"""Reuse the last analysis while no source file changed: <repo>/.codefactory/graph.json, keyed by a fingerprint of
every analyzable file's path, size and modification time (plus factory.toml, tsconfig.json and codefactory's version).
An AI agent asking for context many times in a row then waits once, not every time."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import __version__

SOURCE = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
SETTINGS = ("factory.toml", "tsconfig.json", "jsconfig.json", "pyproject.toml")


def _tool_stamp() -> str:
    """codefactory's own files: a new analyzer or check (even between releases) means the old graph is stale."""
    here = Path(__file__).parent
    parts = [__version__]
    for p in sorted(here.rglob("*")):
        if p.suffix in (".py", ".js") and "__pycache__" not in p.parts:
            st = p.stat()
            parts.append(f"{p.relative_to(here)}|{st.st_size}|{st.st_mtime_ns}")
    return "\n".join(parts)


def fingerprint(root: Path, ignore: list[str]) -> str:
    skip = set(ignore)
    h = hashlib.sha1(_tool_stamp().encode())
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if name.endswith(SOURCE) or name in SETTINGS:
                p = os.path.join(dirpath, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                h.update(f"{os.path.relpath(p, root)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def _dir(root: Path) -> Path:
    return root / ".codefactory"


def load_cached(root: Path, ignore: list[str]) -> dict | None:
    path = _dir(root) / "graph.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get("graph") if data.get("fingerprint") == fingerprint(root, ignore) else None


def save_cache(root: Path, ignore: list[str], graph: dict) -> None:
    d = _dir(root)
    try:
        d.mkdir(exist_ok=True)
        (d / ".gitignore").write_text("# codefactory's cache: never committed\n*\n", encoding="utf-8")
        (d / "graph.json").write_text(json.dumps({"fingerprint": fingerprint(root, ignore), "graph": graph}), encoding="utf-8")
    except OSError:
        pass  # read-only checkout: just analyze each time
