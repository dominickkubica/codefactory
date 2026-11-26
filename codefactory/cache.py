"""Reuse the last analysis while no source file changed: <repo>/.codefactory/graph.json, keyed by a fingerprint of
every analyzable file's path, size and modification time (every language an analyzer reads), the settings files,
codefactory's own code, and which parsers are installed (installing the language pack or TypeScript later must
re-analyze, or the languages they add would stay missing). An AI agent asking for context many times in a row then
waits once, not every time."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from . import __version__


def _source_ext() -> tuple[str, ...]:
    """Every extension an analyzer reads: Python, TypeScript/JavaScript, and each tree-sitter language."""
    from .analyzers.generic import JS_LANGS, LANGS

    return tuple(sorted({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", *LANGS, *JS_LANGS}))


def _parsers() -> str:
    """Which optional parsers this machine has: the language pack, Node.js, and a TypeScript package where codefactory
    looks for one (cheap checks, no subprocess: this runs on every command)."""
    import shutil

    from .analyzers.generic import available

    node = shutil.which("node") or ""
    candidates = [os.environ.get("CODEFACTORY_TYPESCRIPT", "")]
    if node:
        bin_dir = Path(node).resolve().parent
        candidates += [str(bin_dir.parent / "lib" / "node_modules" / "typescript"), str(bin_dir / "node_modules" / "typescript")]
    ts = next((c for c in candidates if c and (Path(c) / "lib" / "typescript.js").is_file()), "")
    return f"pack={available()}|node={bool(node)}|ts={ts}"


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


def fingerprint(root: Path, ignore: list[str], recent: list | None = None) -> str:
    """Every source file's stamp. `recent` (if given) gets True when a file changed too recently to trust."""
    from .paths import file_stamp, racy

    now_ns = time.time_ns()
    skip = set(ignore)
    h = hashlib.sha1((_tool_stamp() + "\n" + _parsers()).encode("utf-8", "surrogatepass"))
    source = _source_ext()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if name.endswith(source) or name in SETTINGS:
                p = os.path.join(dirpath, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if recent is not None and not recent and racy(st, now_ns):
                    recent.append(True)
                h.update(f"{os.path.relpath(p, root)}|{file_stamp(st)}\n".encode("utf-8", "surrogatepass"))
    return h.hexdigest()


def _dir(root: Path) -> Path | None:
    from .paths import cache_dir

    return cache_dir(root)


def load_cached(root: Path, ignore: list[str]) -> dict | None:
    d = _dir(root)
    if d is None:
        return None
    path = d / "graph.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get("graph") if data.get("fingerprint") == fingerprint(root, ignore) else None


def save_cache(root: Path, ignore: list[str], graph: dict) -> None:
    d = _dir(root)
    if d is None:
        return  # untrusted cache folder: analyze in full each time
    recent: list = []
    stamp = fingerprint(root, ignore, recent)
    if recent:
        return  # a file changed in the last moments: a same-size edit in the same tick would look unchanged
    try:
        d.mkdir(exist_ok=True)
        (d / ".gitignore").write_text("# codefactory's cache: never committed\n*\n", encoding="utf-8")
        (d / "graph.json").write_text(json.dumps({"fingerprint": stamp, "graph": graph}), encoding="utf-8")
    except OSError:
        pass  # read-only checkout: just analyze each time
