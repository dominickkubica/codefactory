"""Per-file work in parallel, with a per-file cache, so big codebases analyze on every core and re-analyze only what
changed.

An analyzer splits its work into a per-file step (a top-level function: path -> plain, JSON-able data) and a step
that links the files together. This module runs the per-file step: results for files whose size and modification
time haven't changed come from `.codefactory/files-<name>.json`; the rest run in a process pool (in this process when
there are only a few, where starting workers would cost more than it saves).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .. import __version__

MIN_PARALLEL = 64  # files; below this, one process is faster
CHUNK = 16


def workers() -> int:
    env = os.environ.get("CODEFACTORY_JOBS")
    if env and env.isdigit():
        return max(1, int(env))
    return max(1, min(32, (os.cpu_count() or 1)))


def _stamp(path: Path) -> str:
    st = path.stat()
    return f"{st.st_size}:{st.st_mtime_ns}"


def _cache_file(root: Path, name: str) -> Path:
    return root / ".codefactory" / f"files-{name}.json"


def _load(root: Path, name: str, tool: str) -> dict:
    try:
        data = json.loads(_cache_file(root, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data.get("files", {}) if data.get("tool") == tool else {}


def _save(root: Path, name: str, tool: str, files: dict) -> None:
    try:
        d = root / ".codefactory"
        d.mkdir(exist_ok=True)
        (d / ".gitignore").write_text("# codefactory's cache: never committed\n*\n", encoding="utf-8")
        _cache_file(root, name).write_text(json.dumps({"tool": tool, "files": files}), encoding="utf-8")
    except OSError:
        pass  # a read-only checkout: analyze in full each time


def run(
    root: Path,
    name: str,
    items: list[tuple[str, tuple]],
    work: Callable[..., dict | None],
    tool: str = "",
    cache: bool = True,
) -> dict[str, dict]:
    """items: (relative path, arguments for work). Returns relative path -> result (None results are left out).
    `tool` identifies the analyzer's version: a different one ignores the cache."""
    tool = f"{__version__}|{tool}|{_tool_hash()}"
    old = _load(root, name, tool) if cache else {}
    out: dict[str, dict] = {}
    stamps: dict[str, str] = {}
    todo: list[tuple[str, tuple]] = []
    for rel, args in items:
        try:
            stamps[rel] = _stamp(root / rel)
        except OSError:
            continue
        hit = old.get(rel)
        if hit and hit[0] == stamps[rel]:
            if hit[1] is not None:
                out[rel] = hit[1]
        else:
            todo.append((rel, args))
    if len(todo) >= MIN_PARALLEL and workers() > 1:
        try:
            with ProcessPoolExecutor(max_workers=workers()) as pool:
                results = list(pool.map(_call, [(work, a) for _, a in todo], chunksize=CHUNK))
        except (OSError, RuntimeError, ImportError):  # no process support here (some sandboxes): do it in-process
            results = [work(*a) for _, a in todo]
    else:
        results = [work(*a) for _, a in todo]
    new = {rel: [stamps[rel], out[rel]] for rel in out}
    for (rel, _), res in zip(todo, results, strict=True):
        new[rel] = [stamps[rel], res]
        if res is not None:
            out[rel] = res
    if cache:
        _save(root, name, tool, new)
    return out


def _tool_hash() -> str:
    """Changes whenever codefactory's own code does, so a new or edited version never reuses old results."""
    import hashlib

    from ..cache import _tool_stamp

    return hashlib.sha1(_tool_stamp().encode()).hexdigest()[:12]


def _call(job: tuple) -> dict | None:
    work, args = job
    return work(*args)
