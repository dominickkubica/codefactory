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
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .. import __version__

MIN_PARALLEL = 64  # files; below this, one process is faster
CHUNK = 16
# (root, name, tool) -> relative path -> [stamp, result]: this process's own results, for a run that asks for them
# again (the source checks, done while the graph is built and then by the review), whether or not a disk cache exists
_MEMO: dict[tuple[str, str, str], dict[str, list]] = {}


def workers() -> int:
    env = os.environ.get("CODEFACTORY_JOBS")
    if env and env.isdigit():
        return max(1, int(env))
    return max(1, min(32, (os.cpu_count() or 1)))


def _stamp(path: Path, now_ns: int = 0) -> str:
    """The file's stamp; "" (never matches) when it changed too recently to trust (see paths.racy)."""
    from ..paths import file_stamp, racy

    st = path.stat()
    return "" if now_ns and racy(st, now_ns) else file_stamp(st)


def _cache_file(root: Path, name: str) -> Path | None:
    from ..paths import cache_dir

    d = cache_dir(root)
    return d / f"files-{name}.json" if d else None


def _load(root: Path, name: str, tool: str) -> dict:
    path = _cache_file(root, name)
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data.get("files", {}) if data.get("tool") == tool else {}


def _save(root: Path, name: str, tool: str, files: dict) -> None:
    path = _cache_file(root, name)
    if path is None:
        return  # untrusted cache folder
    try:
        d = path.parent
        d.mkdir(exist_ok=True)
        (d / ".gitignore").write_text("# codefactory's cache: never committed\n*\n", encoding="utf-8")
        path.write_text(json.dumps({"tool": tool, "files": files}), encoding="utf-8")
    except OSError:
        pass  # a read-only checkout: analyze in full each time


def run(
    root: Path,
    name: str,
    items: list[tuple[str, tuple]],
    work: Callable[..., dict | None],
    tool: str = "",
    cache: bool = True,
    memo: bool = False,
    jobs: int | None = None,
    nice: int = 0,
) -> dict[str, dict]:
    """items: (relative path, arguments for work). Returns relative path -> result (None results are left out).
    `tool` identifies the analyzer's version: a different one ignores the cache. `memo`: also keep the results in this
    process, for a second call (see _MEMO). `jobs`: processes at most (default: workers()); `nice`: their priority,
    lowered by that much (background work that mustn't slow what runs alongside it)."""
    tool = f"{__version__}|{tool}|{_tool_hash()}"
    old = _load(root, name, tool) if cache else {}
    held = _MEMO.get((str(root), name, tool), {}) if memo else {}
    old = {**old, **held} if held else old
    out: dict[str, dict] = {}
    stamps: dict[str, str] = {}
    todo: list[tuple[str, tuple]] = []
    now_ns = time.time_ns()
    for rel, args in items:
        try:
            stamps[rel] = _stamp(root / rel, now_ns)
        except OSError:
            continue
        hit = old.get(rel)
        if hit and stamps[rel] and hit[0] == stamps[rel]:
            if hit[1] is not None:
                out[rel] = hit[1]
        else:
            todo.append((rel, args))
    n = min(jobs or workers(), workers())
    if len(todo) >= MIN_PARALLEL and n > 1:
        try:
            lower = {"initializer": os.nice, "initargs": (nice,)} if nice and hasattr(os, "nice") else {}
            with ProcessPoolExecutor(max_workers=n, **lower) as pool:
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
    if memo:
        _MEMO.setdefault((str(root), name, tool), {}).update(new)
    return out


def _tool_hash() -> str:
    """Changes whenever codefactory's own code does, so a new or edited version never reuses old results."""
    import hashlib

    from ..cache import _tool_stamp

    return hashlib.sha1(_tool_stamp().encode()).hexdigest()[:12]


def _call(job: tuple) -> dict | None:
    work, args = job
    return work(*args)
