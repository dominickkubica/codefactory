"""Work a review needs that doesn't need the graph, started while the graph is built.

A TypeScript project's type checker runs for a minute or more (teable: 75 s) while Python only waits for it. The
source checks of every file (review), and the reading, filtering and parsing of the JavaScript and TypeScript files
(the data-flow pass), depend on the files alone, so they run then, in the background. Each is only a head start: what
it prepared is used where it matches (a source check result by the file's stamp, as with the disk cache; a parsed
file by its exact bytes), and anything it missed or got wrong is done as before. A failure here costs nothing.
"""

from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path

# (root, job) -> the thread doing it
_RUNNING: dict[tuple[str, str], threading.Thread] = {}


def start(root: Path) -> None:
    from . import checks, flags, jstaint, privacy

    root = root.resolve()
    sources = checks.kept_on_disk(root)
    js = [f for f in sources if Path(f).suffix in jstaint.EXT_LANG]
    if not js:
        return  # no type checker to wait for: the build keeps every core busy itself
    # (half the cores for the source checks: the type checker's processes need the rest)
    _spawn(root, "sources", lambda: checks.warm(root, sources, jobs=max(1, (os.cpu_count() or 2) // 2)))
    _spawn(root, "jstaint", lambda: jstaint.prepare(root, js))
    _spawn(root, "mentions", lambda: flags.prepare_mentions(root, sources))
    _spawn(root, "privacy", lambda: privacy.prepare(root, sources))


def wait(root: Path, job: str) -> None:
    """Wait for that job, if it was started for `root` and is still running (once: after that it's done)."""
    t = _RUNNING.pop((str(Path(root).resolve()), job), None)
    if t is not None:
        t.join()


def _spawn(root: Path, job: str, work) -> None:
    def run() -> None:
        # behind the type checker, which the run waits for (Linux sets a thread's own priority; elsewhere it's skipped)
        with contextlib.suppress(AttributeError, OSError):
            os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)
        # (a head start that fails: the work is done as before, when it's asked for)
        with contextlib.suppress(Exception):
            work()

    if (str(root), job) not in _RUNNING:
        t = threading.Thread(target=run, name=f"codefactory-warm-{job}", daemon=True)
        _RUNNING[(str(root), job)] = t
        t.start()
