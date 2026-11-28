"""Language analyzers. Each reads a codebase and returns a Graph; add a language by adding a module here.

Python and TypeScript/JavaScript have precise analyzers (the standard library's ast; the TypeScript type checker).
Every other language goes through tree-sitter (generic.py), which also stands in for TypeScript/JavaScript when the
typescript package isn't installed.
"""

from __future__ import annotations

import sys
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from ..graph import Graph
from ..timing import phase
from .generic import analyze_generic
from .python import analyze_python
from .typescript import TypeScriptUnavailable, analyze_typescript

LANGUAGES = ("python", "typescript", "other")


# set when the last analysis left a language out for want of a tool (no TypeScript compiler): such a result isn't
# cached, so installing the tool takes effect on the next run instead of after --no-cache
INCOMPLETE: list[str] = []


def analyze(root: Path, ignore: list[str], languages: list[str] | None = None, cache: bool = True,
            review_follows: bool = False) -> Graph:  # fmt: skip
    INCOMPLETE.clear()
    g = Graph(root=str(root), language="")
    wanted = languages or list(LANGUAGES)
    # the TypeScript analyzer is a Node process of its own: start it first, so it runs while Python is analyzed on the
    # other cores (a Django or FastAPI app with a TypeScript front end waited for one, then the other); the results
    # are merged in the same order as before
    pool = ThreadPoolExecutor(max_workers=1) if "typescript" in wanted else None

    def timed_typescript() -> Graph:
        with phase("build.typescript"):
            return analyze_typescript(root, ignore, cache=cache)

    ts_future = pool.submit(timed_typescript) if pool else None
    try:
        return _analyze(root, ignore, languages, cache, wanted, ts_future, g, review_follows)
    finally:
        if pool:
            pool.shutdown(wait=True)


def _analyze(root: Path, ignore: list[str], languages: list[str] | None, cache: bool, wanted: list[str],
             ts_future: Future | None, g: Graph, review_follows: bool = False) -> Graph:  # fmt: skip
    js_fallback = False
    for lang in wanted:
        if lang == "python":
            with phase("build.python"):
                part = analyze_python(root, ignore, cache=cache)
        elif lang == "typescript":
            if review_follows:  # while the type checker runs, the review's work that needs no graph (warm.py)
                from .. import warm

                warm.start(root)
            try:
                part = ts_future.result()
            except TypeScriptUnavailable as e:
                if languages and "other" not in languages:  # asked for explicitly: that's an error
                    raise SystemExit(f"codefactory: {e}") from None
                from .generic import available

                INCOMPLETE.append("typescript")  # (by name, or not at all: either way not what a compiler gives)
                if available():
                    print(f"codefactory: {e} Using the general analyzer for TypeScript/JavaScript instead.", file=sys.stderr)
                else:  # nothing will read them: say so, loudly (a review of nothing once graded "Strong")
                    print(f"codefactory: {e} The language pack isn't installed either, so TypeScript/JavaScript files "
                          "are NOT analyzed (line checks only).", file=sys.stderr)  # fmt: skip
                js_fallback = True
                continue
        elif lang == "other":
            with phase("build.other_languages"):
                part = analyze_generic(root, ignore, include_js=js_fallback, cache=cache)
        else:
            raise ValueError(f"unknown language {lang!r} (choose from {', '.join(LANGUAGES)})")
        if part.files:
            g.merge(part)
    _unique_ids(g)
    # (in a fixed order: some analyzers build their edges from sets, and string hashing differs per process, so the
    # same code gave the same edges in a different order each run and no two exports could be compared byte for byte)
    g.edges.sort(key=lambda e: (e.src, e.dst, e.kind))
    return g


def _unique_ids(g: Graph) -> None:
    """Every function id once, whatever an analyzer produced (minified or generated code can repeat a name on one
    line): a repeat gets #2, #3… Edges keep pointing at the first."""
    seen: dict[str, int] = {}
    for f in g.functions:
        n = seen.get(f.id, 0)
        seen[f.id] = n + 1
        if n:
            f.id = f"{f.id}#{n + 1}"
