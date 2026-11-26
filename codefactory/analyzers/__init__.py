"""Language analyzers. Each reads a codebase and returns a Graph; add a language by adding a module here.

Python and TypeScript/JavaScript have precise analyzers (the standard library's ast; the TypeScript type checker).
Every other language goes through tree-sitter (generic.py), which also stands in for TypeScript/JavaScript when the
typescript package isn't installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..graph import Graph
from .generic import analyze_generic
from .python import analyze_python
from .typescript import TypeScriptUnavailable, analyze_typescript

LANGUAGES = ("python", "typescript", "other")


def analyze(root: Path, ignore: list[str], languages: list[str] | None = None, cache: bool = True) -> Graph:
    g = Graph(root=str(root), language="")
    wanted = languages or list(LANGUAGES)
    js_fallback = False
    for lang in wanted:
        if lang == "python":
            part = analyze_python(root, ignore, cache=cache)
        elif lang == "typescript":
            try:
                part = analyze_typescript(root, ignore, cache=cache)
            except TypeScriptUnavailable as e:
                if languages and "other" not in languages:  # asked for explicitly: that's an error
                    raise SystemExit(f"codefactory: {e}") from None
                from .generic import available

                if available():
                    print(f"codefactory: {e} Using the general analyzer for TypeScript/JavaScript instead.", file=sys.stderr)
                else:  # nothing will read them: say so, loudly (a review of nothing once graded "Strong")
                    print(f"codefactory: {e} The language pack isn't installed either, so TypeScript/JavaScript files "
                          "are NOT analyzed (line checks only).", file=sys.stderr)  # fmt: skip
                js_fallback = True
                continue
        elif lang == "other":
            part = analyze_generic(root, ignore, include_js=js_fallback, cache=cache)
        else:
            raise ValueError(f"unknown language {lang!r} (choose from {', '.join(LANGUAGES)})")
        if part.files:
            g.merge(part)
    _unique_ids(g)
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
