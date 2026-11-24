"""Language analyzers. Each reads a codebase and returns a Graph; add a language by adding a module here."""

from __future__ import annotations

import sys
from pathlib import Path

from ..graph import Graph
from .python import analyze_python
from .typescript import TypeScriptUnavailable, analyze_typescript

ANALYZERS = {"python": analyze_python, "typescript": analyze_typescript}


def analyze(root: Path, ignore: list[str], languages: list[str] | None = None) -> Graph:
    g = Graph(root=str(root), language="")
    for lang in languages or list(ANALYZERS):
        try:
            part = ANALYZERS[lang](root, ignore)
        except TypeScriptUnavailable as e:
            if languages:  # asked for explicitly: that's an error
                raise SystemExit(f"codefactory: {e}") from None
            print(f"codefactory: skipping TypeScript/JavaScript. {e}", file=sys.stderr)
            continue
        if part.files:
            g.merge(part)
    return g
