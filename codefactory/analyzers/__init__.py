"""Language analyzers. Each reads a codebase and returns a Graph; add a language by adding a module here."""
from __future__ import annotations

from pathlib import Path

from ..graph import Graph
from .python import analyze_python

ANALYZERS = {"python": analyze_python}


def analyze(root: Path, ignore: list[str], languages: list[str] | None = None) -> Graph:
    g = Graph(root=str(root), language="")
    for lang in languages or list(ANALYZERS):
        g.merge(ANALYZERS[lang](root, ignore))
    return g
