"""Which layer (factory zone) each file belongs to, and the zones' left-to-right order."""

from __future__ import annotations

import re
import sys
from collections import Counter
from fnmatch import fnmatch
from pathlib import PurePosixPath

from . import paths
from .config import Config
from .graph import Graph

TEST_DIRS = set(paths.TEST_DIRS)
SOURCE_DIRS = {"src", "lib", "source"}


def _inferred(paths: list[str]) -> dict[str, str]:
    """Layer = the first folder after the folders every file shares (src/ and one top package are skipped)."""
    dirs = [PurePosixPath(p).parts[:-1] for p in paths]
    nontest = [d for d in dirs if not (set(d) & TEST_DIRS)] or dirs
    common: list[str] = []
    if nontest:
        for parts in zip(*nontest, strict=False):  # up to the shortest path
            if len(set(parts)) != 1:
                break
            common.append(parts[0])
    out: dict[str, str] = {}
    deeper: dict[str, tuple[str, ...]] = {}  # the folders below each file's layer
    for p, d in zip(paths, dirs, strict=True):
        if set(d) & TEST_DIRS:
            out[p] = "tests"
            continue
        rest = d[len(common) :] if tuple(d[: len(common)]) == tuple(common) else d
        if rest and rest[0] in SOURCE_DIRS:  # src/app/x.ts -> "app"; files directly in src/ -> "src"
            out[p] = rest[1] if len(rest) > 1 else rest[0]
            deeper[p] = rest[2:]
            continue
        out[p] = rest[0] if rest else (common[-1] if common else "root")
        deeper[p] = rest[1:]
    return _split_dominant(out, deeper)


def _split_dominant(out: dict[str, str], deeper: dict[str, tuple[str, ...]]) -> dict[str, str]:
    """One zone holding most of the code (pip/_internal/…, app/core/…) says nothing: split it by the next folder level,
    as long as that gives several real zones. Files directly in the zone's folder keep its name."""
    counts = Counter(layer for layer in out.values() if layer != "tests")
    total = sum(counts.values())
    if not counts:
        return out
    top, n = counts.most_common(1)[0]
    members = [p for p, layer in out.items() if layer == top]
    subs = Counter(deeper[p][0] for p in members if deeper.get(p))
    if total >= 12 and n >= 0.7 * total and len([c for c in subs.values() if c >= 2]) >= 3:
        for p in members:
            if deeper.get(p):
                out[p] = deeper[p][0]
    return out


def _by_depth(g: Graph, ids: set[str]) -> dict[str, str]:
    """For code with no folders to go by: zones by import depth. "level 0" imports nothing else here (the
    foundation); each level up builds on the ones below, like stages of a production line. Import loops share a level."""
    adj = {i: set() for i in ids}
    for e in g.edges:
        if e.kind == "import" and e.src in ids and e.dst in ids:
            adj[e.src].add(e.dst)
    depth: dict[str, int] = {}

    def level(v: str, trail: set[str]) -> int:
        if v in depth:
            return depth[v]
        if v in trail:  # a loop: stop here
            return 0
        trail.add(v)
        d = max((level(w, trail) + 1 for w in adj[v]), default=0)
        trail.discard(v)
        depth[v] = d
        return d

    sys.setrecursionlimit(max(sys.getrecursionlimit(), len(ids) * 4 + 100))
    out = {}
    top = max((level(v, set()) for v in ids), default=0)
    width = max(1, -(-(top + 1) // 6))  # at most 6 zones
    for v in ids:
        lo = (level(v, set()) // width) * width
        hi = min(top, lo + width - 1)
        out[v] = f"level {lo}" if lo == hi else f"level {lo}-{hi}"
    return out


def assign_layers(g: Graph, cfg: Config) -> None:
    paths = [f.id for f in g.files]
    inferred = _inferred(paths)
    main = {p for p, layer in inferred.items() if layer != "tests"}
    if not cfg.layers and len({inferred[p] for p in main}) == 1 and len(main) > 6:
        inferred.update(_by_depth(g, main))
    for f in g.files:
        f.layer = next((name for name, globs in cfg.layers.items() if any(fnmatch(f.id, gl) for gl in globs)), inferred[f.id])
    g.layers = order_layers(g)
    g.rules = [f"{a} -> {b}" for a, b in cfg.forbid]


def order_layers(g: Graph) -> list[str]:
    """Layers that depend on others go left (entry points, UI), layers others depend on go right (data, utils)."""
    layer_of = {f.id: f.layer for f in g.files}
    score: Counter = Counter({f.layer: 0 for f in g.files})
    for e in g.edges:
        if e.kind != "import":
            continue
        a, b = layer_of.get(e.src), layer_of.get(e.dst)
        if a and b and a != b:
            score[a] += 1
            score[b] -= 1
    levels = {n: int(m.group(1)) for n in score if (m := re.fullmatch(r"level (\d+)(-\d+)?", n))}
    if levels and len(levels) == len([n for n in score if n != "tests"]):
        return sorted(score, key=lambda name: (name != "tests", -levels.get(name, 0)))
    return sorted(score, key=lambda name: (name != "tests", -score[name], name))
