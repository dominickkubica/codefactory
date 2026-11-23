"""Issue detectors. They read only the Graph, so they work the same for every language."""
from __future__ import annotations

from collections import defaultdict

from .config import Config
from .efficiency import efficiency_flags
from .graph import Flag, Graph
from .similar import near_duplicates

SEVERITY_ORDER = {"high": 0, "warn": 1, "info": 2}


def _is_entry(fn) -> bool:
    n = fn.name
    return (fn.kind == "module" or fn.exported or fn.decorated or n.startswith("__") or n.startswith("test")
            or n in ("setUp", "tearDown", "setUpClass", "tearDownClass") or _is_test_file(fn.file))


def _is_test_file(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return any(p in ("tests", "test", "__tests__", "__mocks__") for p in parts[:-1]) or name.startswith("test_") \
        or ".test." in name or ".spec." in name or name.endswith("_test.py")


def dead_code(g: Graph) -> list[Flag]:
    file_of = {fn.id: fn.file for fn in g.functions}
    used = {e.dst for e in g.edges if e.kind in ("call", "ref")}
    used_by_code = {e.dst for e in g.edges if e.kind in ("call", "ref") and not _is_test_file(file_of.get(e.src, ""))}
    imported = {e.dst for e in g.edges if e.kind == "import"}
    out = []
    for fn in g.functions:
        # A file nothing imports is loaded by a framework, a runner or a user: its exports are entry points.
        if _is_entry(fn) or (fn.public and fn.file not in imported):
            continue
        if fn.id in used:
            if fn.id not in used_by_code and not _is_test_file(fn.file):
                out.append(Flag("test_only", "info", fn.id, f"{fn.qualname} is only called from tests"))
            continue
        if fn.kind == "method":  # often called through an instance or a framework: only a hint
            if fn.dynamic:
                continue
            out.append(Flag("unused", "info", fn.id, f"{fn.qualname} has no callers found (it may be called "
                                                      "through an instance or a framework)"))
        else:
            out.append(Flag("unused", "warn", fn.id, f"{fn.qualname} is never called or referenced"))
    return out


def duplicates(g: Graph, cfg: Config) -> list[Flag]:
    groups = defaultdict(list)
    for fn in g.functions:
        if fn.shape and fn.loc >= cfg.duplicate_min_lines:
            groups[fn.shape].append(fn)
    out = []
    for fns in groups.values():
        if len(fns) < 2:
            continue
        ids = [f.id for f in fns]
        names = ", ".join(f.qualname for f in fns[:4]) + (" …" if len(fns) > 4 else "")
        for f in fns:
            out.append(Flag("duplicate", "warn", f.id, f"Same structure as {len(fns) - 1} other function(s): {names}",
                            [i for i in ids if i != f.id]))
    return out


def import_cycles(g: Graph) -> list[Flag]:
    """Strongly connected groups of files in the import graph (Tarjan)."""
    adj = defaultdict(set)
    for e in g.edges:
        if e.kind == "import":
            adj[e.src].add(e.dst)
    index, low, stack, on, comps, counter = {}, {}, [], set(), [], [0]

    def visit(v: str) -> None:
        work = [(v, iter(sorted(adj[v])))]
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        while work:
            node, it = work[-1]
            nxt = next(it, None)
            if nxt is None:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp.append(w)
                        if w == node:
                            break
                    if len(comp) > 1:
                        comps.append(sorted(comp))
            elif nxt not in index:
                index[nxt] = low[nxt] = counter[0]
                counter[0] += 1
                stack.append(nxt)
                on.add(nxt)
                work.append((nxt, iter(sorted(adj[nxt]))))
            elif nxt in on:
                low[node] = min(low[node], index[nxt])

    for v in sorted({f.id for f in g.files}):
        if v not in index:
            visit(v)
    out = []
    for comp in comps:
        loop = " → ".join(c.split("/")[-1] for c in comp)
        for f in comp:
            out.append(Flag("cycle", "high", f, f"Import loop of {len(comp)} files: {loop}", [c for c in comp if c != f]))
    return out


def size_flags(g: Graph, cfg: Config) -> list[Flag]:
    out = []
    for f in g.files:
        if f.loc > cfg.large_file:
            out.append(Flag("large_file", "info", f.id, f"{f.loc} lines (over {cfg.large_file})"))
    for fn in g.functions:
        if fn.kind != "module" and fn.loc > cfg.long_function:
            out.append(Flag("long_function", "info", fn.id, f"{fn.qualname} is {fn.loc} lines (over {cfg.long_function})"))
    return out


def hubs(g: Graph, cfg: Config) -> list[Flag]:
    """Functions called from many different files: a change there ripples everywhere."""
    file_of = {fn.id: fn.file for fn in g.functions}
    callers = defaultdict(set)
    for e in g.edges:
        if e.kind == "call" and file_of.get(e.src) != file_of.get(e.dst):
            callers[e.dst].add(file_of.get(e.src))
    by_id = {fn.id: fn for fn in g.functions}
    return [Flag("hub", "info", fid, f"{by_id[fid].qualname} is called from {len(files)} files")
            for fid, files in callers.items() if len(files) >= cfg.hub_callers and fid in by_id]


def layer_violations(g: Graph, cfg: Config) -> list[Flag]:
    if not cfg.forbid:
        return []
    layer_of = {f.id: f.layer for f in g.files}
    forbidden = set(cfg.forbid)
    out = []
    for e in g.edges:
        if e.kind != "import":
            continue
        pair = (layer_of.get(e.src), layer_of.get(e.dst))
        if pair in forbidden:
            out.append(Flag("layer_violation", "high", e.src, f"{e.src} ({pair[0]}) imports {e.dst} ({pair[1]}), "
                                                             f"which factory.toml forbids", [e.dst]))
    return out


def run_flags(g: Graph, cfg: Config) -> None:
    g.flags = [*import_cycles(g), *layer_violations(g, cfg), *duplicates(g, cfg), *near_duplicates(g, cfg),
               *efficiency_flags(g), *dead_code(g), *hubs(g, cfg), *size_flags(g, cfg)]
    by_id = {fn.id: fn for fn in g.functions}
    for f in g.flags:  # every issue points at a line, for editors and for Claude Code
        if not f.line and f.target in by_id:
            f.line = by_id[f.target].line
    g.flags.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.kind, f.target))
    for fn in g.functions:  # only needed for the checks above; keeps the saved graph and the HTML small
        fn.tokens = ""
