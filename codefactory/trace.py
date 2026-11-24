"""EXPLAIN for a function: everything it eventually calls, how deep, and how much code that is; and the shortest
call path from one function to another. Works on the graph dict, so also on a saved graph .json."""

from __future__ import annotations

from collections import defaultdict, deque


def _adjacency(graph: dict, kinds=("call",)) -> dict[str, list[str]]:
    adj = defaultdict(list)
    for e in graph["edges"]:
        if e["kind"] in kinds:
            adj[e["src"]].append(e["dst"])
    return adj


def find_function(graph: dict, query: str) -> list[dict]:
    """Matches an id ("file::qualname"), a qualname ("Class.method") or a bare name; exact matches first."""
    fns = [f for f in graph["functions"] if f["kind"] != "module"]
    for key in ("id", "qualname", "name"):
        hits = [f for f in fns if f[key] == query]
        if hits:
            return hits
    return [f for f in fns if f["id"].endswith(query)]


def trace(graph: dict, start: str, kinds=("call",)) -> dict:
    """Breadth-first walk of what `start` calls, directly or not. Each function appears once, at its shortest depth."""
    by_id = {f["id"]: f for f in graph["functions"]}
    adj = _adjacency(graph, kinds)
    depth = {start: 0}
    via: dict[str, str] = {}
    loops: set[str] = set()
    q = deque([start])
    while q:
        cur = q.popleft()
        for nxt in adj[cur]:
            if nxt == start:
                loops.add(cur)  # something it calls calls it back
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                via[nxt] = cur
                q.append(nxt)
    reached = [by_id[i] | {"depth": d, "via": via.get(i)} for i, d in depth.items() if i != start and i in by_id]
    reached.sort(key=lambda f: (f["depth"], f["file"], f["line"]))
    return {
        "start": start,
        "functions": reached,
        "files": sorted({f["file"] for f in reached}),
        "depth": max((f["depth"] for f in reached), default=0),
        "loc": sum(f["loc"] for f in reached),
        "calls_back": sorted(loops),
    }


def shortest_path(graph: dict, src: str, dst: str, kinds=("call",)) -> list[str] | None:
    adj = _adjacency(graph, kinds)
    prev = {src: None}
    q = deque([src])
    while q:
        cur = q.popleft()
        if cur == dst:
            path = []
            while cur is not None:
                path.append(cur)
                cur = prev[cur]
            return path[::-1]
        for nxt in adj[cur]:
            if nxt not in prev:
                prev[nxt] = cur
                q.append(nxt)
    return None
