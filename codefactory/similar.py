"""Near-duplicate functions: copies that were edited afterwards, so their structure is mostly, not exactly, the same.

Each function's structure tokens are cut into overlapping 4-token shingles; MinHash with banding (LSH) finds likely
pairs without comparing every pair, then the exact Jaccard similarity of the shingle sets decides. Pairs that are
exact copies are left to the duplicate check; a function and one nested inside it aren't compared.
"""

from __future__ import annotations

import zlib
from collections import defaultdict

from .config import Config
from .graph import Flag, Graph

K = 4  # tokens per shingle
PERMS = 64
BANDS, ROWS = 16, 4  # PERMS = BANDS * ROWS
PRIME = (1 << 61) - 1
# Fixed seeds: the same code gives the same results on every run.
_A = [(i * 0x9E3779B97F4A7C15 + 0x632BE59BD9B4E019) % PRIME or 1 for i in range(1, PERMS + 1)]
_B = [(i * 0xBF58476D1CE4E5B9 + 0x94D049BB133111EB) % PRIME for i in range(1, PERMS + 1)]


def shingles(tokens: str) -> set[int]:
    t = tokens.split()
    return {zlib.crc32(" ".join(t[i : i + K]).encode()) for i in range(max(0, len(t) - K + 1))}


def signature(sh: set[int]) -> list[int]:
    return [min((a * x + b) % PRIME for x in sh) for a, b in zip(_A, _B, strict=True)]


def jaccard(a: set[int], b: set[int]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def similar_pairs(g: Graph, min_tokens: int = 40, threshold: float = 0.75) -> dict[tuple[str, str], float]:
    fns = [f for f in g.functions if f.tokens and len(f.tokens.split()) >= min_tokens]
    sets = {f.id: shingles(f.tokens) for f in fns}
    by_id = {f.id: f for f in fns}
    buckets = defaultdict(list)
    for f in fns:
        sig = signature(sets[f.id])
        for band in range(BANDS):
            buckets[(band, tuple(sig[band * ROWS : (band + 1) * ROWS]))].append(f.id)
    pairs: dict[tuple[str, str], float] = {}
    for ids in buckets.values():
        if len(ids) < 2 or len(ids) > 200:  # a giant bucket is boilerplate everyone shares, not copies
            continue
        for i, a in enumerate(ids):
            for b in ids[i + 1 :]:
                key = (a, b) if a < b else (b, a)
                if key in pairs:
                    continue
                fa, fb = by_id[a], by_id[b]
                if fa.shape and fa.shape == fb.shape:
                    continue  # an exact copy: reported as a duplicate
                if fa.file == fb.file and (
                    fa.qualname.startswith(fb.qualname + ".") or fb.qualname.startswith(fa.qualname + ".")
                ):
                    continue  # one holds the other
                na, nb = len(sets[a]), len(sets[b])
                if min(na, nb) / max(na, nb) < 0.6:
                    continue
                sim = jaccard(sets[a], sets[b])
                if sim >= threshold:
                    pairs[key] = sim
    return pairs


def near_duplicates(g: Graph, cfg: Config) -> list[Flag]:
    pairs = similar_pairs(g, threshold=cfg.similar_threshold)
    if not pairs:
        return []
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in pairs:
        parent[find(a)] = find(b)
    groups = defaultdict(list)
    for x in parent:
        groups[find(x)].append(x)
    by_id = {f.id: f for f in g.functions}
    best: dict[str, float] = defaultdict(float)
    for (a, b), sim in pairs.items():
        best[a] = max(best[a], sim)
        best[b] = max(best[b], sim)
    out = []
    for members in groups.values():
        members.sort()
        for m in members:
            others = [o for o in members if o != m]
            sims = [pairs.get((m, o) if m < o else (o, m)) for o in others]
            known = [s for s in sims if s]
            names = ", ".join(by_id[o].qualname for o in others[:4]) + (" …" if len(others) > 4 else "")
            lo, hi = round(min(known) * 100), round(max(known) * 100)
            pct = f"{lo}–{hi}%" if lo != hi else f"{hi}%"
            out.append(
                Flag(
                    "similar",
                    "warn" if best[m] >= 0.85 else "info",
                    m,
                    f"{pct} similar to {names}: likely a copy that was edited",
                    others,
                    line=by_id[m].line,
                    score=round(best[m], 3),
                )
            )
    return out
