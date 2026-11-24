"""Near-duplicate functions: copies that were edited afterwards, so their structure is mostly, not exactly, the same.

Each function's structure tokens are cut into overlapping 4-token shingles; one-permutation MinHash with banding
(LSH) finds likely pairs without comparing every pair, then the exact Jaccard similarity of the shingle sets decides.
Pairs that are exact copies are left to the duplicate check; a function and one nested inside it aren't compared.
"""

from __future__ import annotations

import zlib
from collections import defaultdict
from operator import eq

from .config import Config
from .graph import Flag, Graph
from .paths import platform_variants

K = 4  # tokens per shingle
PERMS = 64
BANDS, ROWS = 16, 4  # PERMS = BANDS * ROWS
# Matching signature positions estimate the similarity (standard deviation ≈ 0.054 at 0.75 with 64 positions); a pair
# estimated 0.2 below the threshold (≈3.7 deviations) is skipped without building its shingle sets.
ESTIMATE_MARGIN = 0.2


def shingles(tokens: str) -> set[int]:
    t = tokens.split()
    return {zlib.crc32(" ".join(t[i : i + K]).encode("utf-8", "surrogatepass")) for i in range(max(0, len(t) - K + 1))}


MASK = (1 << 64) - 1
LOW = (1 << 58) - 1


def signature(sh: set[int]) -> list[int]:
    """One-permutation MinHash: each shingle is hashed once into one of PERMS bins, which keep their minimum; empty
    bins borrow the next filled bin's value (densification). As good as PERMS separate hashes for finding pairs, and
    PERMS times cheaper, which matters on millions of lines."""
    sig: list[int | None] = [None] * PERMS
    for x in sh:
        h = ((x + 0x632BE59BD9B4E019) * 0x9E3779B97F4A7C15) & MASK
        h ^= h >> 31
        h = (h * 0xBF58476D1CE4E5B9) & MASK
        b, v = h >> 58, h & LOW  # the high bits pick the bin (they're the best mixed), the rest are the value
        cur = sig[b]
        if cur is None or v < cur:
            sig[b] = v
    if all(s is None for s in sig):
        return [0] * PERMS
    out = []
    for i in range(PERMS):
        j, dist = i, 0
        while sig[j] is None:
            j, dist = (j + 1) % PERMS, dist + 1
        out.append(sig[j] + dist * 0x5BD1E995 if dist else sig[j])
    return out


def jaccard(a: set[int], b: set[int]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def _sig_of(tokens: str) -> list[int]:
    return signature(shingles(tokens))


def signatures(g: Graph, fns: list) -> dict[str, list[int]]:
    """Each function's signature, reused from `.codefactory/minhash.json` for code that didn't change (keyed by a hash
    of its tokens) and computed on every core for the rest."""
    import hashlib
    import json
    from pathlib import Path

    from .analyzers.parallel import MIN_PARALLEL, workers

    path = Path(g.root) / ".codefactory" / "minhash.json" if g.root else None
    try:
        old = json.loads(path.read_text(encoding="utf-8")) if path else {}
        old = old if old.get("v") == 1 else {}
    except (OSError, ValueError):
        old = {}
    keys = {f.id: hashlib.sha1(f.tokens.encode("utf-8", "surrogatepass")).hexdigest()[:20] for f in fns}
    sigs = old.get("sigs", {})
    missing = sorted({keys[f.id]: f.tokens for f in fns if keys[f.id] not in sigs}.items())
    if len(missing) >= MIN_PARALLEL * 8 and workers() > 1:
        from concurrent.futures import ProcessPoolExecutor

        try:
            with ProcessPoolExecutor(max_workers=workers()) as pool:
                computed = list(pool.map(_sig_of, [tok for _, tok in missing], chunksize=64))
        except (OSError, RuntimeError, ImportError):
            computed = [_sig_of(tok) for _, tok in missing]
    else:
        computed = [_sig_of(tok) for _, tok in missing]
    sigs.update({k: s for (k, _), s in zip(missing, computed, strict=True)})
    live = {keys[f.id] for f in fns}
    if path and (missing or len(sigs) > len(live)):
        try:
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"v": 1, "sigs": {k: v for k, v in sigs.items() if k in live}}), encoding="utf-8")
        except OSError:
            pass
    return {f.id: sigs[keys[f.id]] for f in fns}


def similar_pairs(g: Graph, min_tokens: int = 40, threshold: float = 0.75) -> dict[tuple[str, str], float]:
    fns = [f for f in g.functions if f.tokens and len(f.tokens.split()) >= min_tokens]
    sets: dict[str, set[int]] = {}  # built only for functions that land in a bucket with another

    def shingled(fid: str) -> set[int]:
        if fid not in sets:
            sets[fid] = shingles(by_id[fid].tokens)
        return sets[fid]

    by_id = {f.id: f for f in fns}
    sig_of = signatures(g, fns)
    buckets = defaultdict(list)
    for f in fns:
        sig = sig_of[f.id]
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
                if platform_variants(fa.file, fb.file):
                    continue  # the same file for another platform: copied on purpose
                if fa.file == fb.file and fa.name == fb.name:
                    continue  # overloads (indexOf(int[]), indexOf(long[])): one method per type, as Java requires
                if fa.file == fb.file and (
                    fa.qualname.startswith(fb.qualname + ".") or fb.qualname.startswith(fa.qualname + ".")
                ):
                    continue  # one holds the other
                sga, sgb = sig_of[a], sig_of[b]
                if sum(map(eq, sga, sgb)) < (threshold - ESTIMATE_MARGIN) * PERMS:
                    continue  # the signatures already say it's far below the threshold
                sa, sb = shingled(a), shingled(b)
                na, nb = len(sa), len(sb)
                if min(na, nb) / max(na, nb) < 0.6:
                    continue
                sim = jaccard(sa, sb)
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
