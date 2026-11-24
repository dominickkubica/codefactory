"""Efficiency checks, from what the analyzers record inside functions (Site) and the call graph.

- io_in_loop: a database, file or network call, or a call to one of the codebase's own functions that eventually
  makes one, runs once per loop iteration (the N+1 pattern: one query per item instead of one query for all).
- sequential_await: awaits inside a for/while loop wait for each round in turn; independent ones can run together.
- quadratic_scan: searching an array (find, filter, includes, indexOf…) inside a loop over items: O(n²) as data grows.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque

from .graph import Flag, Graph
from .paths import is_test


def io_reach(g: Graph) -> dict[str, tuple[str, str]]:
    """Function id -> (next function on the way, the I/O call it reaches), for every function that does I/O itself
    or through the functions it calls. A function doing it itself has next = itself."""
    callers = defaultdict(list)
    for e in g.edges:
        if e.kind == "call":
            callers[e.dst].append(e.src)
    reach: dict[str, tuple[str, str]] = {}
    q = deque()
    for f in g.functions:
        if f.io and f.kind != "module":
            reach[f.id] = (f.id, f.io[0])
            q.append(f.id)
    while q:
        cur = q.popleft()
        for c in callers[cur]:
            if c not in reach:
                reach[c] = (cur, reach[cur][1])
                q.append(c)
    return reach


def _name(fn) -> str:
    return f"top-level code in {fn.file.split('/')[-1]}" if fn.kind == "module" else fn.qualname


NETWORK = re.compile(r"(^|\.)(fetch|urlopen)$|axios|requests\.|httpx|aiohttp|http|supabase|firestore", re.I)
READS = re.compile(
    r"getAll|getFirst|getEach|fetchone|fetchall|fetchmany|(^|\.)(query|select|find\w*|get|getItem\w*|"
    r"read\w*|scalars?|from)$|objects\.(get|filter|all)|\(.SELECT",
    re.I,
)


FILES = re.compile(
    r"readFile|writeFile|appendFile|readdir|(^|\.)stat(Sync)?$|read_text|write_text|read_bytes|"
    r"write_bytes|AsStringAsync|downloadAsync|downloadFileAsync|uploadAsync|^open$|iterdir|r?glob$",
    re.I,
)


def called(x: str) -> str:
    return x if x.endswith(")") else f"{x}()"


def kind_of(sink: str) -> str:
    """network | file | read | write: how much a call in a loop costs. Network and database reads are the classic
    N+1; files one by one are normal in scripts; writes one at a time are slower than a batch but usually fine inside
    one transaction."""
    if NETWORK.search(sink):
        return "network"
    if FILES.search(sink):
        return "file"
    return "read" if READS.search(sink) else "write"


def efficiency_flags(g: Graph) -> list[Flag]:
    """Test files are left out: a loop of setup calls in a test isn't a problem anyone ships."""
    by_id = {f.id: f for f in g.functions}
    reach = io_reach(g)
    out: list[Flag] = []
    loop_io: dict[tuple[str, str], list[int]] = defaultdict(list)  # (fn, what) -> lines
    unbounded: set[tuple[str, str]] = set()  # (fn, what) with at least one loop whose length depends on data
    awaits: dict[str, list[int]] = defaultdict(list)
    for s in g.sites:
        if s.fn not in by_id or is_test(by_id[s.fn].file):
            continue
        if s.kind in ("loop_io", "loop_call"):
            key = (s.fn, s.detail if s.kind == "loop_io" else s.target)
            if s.kind == "loop_call" and s.target not in reach:
                continue
            loop_io[key].append(s.line)
            if not s.bounded:
                unbounded.add(key)
        elif s.kind == "loop_await" and not s.bounded:  # a few fixed rounds in turn cost nothing worth reporting
            awaits[s.fn].append(s.line)
        elif s.kind == "loop_scan" and not s.bounded:
            fn = by_id.get(s.fn)
            if fn:
                out.append(
                    Flag(
                        "quadratic_scan",
                        "info",
                        s.fn,
                        f"{_name(fn)} calls {s.detail}() on every round of a "
                        f"loop (line {s.line}): fine for short lists, slow (O(n²)) for long ones. A Map or Set "
                        "built once before the loop makes each lookup instant.",
                        line=s.line,
                    )
                )
    advice = {
        "network": "one network request per item. Send one request for all items, or run them together.",
        "read": "one query per item (the N+1 pattern). Load them all with one query (WHERE id IN (…), a JOIN).",
        "file": "one file operation per item. Normal when each item is its own file; if it's the same file each "
        "time, read it once before the loop.",
        "write": "one write per item. Fine for a few inside one transaction; for many, batch them (one multi-row "
        "INSERT/UPDATE) and make sure they share a transaction.",
    }
    explained: dict[str, set[int]] = defaultdict(set)  # lines an await check would only repeat
    for (fid, what), lines in loop_io.items():
        fn = by_id.get(fid)
        if not fn:
            continue
        explained[fid].update(lines)
        where = f"line {lines[0]}" + (f" and {len(lines) - 1} more" if len(lines) > 1 else "")
        sink = reach[what][1] if what in by_id else what
        kind = kind_of(sink)
        sev = "warn" if kind in ("network", "read") else "info"
        fixed = (fid, what) not in unbounded
        migration = "migration" in fn.file.lower()
        if fixed or migration:  # can't grow with the data: worth knowing, not worth fixing
            sev = "info"
        note = (
            " It loops over a list fixed in the code, so the number of calls can't grow with the data: fine as "
            "is unless that list gets long."
            if fixed
            else " It's in a migration, which runs once per upgrade."
            if migration
            else ""
        )
        if what in by_id:  # one of the codebase's functions that reaches I/O
            out.append(
                Flag(
                    "io_in_loop",
                    sev,
                    fid,
                    f"{_name(fn)} calls {by_id[what].qualname}() inside a loop ({where}), "
                    f"and that reaches {called(sink)}: {advice[kind]}{note}",
                    [what],
                    line=lines[0],
                )
            )
        else:
            out.append(
                Flag(
                    "io_in_loop",
                    sev,
                    fid,
                    f"{_name(fn)} calls {called(what)} inside a loop ({where}): {advice[kind]}{note}",
                    line=lines[0],
                )
            )
    for fid, all_lines in awaits.items():
        fn = by_id.get(fid)
        lines = [ln for ln in all_lines if ln not in explained[fid]]
        if fn and lines:
            out.append(
                Flag(
                    "sequential_await",
                    "info",
                    fid,
                    f"{_name(fn)} awaits inside a loop (line "
                    f"{', '.join(map(str, lines[:5]))}): each round waits for the last. If they don't "
                    "depend on each other, start them together (Promise.all / asyncio.gather).",
                    line=lines[0],
                )
            )
    return out
