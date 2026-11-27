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


def _path_names(start: str, reach: dict, by_id: dict) -> list[str]:
    """The names of the functions from `start` to the one doing the I/O."""
    names, cur, seen = [], start, set()
    while cur in by_id and cur not in seen:
        seen.add(cur)
        names.append(by_id[cur].name)
        nxt = reach.get(cur, (cur,))[0]
        if nxt == cur:
            break
        cur = nxt
    return names


def _name(fn) -> str:
    return f"top-level code in {fn.file.split('/')[-1]}" if fn.kind == "module" else fn.qualname


NETWORK = re.compile(r"(^|\.)(fetch|urlopen)$|axios|requests\.|httpx|aiohttp|http|supabase|firestore", re.I)
READS = re.compile(
    r"getAll|getFirst|getEach|fetchone|fetchall|fetchmany|(^|\.)(query\w*|rawQuery|Query\w*|select|find\w*|get|getItem\w*|"
    r"read\w*|scalars?|from)$|objects\.(get|filter|all)|\(.SELECT",
    re.I,
)


FILES = re.compile(
    r"readFile|writeFile|appendFile|readdir|(^|\.)stat(Sync)?$|read_text|write_text|read_bytes|"
    r"write_bytes|AsStringAsync|downloadAsync|downloadFileAsync|uploadAsync|^open$|iterdir|r?glob$|shutil\.|"
    r"(^|\.)(copy2?|copyfile|copytree|move|rename|replace|unlink|remove|rmtree|mkdir|makedirs|rmdir|touch|"
    r"copyFile|copyAsync|moveAsync|deleteAsync|makeDirectoryAsync)$",
    re.I,
)


WAIT = re.compile(r"(^|\.)(sleep|wait|setTimeout|delay)$")
PROCESS = re.compile(r"subprocess\.|(^|\.)(system|popen|spawn|execSync|execFile|exec_command)$|child_process", re.I)


def called(x: str) -> str:
    return x if x.endswith(")") else f"{x}()"


def kind_of(sink: str) -> str:
    """wait | process | network | file | read | write: how much a call in a loop costs. Network and database reads are
    the classic N+1; files one by one are normal in scripts; writes one at a time are slower than a batch but usually
    fine inside one transaction; a sleep in a loop is pacing on purpose."""
    if WAIT.search(sink):
        return "wait"
    if PROCESS.search(sink):
        return "process"
    if NETWORK.search(sink):
        return "network"
    if FILES.search(sink):
        return "file"
    if READS.search(sink):
        return "read"
    # a write only when the call says so (an INSERT, save, commit, put, set…): an I/O-looking call that says neither
    # (`resolve_attribute`, `add_line`, `preg_match` reached by a name match) was the source of most wrong "writes
    # inside loops" on the corpus
    return "write" if WRITE_SQL.search(sink) or WRITE_CALL.search(sink) else "other"


WRITE_CALL = re.compile(r"(^|\.)(?:insert\w*|update\w*|upsert\w*|save\w*|delete\w*|destroy|remove\w*|create\w*|put\w*|"
                        r"set\w*|write\w*|append\w*|add\w*|commit|persist|flush|exec(?:ute)?\w*|send\w*|post\w*|"
                        r"patch\w*|store\w*|push\w*|incr\w*|decr\w*|expire|publish|enqueue|Exec\w*|Update\w*|"
                        r"Save\w*|Delete\w*|Insert\w*|Create\w*|Set\w*|Put\w*|Add\w*|run(?:Async|Sync)?|transact\w*)\b")
WRITE_SQL = re.compile(r"INSERT|UPDATE|DELETE|REPLACE|UPSERT|commit|save|put|set|write|create|add|remove|delete", re.I)
READ_NAME = re.compile(r"^_?(read|get|load|fetch|list|find|count|select|query|lookup|latest|recent|stored)", re.I)


def kind_through(sink: str, path: list[str]) -> str:
    """kind_of, using the names of the functions on the way as a hint when the call itself doesn't say: a
    `conn.execute(sql)` reached through `read_snapshots` is a read, not a write."""
    kind = kind_of(sink)
    if kind == "write" and not WRITE_SQL.search(sink) and any(READ_NAME.match(n) for n in path):
        return "read"
    return kind


TX_WRAPPER = re.compile(r"transaction|atomic|withTransaction|writeTxn", re.I)


def in_transaction(g: Graph) -> set[str]:
    """Functions that always run inside a transaction: every call to them is made inside a transaction block, or by a
    function that itself always runs in one (route -> service -> repository), followed to a fixed point."""
    tx_calls: dict[tuple[str, str], int] = defaultdict(int)
    for s in g.sites:
        if s.kind == "tx_call" or (s.kind == "loop_call" and s.tx):
            tx_calls[(s.fn, s.target)] += 1
    callers: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for e in g.edges:
        if e.kind == "call":
            callers[e.dst].append((e.src, e.count))
    inside: set[str] = set()
    changed = True
    while changed:  # each round can only add, so this ends; each added function is justified by the ones before it
        changed = False
        for dst, srcs in callers.items():
            if dst not in inside and all(src in inside or tx_calls.get((src, dst), 0) >= n for src, n in srcs):
                inside.add(dst)
                changed = True
    return inside


def efficiency_flags(g: Graph) -> list[Flag]:
    """Test files are left out: a loop of setup calls in a test isn't a problem anyone ships."""
    by_id = {f.id: f for f in g.functions}
    reach = io_reach(g)
    out: list[Flag] = []
    loop_io: dict[tuple[str, str], list[int]] = defaultdict(list)  # (fn, what) -> lines
    unbounded: set[tuple[str, str]] = set()  # (fn, what) with at least one loop whose length depends on data
    outside_tx: set[tuple[str, str]] = set()  # (fn, what) with at least one call not inside a transaction
    awaits: dict[str, list[int]] = defaultdict(list)
    always_tx = in_transaction(g)
    for s in g.sites:
        if s.fn not in by_id or is_test(by_id[s.fn].file):
            continue
        if s.kind in ("loop_io", "loop_call"):
            key = (s.fn, s.detail if s.kind == "loop_io" else s.target)
            if s.kind == "loop_call" and (
                s.target not in reach or TX_WRAPPER.search(by_id[s.target].name if s.target in by_id else "")
            ):
                continue  # nothing to reach, or the transaction helper itself (calling it per batch is the batching)
            loop_io[key].append(s.line)
            if not s.bounded:
                unbounded.add(key)
            if not (s.tx or s.fn in always_tx):
                outside_tx.add(key)
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
        "process": "one program run per item. Fine for a handful; for many, pass them all to one run if the "
        "program accepts several.",
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
        kind = kind_through(sink, _path_names(what, reach, by_id))
        if kind in ("wait", "other"):
            continue  # sleeping between rounds is pacing (rate limits, polling); `other` isn't known to be I/O at all
        if kind == "write" and (fid, what) not in outside_tx:
            continue  # writes batched inside one transaction: the advice would be to do what it already does
        sev = "warn" if kind in ("network", "read") else "info"
        fixed = (fid, what) not in unbounded
        migration = "migration" in fn.file.lower() or "migrat" in fn.name.lower()
        if fixed or migration:  # can't grow with the data: worth knowing, not worth fixing
            sev = "info"
        note = (
            " It loops over a list fixed in the code, or runs once at startup or in a migration, so the number of "
            "calls can't grow with the data: fine as "
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
                    detail=kind + (":fixed" if fixed or migration else ""),
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
                    detail=kind + (":fixed" if fixed or migration else ""),
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
