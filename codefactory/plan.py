"""From issues to work: ranked tasks, each with where, concrete steps, the tests to run, how to know it's done, and a
self-contained prompt for Claude Code (or any agent). Related issues become one task: a group of copies is one merge,
a function's loop calls are one batching job, dead code is one cleanup.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from .brief import View
from .paths import is_script, is_test

BASE = {
    "cycle": 90,
    "layer_violation": 80,
    "io_in_loop": 70,
    "duplicate": 60,
    "similar": 45,
    "unused": 35,
    "sequential_await": 18,
    "quadratic_scan": 14,
    "test_only": 12,
    "long_function": 8,
}
SCRIPT_EXT = (".js", ".mjs", ".cjs", ".jsx")


def batch_name(name: str, file: str) -> str:
    """The batched variant's name in the code's own style: get_order -> get_orders_batch(ids), getOrder -> getOrderMany(ids)."""
    if "_" in name or name.islower() or file.endswith((".py", ".rb", ".rs", ".ex", ".exs")):
        return f"{name}_batch(ids)"
    return f"{name}Many(ids)"


def _id(kind: str, parts: list[str]) -> str:
    return hashlib.sha1(f"{kind}|{'|'.join(sorted(parts))}".encode("utf-8", "surrogatepass")).hexdigest()[:6]


class Planner:
    def __init__(self, g: dict, changes: dict[str, int] | None = None):
        self.g, self.v = g, View(g)
        self.changes = changes or {}  # file -> commits in the last 12 months (hotspots.py)
        self.layer_rank = {name: i for i, name in enumerate(g["layers"])}  # right = more depended upon
        self.idx = {id(f): i for i, f in enumerate(g["flags"])}
        from .owners import load as load_owners

        self.owners = load_owners(Path(g["root"])) if g.get("root") and Path(g["root"]).is_dir() else None

    # -- helpers ---------------------------------------------------------------------------------------------------
    def at(self, fid: str, line: int | None = None) -> dict:
        fn = self.v.fn.get(fid)
        if not fn:
            return {"file": fid, "line": line or 0, "name": ""}
        return {"file": fn["file"], "line": line or fn["line"], "name": "" if fn["kind"] == "module" else fn["qualname"]}

    def callers_of(self, fid: str) -> list[str]:
        return sorted({self.v.where(e["src"]) for e in self.v.callers[fid]})

    def tests_for(self, ids: list[str]) -> list[str]:
        dep = self.v.dependents(ids) | set(ids)
        files = {self.v.fn[d]["file"] for d in dep if d in self.v.fn}
        for i in ids:
            fn = self.v.fn.get(i)
            if fn:
                files |= self.v.importers.get(fn["file"], set())
        return sorted(f for f in files if is_test(f))[:12]

    def weight(self, files: list[str]) -> float:
        """Tests and one-off scripts matter less than the product's code."""
        if files and all(is_test(f) for f in files):
            return 0.3
        if files and all(is_script(f) for f in files):
            return 0.5
        return 1.0

    @staticmethod
    def fmt(w: dict) -> str:
        return f"`{w['file']}:{w['line']}`" + (f" {w['name']}" if w["name"] else "")

    # -- tasks -----------------------------------------------------------------------------------------------------
    def copies(self) -> list[dict]:
        out, seen = [], set()
        for f in self.g["flags"]:
            if f["kind"] not in ("duplicate", "similar"):
                continue
            group = frozenset([f["target"], *f.get("related", [])])
            if group in seen:
                continue
            seen.add(group)
            members = [self.v.fn[i] for i in group if i in self.v.fn]
            if len(members) < 2:
                continue
            flags = [x for x in self.g["flags"] if x["kind"] == f["kind"] and x["target"] in group]
            exact = f["kind"] == "duplicate"
            # keep the copy in the layer the others can depend on (rightmost), then the most-called one
            home = max(
                members,
                key=lambda m: (
                    not is_test(m["file"]),
                    self.layer_rank.get(self.v.file[m["file"]]["layer"], 0),
                    not m["file"].endswith(SCRIPT_EXT),
                    len(self.v.callers[m["id"]]),
                ),
            )
            others = [m for m in members if m is not home]
            code = lambda m: max(1, m["loc"] - m.get("doc", 0))  # noqa: E731  docstrings aren't copied logic
            saved = sum(code(m) for m in members) - max(code(m) for m in members)
            # different names in one file: kept apart on purpose (separate entry points); share the body instead
            # (each name used or exported: a copy nobody calls is just a copy to delete)
            named_apart = (
                len({m["file"] for m in members}) == 1
                and len({m["name"] for m in members}) == len(members)
                and all(self.v.callers[m["id"]] or m.get("exported") or m.get("public") for m in members)
            )
            sim = "identical" if exact else f"{round(max(x.get('score', 0) for x in flags) * 100)}% similar"
            if named_apart:
                names = ", ".join(f"`{m['qualname']}`" for m in members)
                steps = [
                    f"{names} in `{home['file']}` have the same body under different names, which usually means "
                    "separate entry points kept on purpose: keep every name.",
                    "Move the shared body into one private helper in the same file and make each of them a one-line "
                    "call to it (keep their docstrings), so a fix to the body reaches all of them.",
                    "If they're expected to diverge, silence it instead: `codefactory: ignore duplicate — <why>`.",
                ]
            else:
                steps = [
                    f"Keep `{home['qualname']}` in `{home['file']}:{home['line']}` as the one version "
                    f"(layer {self.v.file[home['file']]['layer']}, which the other copies' callers can import)."
                ]
            if not exact:
                steps.append(
                    "The copies differ: compare them line by line, and fold each difference into a parameter "
                    "(or keep the variant every caller needs) before merging."
                )
            for m in [] if named_apart else others:
                callers = self.callers_of(m["id"])
                steps.append(
                    f"Replace `{m['qualname']}` in `{m['file']}:{m['line']}` with an import of the kept one; "
                    f"its callers: {', '.join(f'`{c}`' for c in callers[:6]) or 'none found'}"
                    + (" …" if len(callers) > 6 else "")
                    + ". Then delete it."
                )
                if m["file"].endswith(SCRIPT_EXT) != home["file"].endswith(SCRIPT_EXT):
                    steps.append(
                        f"Note: `{m['file']}` is plain JavaScript and `{home['file']}` isn't (or the other way "
                        "round), so one may not be able to import the other directly. Either move the shared "
                        "function into a module both can import, or keep both and silence this with "
                        "`codefactory: ignore duplicate — <why>` above one of them."
                    )
            files = [m["file"] for m in members]
            score = (BASE["duplicate"] if exact else BASE["similar"]) + min(25, saved) + 3 * len(others)
            out.append(
                self.task(
                    f["kind"],
                    [m["id"] for m in members],
                    score * self.weight(files),
                    f"Share one body between {', '.join(sorted(m['name'] for m in members))} ({sim}, ~{saved} lines)"
                    if named_apart
                    else f"Merge {len(members)} copies of {home['qualname']} ({sim}, ~{saved} lines)",
                    f"The same logic lives in {len(members)} places ({sim}). A fix in one copy silently misses "
                    f"the others; merging saves ~{saved} lines.",
                    [self.at(m["id"]) for m in members],
                    steps,
                    [m["id"] for m in members],
                    f"codefactory flags --kind {f['kind']}",
                    flags,
                )
            )
        return out

    def loops(self) -> list[dict]:
        out = []
        by_fn = defaultdict(list)
        for f in self.g["flags"]:
            if f["kind"] == "io_in_loop":
                by_fn[f["target"]].append(f)
        for fid, flags in by_fn.items():
            fn = self.v.fn.get(fid)
            if not fn:
                continue
            warn = any(f["severity"] == "warn" for f in flags)
            name = self.at(fid)["name"] or f"top-level code in {fn['file']}"
            where = [self.at(fid, f.get("line")) for f in flags]
            steps = []
            for f in flags:
                callee = f.get("related", [None])[0] if f.get("related") else None
                msg = f["message"].split(": ", 1)
                steps.append(f"Line {f.get('line')}: {msg[0]}.")
                if callee and callee in self.v.fn:
                    c = self.v.fn[callee]
                    steps.append(
                        f"  The I/O happens in `{c['qualname']}` (`{c['file']}:{c['line']}`): add a batched variant "
                        f"that takes all items at once (e.g. `{batch_name(c['name'], c['file'])}`), call it once before "
                        f"the loop, and read results from a {'dict' if c['file'].endswith('.py') else 'Map'} inside "
                        "the loop."
                    )
            if warn:
                steps.append(
                    "Reads / network: collect the keys first, load everything with one query (WHERE id IN (…), "
                    "a JOIN) or one request, then loop over the results in memory."
                )
            else:
                steps.append(
                    "Writes / files: make sure the whole loop runs inside one transaction; if it can be long, "
                    "use one multi-row INSERT/UPDATE. If the loop is small and bounded, silence it with "
                    "`codefactory: ignore io_in_loop — <why>`."
                )
            score = (BASE["io_in_loop"] if warn else 25) + 4 * (len(flags) - 1) + min(10, len(self.v.callers[fid]))
            out.append(
                self.task(
                    "io_in_loop",
                    [fid],
                    score * self.weight([fn["file"]]),
                    f"{'Batch the queries' if warn else 'Batch the writes'} in {name}",
                    "It talks to the database, network or disk once per item. "
                    + (
                        "With N items that's N round trips where one would do (the N+1 pattern)."
                        if warn
                        else "Usually fine inside one transaction, slow if the loop grows."
                    ),
                    where,
                    steps,
                    [fid],
                    "codefactory flags --kind io_in_loop",
                    flags,
                )
            )
        return out

    def grouped(self, kind: str, title: str, why: str, step: str) -> list[dict]:
        flags = [f for f in self.g["flags"] if f["kind"] == kind]
        code = [f for f in flags if not is_test(self.at(f["target"])["file"])]
        if not code:
            return []
        where = [self.at(f["target"], f.get("line")) for f in code]
        steps = [step] + [f"{self.fmt(w)}: {f['message']}" for w, f in zip(where, code, strict=True)]
        ids = [f["target"] for f in code]
        return [
            self.task(
                kind,
                ids,
                BASE[kind] + min(20, 2 * len(code)),
                title.format(n=len(code)),
                why,
                where,
                steps,
                ids,
                f"codefactory flags --kind {kind}",
                code,
            )
        ]

    def per_flag(self, kind: str, title, why: str, steps_for) -> list[dict]:
        out = []
        for f in self.g["flags"]:
            if f["kind"] != kind:
                continue
            w = self.at(f["target"], f.get("line"))
            out.append(
                self.task(
                    kind,
                    [f["target"], str(f.get("line"))],
                    BASE[kind] * self.weight([w["file"]]),
                    title(f, w),
                    why,
                    [w],
                    steps_for(f, w),
                    [f["target"]],
                    f"codefactory flags --kind {kind}",
                    [f],
                )
            )
        return out

    def cycles(self) -> list[dict]:
        out, seen = [], set()
        for f in self.g["flags"]:
            if f["kind"] != "cycle":
                continue
            group = frozenset([f["target"], *f.get("related", [])])
            if group in seen:
                continue
            seen.add(group)
            files = sorted(group)
            flags = [x for x in self.g["flags"] if x["kind"] == "cycle" and x["target"] in group]
            steps = [
                "Find the import that closes the loop: for each file below, check which of the others it imports "
                "(`codefactory context <file>` lists imports).",
                "Move what both sides need into a new module that imports neither, or pass the dependency in "
                "(a parameter or callback) instead of importing it.",
                *[f"`{x}`" for x in files],
            ]
            out.append(
                self.task(
                    "cycle",
                    files,
                    BASE["cycle"] + 2 * len(files),
                    f"Break the import loop between "
                    f"{len(files)} files ({', '.join(x.split('/')[-1] for x in files[:3])}{' …' if len(files) > 3 else ''})",
                    "Files that import each other load in a fragile order and can't be understood or tested alone.",
                    [{"file": x, "line": 1, "name": ""} for x in files],
                    steps,
                    [],
                    "codefactory flags --kind cycle",
                    flags,
                )
            )
        return out

    def task(self, kind, key_parts, score, title, why, where, steps, ids, verify, flags) -> dict:
        tests = self.tests_for([i for i in ids if i in self.v.fn])
        t = {
            "id": _id(kind, key_parts),
            "kind": kind,
            "score": round(score, 1),
            "severity": min((f["severity"] for f in flags), key=["high", "warn", "info"].index),
            "title": title,
            "why": why,
            "where": where,
            "steps": steps,
            "tests": tests,
            "verify": verify,
            "flags": sorted(self.idx[id(f)] for f in flags if id(f) in self.idx),
        }
        if self.owners:  # who to hand it to (CODEOWNERS)
            t["owners"] = sorted({o for w in where for o in self.owners.of(w["file"])})
        t["prompt"] = prompt_for(t)
        return t

    def plan(self) -> list[dict]:
        tasks = [*self.cycles()]
        tasks += self.per_flag(
            "layer_violation",
            lambda f, w: f"Remove the forbidden import in {w['file'].split('/')[-1]}",
            "factory.toml forbids this layer from importing that one.",
            lambda f, w: [
                f["message"],
                "Move the code that needs it into an allowed layer, or invert the "
                "dependency (pass it in), then remove the import.",
            ],
        )
        tasks += self.loops() + self.copies()
        tasks += self.grouped(
            "unused",
            "Remove {n} unused functions",
            "Dead code costs reading time and keeps dependencies alive.",
            "For each: search the repo for its name, including in strings and "
            "config (frameworks can call code by name). If nothing uses it, delete it; if something does, "
            "silence it with `codefactory: ignore unused — <who calls it>`.",
        )
        tasks += self.grouped(
            "test_only",
            "Decide on {n} functions only tests call",
            "They're dead in the product but kept alive by tests.",
            "For each: if the product should use it, wire it in; if not, delete "
            "it and its tests; if it's a test helper, move it next to the tests.",
        )
        tasks += self.per_flag(
            "sequential_await",
            lambda f, w: f"Run independent awaits together in {w['name'] or w['file']}",
            "Each round of the loop waits for the previous one.",
            lambda f, w: [
                f["message"],
                "If the iterations don't depend on each other (and aren't "
                "ordered writes on one connection), start them all and await Promise.all / "
                "asyncio.gather, with a concurrency limit for network calls.",
            ],
        )
        scans = defaultdict(list)
        for f in self.g["flags"]:
            if f["kind"] == "quadratic_scan":
                scans[self.at(f["target"])["file"]].append(f)
        for file, flags in scans.items():
            where = [self.at(f["target"], f.get("line")) for f in flags]
            tasks.append(
                self.task(
                    "quadratic_scan",
                    [file],
                    (BASE["quadratic_scan"] + len(flags)) * self.weight([file]),
                    f"Replace {len(flags)} search(es) in loops in {file.split('/')[-1]}",
                    "Searching an array inside a loop is O(n²): fine for short lists, slow for long ones.",
                    where,
                    [
                        "Only worth it if these lists can grow past a few hundred items. Build a Map "
                        "or Set once before the loop and look items up in it:"
                    ]
                    + [f"{self.fmt(w)}: {f['message'].split(':')[0]}" for w, f in zip(where, flags, strict=True)],
                    [f["target"] for f in flags],
                    "codefactory flags --kind quadratic_scan",
                    flags,
                )
            )
        tasks += self.per_flag(
            "long_function",
            lambda f, w: f"Split {w['name']} ({self.v.fn[f['target']]['loc']} lines)",
            "Long functions are hard to read, test and change safely.",
            lambda f, w: [
                f"{self.fmt(w)} is {self.v.fn[f['target']]['loc']} lines.",
                "Pull out the parts that have a name of their own (a calculation, a block of "
                "UI, a load/save step) into separate functions; keep behaviour identical.",
            ],
        )
        if self.changes:  # the same problem costs more where people keep working: up to twice the score
            for task in tasks:
                n = max((self.changes.get(w["file"], 0) for w in task["where"]), default=0)
                if n >= 3:
                    task["changes"] = n
                    task["score"] = round(task["score"] * (1 + min(n, 20) / 20), 1)
        tasks.sort(key=lambda t: (-t["score"], t["title"]))
        return tasks


def prompt_for(t: dict) -> str:
    where = "\n".join(f"- {Planner.fmt(w)}" for w in t["where"][:15]) + (
        f"\n- … {len(t['where']) - 15} more" if len(t["where"]) > 15 else ""
    )
    steps = "\n".join(f"{i}. {s}" if not s.startswith("  ") else f"   {s.strip()}" for i, s in enumerate(t["steps"], 1))
    tests = (
        ("\n".join(f"- {x}" for x in t["tests"]) + "\n- and the project's full test command")
        if t["tests"]
        else "- the project's full test command"
    )
    return f"""Task (codefactory plan {t["id"]}): {t["title"]}

Why: {t["why"]}

Where:
{where}

Steps:
{steps}

Constraints:
- Keep behaviour identical. Make the smallest change that does the job.
- Don't rename or change the signature of anything other code calls unless you update every caller
  (`codefactory context <name>` lists them, with the tests that exercise it).

Done when:
- `{t["verify"]}` no longer lists these
- These tests pass:
{tests}
"""


def make_plan(g: dict, changes: dict[str, int] | None = None) -> list[dict]:
    """Ranked tasks; with `changes` (commits per file), work in code that keeps changing ranks higher."""
    return Planner(g, changes).plan()


def plan_markdown(tasks: list[dict], top: int) -> str:
    lines = [
        f"# Plan: {len(tasks)} tasks, highest payoff first",
        "",
        "Each has an id: `codefactory prompt <id>` prints a ready-to-paste prompt for Claude Code.",
        "",
    ]
    for i, t in enumerate(tasks[:top], 1):
        hot = f" · changed {t['changes']}× in 12 months" if t.get("changes") else ""
        lines.append(f"## {i}. {t['title']}  `{t['id']}` · {t['severity']} · score {t['score']}{hot}")
        lines.append(t["why"])
        lines += [""] + [f"- [ ] {s}" if not s.startswith("  ") else f"      {s.strip()}" for s in t["steps"][:12]]
        if len(t["steps"]) > 12:
            lines.append(f"- [ ] … {len(t['steps']) - 12} more (see the prompt)")
        if t["tests"]:
            lines.append(f"- [ ] Run: {', '.join(t['tests'][:6])}{' …' if len(t['tests']) > 6 else ''}")
        lines.append(f"- [ ] Check: `{t['verify']}`")
        lines.append("")
    if len(tasks) > top:
        lines.append(f"… {len(tasks) - top} more tasks: `codefactory plan --top {len(tasks)}`")
    return "\n".join(lines) + "\n"
