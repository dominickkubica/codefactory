"""Change prefetch: before an agent starts, locate what its prompt names.

A Claude Code `UserPromptSubmit` hook. For each function, command, route or module the prompt names, it adds the
definition (file and lines), its callers and calls, the tests that exercise it, where the name appears as a string
(an argparse command, a registry key) and the docs that mention it: what an agent otherwise spends its first turns
searching for. It answers from an index built ahead of time (`codefactory prefetch --build`), so the hook takes
milliseconds, and leaves out anything in a file changed since the index was built (its line numbers may have moved).

    {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "codefactory prefetch --hook"}]}]}}
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

INDEX = "prefetch.json"
#: Most that is injected, in characters (about 750 tokens).
BUDGET = 3000
#: Names that commands, handlers and jobs are given around the word the user types (`_cmd_forward_test`).
PREFIXES = ("cmd_", "command_", "handle_", "handler_", "do_", "run_", "api_", "on_", "job_", "task_")
DOC_SUFFIXES = (".md", ".rst", ".txt")
WORD = re.compile(r"/?[A-Za-z_][\w./{}:-]*[\w}]")
#: A short word in backticks (`list`) names a command (`_cmd_list`), not every function called that; from this
#: length it names a function too. Plain words outside backticks never count: English ("parallel", "configured")
#: matched unrelated functions in a large codebase.
PLAIN_MIN = 8
#: Findings about size and shape, not behaviour: noise when locating what a prompt is about.
STYLE = frozenset({"long_function", "complex", "deep_nesting", "long_file", "god_file", "many_params"})
MAX_PER_NAME = 3  # a name matching more functions than this is too common to say anything about


def bare(name: str) -> str:
    """`_cmd_forward_test` -> `forward_test`; `forwardTest` -> `forward_test`."""
    n = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower().lstrip("_")
    for p in PREFIXES:
        if n.startswith(p) and len(n) > len(p):
            return n[len(p) :]
    return n


# -- building the index ------------------------------------------------------------------------------------------------


def build(root: Path, graph: dict) -> dict:
    from .brief import View
    from .paths import is_test, walk
    from .security import find_entries

    v = View(graph)
    test_files = {f["id"] for f in graph["files"] if is_test(f["id"])}
    out_edges: dict[str, set[str]] = {}
    for e in graph["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], set()).add(e["dst"])
    # which test files reach each function: a walk from each test file's functions (few files, so cheap)
    reached_by: dict[str, set[str]] = {}
    direct: dict[str, set[str]] = {}
    for tf in test_files:
        start = [f["id"] for f in v.fns_in.get(tf, [])] + [f"{tf}::<module>"]
        seen, todo = set(start), list(start)
        for s in start:
            for d in out_edges.get(s, ()):
                direct.setdefault(d, set()).add(tf)
        while todo:
            for nxt in out_edges.get(todo.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
        for fid in seen:
            reached_by.setdefault(fid, set()).add(tf)

    def tests(fid: str, file: str) -> list[str]:
        first = sorted(direct.get(fid, set()))  # tests that call it themselves, then ones importing its file
        second = sorted((v.importers.get(file, set()) & test_files) - set(first))
        rest = sorted(reached_by.get(fid, set()) - set(first) - set(second))
        return (first + second + rest)[:4]

    def short(fid: str) -> str:
        f = v.fn.get(fid)
        if not f:
            return fid
        name = f["qualname"] if f["kind"] != "module" else "(top level)"
        return f"{name} {f['file']}:{f['line']}"

    def product(ids: set[str]) -> list[str]:  # callers outside tests (tests are listed on their own)
        return sorted(i for i in ids if not is_test(i.split("::")[0]))

    functions = []
    for f in graph["functions"]:
        if f["kind"] == "module" or is_test(f["file"]):
            continue
        callers = product({e["src"] for e in v.callers[f["id"]]})
        refs = product({e["src"] for e in v.refs_in[f["id"]]} - set(callers))
        functions.append(
            {
                "name": f["name"],
                "qualname": f["qualname"],
                "file": f["file"],
                "line": f["line"],
                "end": f["end"],
                "callers": [short(c) for c in callers[:3]] + [f"{short(c)} (by reference)" for c in refs[:2]],
                "callers_total": len(callers) + len(refs),
                "calls": [short(c) for c in sorted({e["dst"] for e in v.callees[f["id"]]})[:4]],
                "tests": tests(f["id"], f["file"]),
                # what codefactory found wrong with it (a handler nothing calls, a query in a loop…)
                "issues": [
                    f"{fl['kind']}: {fl['message'][:120]}" for fl in v.flags_on.get(f["id"], []) if fl["kind"] not in STYLE
                ][:3],
            }
        )
    modules = {}
    for f in graph["files"]:
        if is_test(f["id"]):
            continue
        stem = Path(f["id"]).stem
        if stem in ("__init__", "index", "main", "mod"):
            continue
        reach = (
            set().union(*(reached_by.get(fn["id"], set()) for fn in v.fns_in.get(f["id"], [])))
            if v.fns_in.get(f["id"])
            else set()
        )
        mtests = sorted(v.importers.get(f["id"], set()) & test_files) or sorted(reach)
        main = sorted(
            (fn for fn in v.fns_in.get(f["id"], []) if fn["kind"] != "module"),
            key=lambda fn: (-len(v.callers[fn["id"]]) - fn["loc"] / 20, fn["line"]),
        )[:4]
        defines = [f"{fn['qualname']} {fn['line']}-{fn['end']}" for fn in sorted(main, key=lambda fn: fn["line"])]
        modules.setdefault(stem, []).append({"file": f["id"], "tests": mtests[:4], "defines": defines})
    routes = []
    try:
        for e in find_entries(root, graph, v):
            fn = v.fn.get(e.fn, {})
            routes.append(
                {
                    "method": e.method,
                    "path": e.path,
                    "file": e.file,
                    "line": e.line,
                    "end": fn.get("end", e.line),
                    "handler": fn.get("qualname", ""),
                    "tests": tests(e.fn, e.file),
                }
            )
    except Exception:  # routes are a bonus: a framework the finder trips on mustn't lose the rest
        pass
    sources = sorted(f["id"] for f in graph["files"])
    docs = sorted(p for p in walk(root, suffixes=DOC_SUFFIXES) if not p.startswith(".") and "/." not in p)[:400]
    stamps = {}
    for rel in set(sources) | set(docs):
        try:
            st = os.stat(root / rel)
            stamps[rel] = [st.st_size, st.st_mtime_ns, _digest(root / rel)]
        except OSError:
            pass
    return {"version": 1, "functions": functions, "modules": modules, "routes": routes, "sources": sources,
            "docs": docs, "stamps": stamps}  # fmt: skip


def index_path(root: Path) -> Path | None:
    from .paths import cache_dir

    d = cache_dir(root)
    return d / INDEX if d else None


def write_index(root: Path, graph: dict) -> Path:
    from .paths import write_file

    path = index_path(root)
    if path is None:
        raise OSError("no usable .codefactory/ folder to keep the index in")
    path.parent.mkdir(exist_ok=True)
    write_file(path, json.dumps(build(root, graph), separators=(",", ":")))
    return path


# -- answering a prompt ------------------------------------------------------------------------------------------------


def names(prompt: str) -> tuple[set[str], set[str]]:
    """(keys to match definitions on, in bare form; phrases to look for as text: strings in code, words in docs)."""
    quoted = re.findall(r"`([^`\n]{2,80})`", prompt)
    keys: set[str] = set()
    phrases: set[str] = set()
    for span in quoted:
        words = span.split()
        phrases.add(span)
        for n in (1, 2, 3):
            for i in range(len(words) - n + 1):
                part = words[i : i + n]
                if all(re.fullmatch(r"[\w./-]+", w) for w in part):
                    keys.add("_".join(bare(w.replace("-", "_")) for w in part))
                    if n > 1:
                        phrases.add(" ".join(part))
    for w in WORD.findall(prompt):
        # a hyphen alone ("built-in") is English; in backticks (`forward-test`) it was counted above
        special = bool(re.search(r"[_./]|[a-z][A-Z]", w))
        if special:
            keys.add(bare(w.replace("-", "_")))
            phrases.add(w)
    keys = {k for k in keys if len(k) >= 3}
    phrases = {p for p in phrases if len(p) >= 4}
    return keys, phrases


def _digest(path: Path) -> str:
    import hashlib

    return hashlib.sha1(path.read_bytes()).hexdigest()


def _fresh(root: Path, index: dict, rel: str, _seen: dict = {}) -> bool:  # noqa: B006 (a per-process memo)
    """The file is as it was indexed: same size and time, or (a checkout rewrote it) the same bytes."""
    key = (str(root), rel)
    if key not in _seen:
        was = index["stamps"].get(rel)
        try:
            st = os.stat(root / rel)
            _seen[key] = bool(was) and st.st_size == was[0] and (st.st_mtime_ns == was[1] or _digest(root / rel) == was[2])
        except OSError:
            _seen[key] = False
    return _seen[key]


def _lines(root: Path, rel: str) -> list[str]:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def answer(root: Path, index: dict, prompt: str) -> str:
    keys, phrases = names(prompt)
    if not keys and not phrases:
        return ""
    fresh = lambda rel: _fresh(root, index, rel)  # noqa: E731
    items: list[str] = []

    def fn_line(f: dict) -> str:
        out = f"- `{f['qualname']}` {f['file']}:{f['line']}-{f['end']}"
        if f["callers"]:
            more = f" (+{f['callers_total'] - len(f['callers'])})" if f["callers_total"] > len(f["callers"]) else ""
            out += f"; called by: {', '.join(f['callers'])}{more}"
        if f["calls"]:
            out += f"; calls: {', '.join(f['calls'])}"
        if f["tests"]:
            out += f"; tests: {', '.join(f['tests'])}"
        if f.get("issues"):
            out += f"; codefactory found: {'; '.join(f['issues'])}"
        return out

    # functions, best names first: a longer key (forward_test) says more than a short one (report)
    by_key: dict[str, list[dict]] = {}
    for f in index["functions"]:
        for k in {bare(f["name"]), bare(f["qualname"].replace(".", "_"))}:
            # a short word (`health`, `list`) names a command (`_cmd_health`), not every function called that
            if k in keys and ("_" in k or len(k) >= PLAIN_MIN or f["name"].lower().lstrip("_") != k):
                by_key.setdefault(k, []).append(f)
    shown = set()
    for k in sorted(by_key, key=lambda k: (-k.count("_"), -len(k))):
        hits = [f for f in by_key[k] if fresh(f["file"])]
        if not hits or len(hits) > MAX_PER_NAME:
            continue
        for f in hits:
            if (f["file"], f["line"]) not in shown:
                shown.add((f["file"], f["line"]))
                items.append(fn_line(f))
    for r in index["routes"]:
        # a prompt's /api/gaps reaches a router's /gaps; a bare / says nothing
        p = r["path"].rstrip("/")
        named = any(c == p or (c.endswith(p) and c[: -len(p)].count("/") <= 2) for c in phrases if c.startswith("/"))
        if p and named and fresh(r["file"]) and (r["file"], r["line"]) not in shown:
            shown.add((r["file"], r["line"]))
            t = f"; tests: {', '.join(r['tests'])}" if r["tests"] else ""
            items.append(f"- route {r['method']} {r['path']}: `{r['handler']}` {r['file']}:{r['line']}-{r['end']}{t}")
    for k in sorted(keys):
        for m in index["modules"].get(k, []):
            t = f"; tests: {', '.join(m['tests'])}" if m["tests"] else ""
            d = f"; defines: {', '.join(m['defines'])}" if m.get("defines") else ""
            items.append(f"- module {m['file']}{d}{t}")
    # where the names appear as strings in code (a CLI command, a registry key), and where a name is assigned at
    # the top of a module (a signal, a setting, a registry): one pass over the source, each file read once
    texts = sorted({p for p in phrases if not p.startswith("/") or p.count("/") > 1}, key=len, reverse=True)
    # a command line (`optscan position list`) is registered word by word: look for each word after the program's
    literals = sorted({w for p in texts for w in (p.split()[1:] if " " in p else [p]) if len(w) >= 4}, key=lambda w: (-len(w), w))
    defined = {p for p in phrases if re.fullmatch(r"[A-Za-z_]\w{3,}", p)}
    quoted = {w: re.compile(r"""["']""" + re.escape(w) + r"""["']""") for w in literals}
    assigned = {w: re.compile(r"^" + re.escape(w) + r"\s*(?::[^=]*)?=(?!=)") for w in defined}
    used = {w: re.compile(r"\b" + re.escape(w) + r"\b") for w in defined}
    hits: dict[tuple[str, str], list[str]] = {}
    for rel in index["sources"]:
        if not fresh(rel):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        wanted = [w for w in set(literals) | defined if w in text]
        if not wanted:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for w in wanted:
                for kind, pats in (("string", quoted), ("assigned", assigned), ("used", used)):
                    pat = pats.get(w)
                    if not pat or not pat.search(line):
                        continue
                    if kind == "used" and (
                        assigned[w].search(line) or line.lstrip().startswith(("import ", "from ", "#", "//", "*", "/*"))
                    ):
                        continue
                    found = hits.setdefault((kind, w), [])
                    if len(found) <= 12:
                        found.append(f"  {rel}:{i}: {line.strip()[:110]}")
    strings: list[str] = []
    for w in sorted(defined):
        found = hits.get(("assigned", w), [])
        if 0 < len(found) <= 3:
            strings.append(f"- `{w}` is defined at:\n" + "\n".join(found))
            uses = hits.get(("used", w), [])
            if uses:
                more = " (first 12)" if len(uses) > 12 else ""
                strings.append(f"- `{w}` is used at{more}:\n" + "\n".join(uses[:12]))
    for w in literals:
        found = hits.get(("string", w), [])
        if 0 < len(found) <= 6:
            strings.append(f'- "{w}" as a string:\n' + "\n".join(found[:4]))
    docs: list[str] = []
    for rel in index["docs"]:
        if not fresh(rel):
            continue
        lines = _lines(root, rel)
        found = [i for i, line in enumerate(lines, 1) if any(p in line for p in texts)]
        if found:
            docs.append(f"{rel}:{','.join(map(str, found[:3]))}")
    items += strings
    if docs:
        items.append(f"- docs mentioning it: {'; '.join(docs[:6])}")
    if not items:
        return ""
    out, used = [], 0
    for item in items:
        if used + len(item) > BUDGET:
            break
        out.append(item)
        used += len(item)
    return (
        "codefactory located what the prompt names (from its call graph; files changed since it was indexed are "
        "left out). Line ranges are exact: read just those lines.\n" + "\n".join(out)
    )


def hook(root: Path) -> int:
    """The hook: the prompt on stdin, extra context (or nothing) on stdout. Never fails the prompt."""
    try:
        prompt = json.load(sys.stdin).get("prompt", "")
        path = index_path(root)
        if not prompt or path is None or not path.exists():
            return 0
        text = answer(root, json.loads(path.read_text(encoding="utf-8")), prompt)
    except Exception:  # a broken index or odd input: the prompt goes ahead without context
        return 0
    if text:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text}}))
    return 0
