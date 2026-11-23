"""codefactory command line: map a codebase, list its issues, query it with SQL, trace calls, brief an AI agent, or
open the factory view."""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analyzers import ANALYZERS, analyze
from .brief import brief_markdown, context_data, context_markdown
from .cache import load_cached, save_cache
from .config import load_config
from .flags import SEVERITY_ORDER, run_flags
from .graph import Flag, Graph
from .layers import assign_layers
from .baseline import baseline_path, compare, read_baseline, write_baseline
from .plan import make_plan, plan_markdown
from .skill import install_skill
from .suppress import apply_suppressions
from .sqlgraph import query_flags, run_query, to_sqlite
from .trace import find_function, shortest_path, trace
from .viewer import render_html


def build(root: Path, languages: list[str] | None = None) -> Graph:
    cfg = load_config(root)
    g = analyze(root, cfg.ignore, languages)
    assign_layers(g, cfg)
    run_flags(g, cfg)
    if cfg.queries:
        g.flags += [Flag(**f) for f in query_flags(g.to_dict(), cfg.queries)]
        g.flags.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.kind, f.target))
    apply_suppressions(g, root, cfg)
    return g


def load_graph(path: Path, languages: list[str] | None = None, cache: bool = True) -> dict:
    """A graph from a saved .json, or by analyzing a folder (reusing .codefactory/graph.json while no source changed)."""
    if path.is_file() and path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if not path.is_dir():
        raise SystemExit(f"codefactory: {path} is not a folder or a graph .json file")
    root = path.resolve()
    ignore = load_config(root).ignore
    if cache and not languages:
        hit = load_cached(root, ignore)
        if hit is not None:
            return hit
    graph = build(root, languages).to_dict()
    if cache and not languages:
        save_cache(root, ignore, graph)
    return graph


def _table(cols: list[str], rows: list[tuple], limit: int = 200) -> str:
    rows = [tuple("" if v is None else str(v) for v in r) for r in rows[:limit]]
    widths = [min(60, max([len(c)] + [len(r[i]) for r in rows])) for i, c in enumerate(cols)]
    line = lambda vals: "  ".join(v[:w].ljust(w) for v, w in zip(vals, widths))  # noqa: E731
    return "\n".join([line(cols), line(["-" * w for w in widths]), *map(line, rows)])


def _write(path: Path, text: str) -> None:
    """Writes an output file, or explains plainly why it can't (the folder doesn't exist, no permission)."""
    if not path.parent.exists():
        raise SystemExit(f"codefactory: can't save {path}: the folder {path.parent} doesn't exist. "
                         "Pick an existing folder with -o (on Windows, a OneDrive-synced Desktop is under OneDrive\\Desktop).")
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        raise SystemExit(f"codefactory: can't save {path}: {e.strerror or e}")


def _one_function(graph: dict, name: str) -> dict:
    hits = find_function(graph, name)
    if not hits:
        raise SystemExit(f"codefactory: no function matches {name!r}")
    if len(hits) > 1:
        raise SystemExit(f"codefactory: {name!r} matches {len(hits)} functions; use the full id:\n  " +
                         "\n  ".join(h["id"] for h in hits[:20]))
    return hits[0]


def _safe_stdout() -> None:
    """Output piped or redirected on Windows defaults to a code page without → or ·: write UTF-8 there instead, and
    never crash on a character a console can't show."""
    out = sys.stdout
    if not hasattr(out, "reconfigure"):
        return
    try:
        out.reconfigure(encoding="utf-8") if not out.isatty() else out.reconfigure(errors="replace")
    except (ValueError, OSError):
        pass


def _split(values: list[str], wanted: int) -> tuple[str, list[str]]:
    """Commands that take names also take the repo first: `trace fn` or `trace path/to/repo fn`."""
    if len(values) == wanted:
        return ".", values
    if len(values) == wanted + 1:
        return values[0], values[1:]
    raise SystemExit(f"codefactory: expected {wanted} value(s) (optionally after the repo path), got {len(values)}")


def _flag_dict(graph: dict, f: dict) -> dict:
    fn = next((x for x in graph["functions"] if x["id"] == f["target"]), None)
    return {"severity": f["severity"], "kind": f["kind"], "file": fn["file"] if fn else f["target"],
            "line": f.get("line") or (fn["line"] if fn else 0), "function": fn["qualname"] if fn else None,
            "message": f["message"], "related": f.get("related", [])}


# ---- commands ----------------------------------------------------------------------------------------------------

def cmd_analyze(a) -> int:
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    text = json.dumps(graph, indent=1)
    if a.output:
        _write(Path(a.output), text)
        print(f"Wrote {a.output}: {len(graph['files'])} files, {len(graph['flags'])} issues")
    else:
        print(text)
    return 0


def _repo(path: str) -> Path:
    p = Path(path)
    return p if p.is_dir() else p.parent


def _new_only(graph: dict, path: str) -> list[dict]:
    base = read_baseline(baseline_path(_repo(path)))
    if base is None:
        raise SystemExit("codefactory: no baseline yet. Run `codefactory baseline` first (and commit the file).")
    return compare(graph, base)[0]


def cmd_flags(a) -> int:
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    limit = SEVERITY_ORDER[a.min]
    pool = _new_only(graph, a.path) if a.new else graph["flags"]
    if a.silenced:
        pool = graph.get("silenced", [])
    shown = [f for f in pool if SEVERITY_ORDER[f["severity"]] <= limit and (not a.kind or f["kind"] in a.kind)]
    if a.json:
        print(json.dumps([_flag_dict(graph, f) for f in shown], indent=1))
    else:
        for f in shown:
            d = _flag_dict(graph, f)
            print(f"{f['severity']:<5} {f['kind']:<16} {d['file']}:{d['line']}" + (f"  {d['function']}" if d["function"] else ""))
            print(f"      {f['message']}" + (f"\n      silenced: {f['reason']}" if a.silenced else ""))
        counts = {s: sum(1 for f in graph["flags"] if f["severity"] == s) for s in SEVERITY_ORDER}
        quiet = len(graph.get("silenced", []))
        print(f"\n{len(graph['files'])} files · " + " · ".join(f"{n} {s}" for s, n in counts.items()) +
              (f" · {quiet} silenced (--silenced lists them)" if quiet else "") +
              (f" · showing {len(shown)} new since the baseline" if a.new else ""))
    fail = a.fail_on and any(SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[a.fail_on] for f in graph["flags"])
    return 1 if fail else 0


def cmd_view(a) -> int:
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    graph = {**graph, "tasks": [{k: t[k] for k in ("id", "title", "prompt", "flags", "score")} for t in make_plan(graph)]}
    out = Path(a.output or "factory.html")
    _write(out, render_html(graph))
    print(f"Wrote {out}: {len(graph['files'])} machines, {len(graph['flags'])} issues")
    if not a.no_open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def cmd_sql(a) -> int:
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    if not Path(a.output).resolve().parent.exists():
        raise SystemExit(f"codefactory: can't save {a.output}: its folder doesn't exist")
    to_sqlite(graph, a.output).close()
    print(f"Wrote {a.output}: tables files, functions, edges, flags; views function_stats, file_deps")
    return 0


def cmd_query(a) -> int:
    path, (sql,) = _split(a.values, 1)
    if Path(path).suffix == ".db":  # a database written by `sql`
        import sqlite3
        db = sqlite3.connect(path)
    else:
        db = to_sqlite(load_graph(Path(path), a.lang, not a.no_cache))
    try:
        cols, rows = run_query(db, sql)
    except Exception as e:  # sqlite3.Error, shown plainly
        raise SystemExit(f"codefactory: query failed: {e}")
    finally:
        db.close()
    if a.json:
        print(json.dumps([dict(zip(cols, r)) for r in rows], indent=1))
        return 0
    print(_table(cols, rows) if cols else "(no result)")
    if len(rows) > 200:
        print(f"… {len(rows) - 200} more rows")
    return 0


def cmd_trace(a) -> int:
    path, (name,) = _split(a.values, 1)
    graph = load_graph(Path(path), a.lang, not a.no_cache)
    fn = _one_function(graph, name)
    t = trace(graph, fn["id"], ("call", "ref") if a.refs else ("call",))
    if a.json:
        print(json.dumps(t, indent=1))
        return 0
    print(f"{fn['id']}  ({fn['loc']} lines)")
    print(f"reaches {len(t['functions'])} functions in {len(t['files'])} files · depth {t['depth']} · "
          f"{t['loc']} lines of code\n")
    for f in t["functions"]:
        print(f"{'  ' * f['depth']}{f['qualname']}  · {f['file']}:{f['line']}  ({f['loc']} lines)")
    if t["calls_back"]:
        print(f"\ncalls back into {fn['qualname']} (a call loop): " + ", ".join(t["calls_back"]))
    return 0


def cmd_path(a) -> int:
    path, (source, target) = _split(a.values, 2)
    graph = load_graph(Path(path), a.lang, not a.no_cache)
    src, dst = _one_function(graph, source), _one_function(graph, target)
    steps = shortest_path(graph, src["id"], dst["id"], ("call", "ref") if a.refs else ("call",))
    if a.json:
        print(json.dumps({"path": steps}, indent=1))
        return 0 if steps else 1
    if not steps:
        print(f"{src['qualname']} never reaches {dst['qualname']} (through calls the analyzer could resolve)")
        return 1
    print(f"{len(steps) - 1} step(s):")
    for i, fid in enumerate(steps):
        print(f"{'  ' * i}{'└ ' if i else ''}{fid}")
    return 0


def cmd_brief(a) -> int:
    text = brief_markdown(load_graph(Path(a.path), a.lang, not a.no_cache), a.limit)
    if a.output:
        _write(Path(a.output), text)
        print(f"Wrote {a.output}")
    else:
        print(text, end="")
    return 0


def cmd_context(a) -> int:
    path, (target,) = _split(a.values, 1)
    graph = load_graph(Path(path), a.lang, not a.no_cache)
    if a.json:
        data = context_data(graph, target, a.limit)
        print(json.dumps(data, indent=1))
        return 1 if "error" in data else 0
    text = context_markdown(graph, target, a.limit)
    print(text, end="")
    return 0


def cmd_baseline(a) -> int:
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    out = baseline_path(_repo(a.path)) if not a.output else Path(a.output)
    n = write_baseline(graph, out)
    print(f"Wrote {out}: {n} issues as the baseline. Commit it; `codefactory check` then fails only on new ones.")
    return 0


def cmd_check(a) -> int:
    """For CI and pre-commit hooks: new issues since the baseline (or, without one, high-severity ones) fail."""
    graph = load_graph(Path(a.path), a.lang, not a.no_cache)
    base = read_baseline(baseline_path(_repo(a.path)))
    level = SEVERITY_ORDER[a.fail_on]
    if base is None:
        blocking = [f for f in graph["flags"] if f["severity"] == "high"]
        fixed = {}
        print("No baseline (codefactory baseline): checking for high-severity issues only.")
    else:
        new, fixed = compare(graph, base)
        blocking = [f for f in new if SEVERITY_ORDER[f["severity"]] <= level]
    for f in blocking:
        d = _flag_dict(graph, f)
        print(f"{f['severity']:<5} {f['kind']:<16} {d['file']}:{d['line']}" + (f"  {d['function']}" if d["function"] else ""))
        print(f"      {f['message']}")
    summary = f"{len(blocking)} new issue(s)" + (f" at {a.fail_on} or worse" if base is not None else "")
    if fixed:
        summary += f" · {sum(fixed.values())} fixed since the baseline (run `codefactory baseline` to lock that in)"
    print(("FAIL: " if blocking else "OK: ") + summary)
    if blocking:
        print("Fix them, or if one is intended, add `codefactory: ignore <kind> — <why>` above it.")
    return 1 if blocking else 0


def cmd_plan(a) -> int:
    tasks = make_plan(load_graph(Path(a.path), a.lang, not a.no_cache))
    if a.json:
        print(json.dumps(tasks[: a.top], indent=1))
    else:
        print(plan_markdown(tasks, a.top), end="")
    return 0


def cmd_prompt(a) -> int:
    path, (task_id,) = _split(a.values, 1)
    tasks = make_plan(load_graph(Path(path), a.lang, not a.no_cache))
    if task_id.isdigit() and len(task_id) < 4:  # "1" = the first task of the plan
        task = tasks[int(task_id) - 1] if 0 < int(task_id) <= len(tasks) else None
    else:
        task = next((t for t in tasks if t["id"] == task_id), None)
    if not task:
        raise SystemExit(f"codefactory: no task {task_id!r}. `codefactory plan` lists them.")
    print(task["prompt"], end="")
    return 0


def cmd_skill(a) -> int:
    path = install_skill(Path(a.path))
    print(f"Wrote {path}. Claude Code in that repo now knows when and how to use codefactory.")
    return 0


COMMANDS = {
    "analyze": (cmd_analyze, "write the graph as JSON"),
    "flags": (cmd_flags, "list issues (file:line), or --json for tools"),
    "view": (cmd_view, "write the factory view (HTML) and open it"),
    "sql": (cmd_sql, "write the graph as a SQLite database (tables files, functions, edges, flags)"),
    "query": (cmd_query, "run a SQL query on the graph: query [repo] \"SELECT …\""),
    "trace": (cmd_trace, "everything a function eventually calls (like SQL EXPLAIN): trace [repo] name"),
    "path": (cmd_path, "the shortest call path between two functions: path [repo] from to"),
    "brief": (cmd_brief, "a Markdown map of the repo for an AI agent: layers, hubs, issues by what to do"),
    "context": (cmd_context, "before changing a file or function: callers, calls, impact, tests: context [repo] name"),
    "plan": (cmd_plan, "ranked tasks with steps, tests and a fix prompt each: the work list"),
    "prompt": (cmd_prompt, "a ready-to-paste Claude Code prompt for one task: prompt [repo] <id or rank>"),
    "baseline": (cmd_baseline, "save today's issues (codefactory-baseline.json, commit it) so only new ones fail"),
    "check": (cmd_check, "for CI / pre-commit: fail on issues new since the baseline"),
    "skill": (cmd_skill, "teach Claude Code in a repo to use codefactory (writes .claude/skills/codefactory/SKILL.md)"),
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="codefactory", description="See a codebase as a factory floor and find its issues.")
    p.add_argument("--version", action="version", version=f"codefactory {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, (_, text) in COMMANDS.items():
        s = sub.add_parser(name, help=text, description=text)
        if name in ("query", "trace", "path", "context", "prompt"):
            s.add_argument("values", nargs="+", metavar="value")
        else:
            s.add_argument("path", nargs="?", default=".", help="the codebase folder (default: here), or a graph .json")
        if name != "skill":
            s.add_argument("--lang", action="append", choices=sorted(ANALYZERS), help="only these languages")
            s.add_argument("--no-cache", action="store_true", help="analyze again even if nothing changed")
        if name in ("flags", "query", "trace", "path", "context", "plan"):
            s.add_argument("--json", action="store_true", help="machine-readable output")
        if name in ("trace", "path"):
            s.add_argument("--refs", action="store_true", help="also follow functions passed by name (callbacks)")
        if name in ("analyze", "view", "brief", "baseline"):
            s.add_argument("-o", "--output", help="output file")
        if name in ("brief", "context"):
            s.add_argument("--limit", type=int, default=12 if name == "brief" else 20, help="items per list")
        if name == "flags":
            s.add_argument("--min", choices=list(SEVERITY_ORDER), default="info", help="lowest severity to show")
            s.add_argument("--kind", action="append", help="only these kinds (e.g. --kind io_in_loop --kind similar)")
            s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any issue is this severe (for CI)")
            s.add_argument("--new", action="store_true", help="only issues not in the baseline")
            s.add_argument("--silenced", action="store_true", help="list the silenced issues and why")
        if name == "check":
            s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="warn", help="lowest new severity that fails (default warn)")
        if name == "plan":
            s.add_argument("--top", type=int, default=10, help="how many tasks (default 10)")
        if name == "view":
            s.add_argument("--no-open", action="store_true", help="don't open the browser")
        if name == "sql":
            s.add_argument("-o", "--output", default="codefactory.db", help="database file (default: codefactory.db)")
    return p


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    a = parser().parse_args(argv)
    return COMMANDS[a.cmd][0](a)


if __name__ == "__main__":
    sys.exit(main())
