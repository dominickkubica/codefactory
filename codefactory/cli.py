"""codefactory command line: map a codebase, list its issues, query it with SQL, trace calls, brief an AI agent, or
open the factory view."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analyzers import LANGUAGES, analyze
from .baseline import baseline_path, compare, read_baseline, write_baseline
from .brief import brief_markdown, context_data, context_markdown
from .cache import load_cached, save_cache
from .checks import scan_sources
from .config import load_config
from .flags import SEVERITY_ORDER, run_flags
from .graph import Flag, Graph
from .layers import assign_layers
from .plan import make_plan, plan_markdown
from .review import review_markdown
from .sarif import build_sarif, github_annotations
from .skill import SOURCE as SKILL_SOURCE
from .skill import install_hook, install_skill, refresh_skill, skill_outdated, update
from .sqlgraph import query_flags, run_query, to_sqlite
from .suppress import apply_suppressions
from .trace import find_function, shortest_path, trace
from .viewer import render_html


def build(root: Path, languages: list[str] | None = None, cache: bool = True) -> Graph:
    cfg = load_config(root)
    g = analyze(root, cfg.ignore, languages, cache)
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
    graph = build(root, languages, cache).to_dict()
    if cache and not languages:
        save_cache(root, ignore, graph)
    return graph


def _table(cols: list[str], rows: list[tuple], limit: int = 200) -> str:
    rows = [tuple("" if v is None else str(v) for v in r) for r in rows[:limit]]
    widths = [min(60, max([len(c)] + [len(r[i]) for r in rows])) for i, c in enumerate(cols)]
    line = lambda vals: "  ".join(v[:w].ljust(w) for v, w in zip(vals, widths, strict=True))  # noqa: E731
    return "\n".join([line(cols), line(["-" * w for w in widths]), *map(line, rows)])


def _write(path: Path, text: str) -> None:
    """Writes an output file, or explains plainly why it can't (the folder doesn't exist, no permission)."""
    if not path.parent.exists():
        raise SystemExit(
            f"codefactory: can't save {path}: the folder {path.parent} doesn't exist. "
            "Pick an existing folder with -o (on Windows, a OneDrive-synced Desktop is under OneDrive\\Desktop)."
        )
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        raise SystemExit(f"codefactory: can't save {path}: {e.strerror or e}") from None


def _one_function(graph: dict, name: str) -> dict:
    hits = find_function(graph, name)
    if not hits:
        raise SystemExit(f"codefactory: no function matches {name!r}")
    if len(hits) > 1:
        raise SystemExit(
            f"codefactory: {name!r} matches {len(hits)} functions; use the full id:\n  " + "\n  ".join(h["id"] for h in hits[:20])
        )
    return hits[0]


def _safe_stdout() -> None:
    """Output piped or redirected on Windows defaults to a code page without → or ·: write UTF-8 there instead, and
    never crash on a character a console can't show."""
    out = sys.stdout
    if not hasattr(out, "reconfigure"):
        return
    with contextlib.suppress(ValueError, OSError):
        out.reconfigure(encoding="utf-8") if not out.isatty() else out.reconfigure(errors="replace")


def _split(values: list[str], wanted: int) -> tuple[str, list[str]]:
    """Commands that take names also take the repo first: `trace fn` or `trace path/to/repo fn`."""
    if len(values) == wanted:
        return ".", values
    if len(values) == wanted + 1:
        return values[0], values[1:]
    raise SystemExit(f"codefactory: expected {wanted} value(s) (optionally after the repo path), got {len(values)}")


def _flag_dict(graph: dict, f: dict) -> dict:
    fn = next((x for x in graph["functions"] if x["id"] == f["target"]), None)
    return {
        "severity": f["severity"],
        "kind": f["kind"],
        "file": fn["file"] if fn else f["target"],
        "line": f.get("line") or (fn["line"] if fn else 0),
        "function": fn["qualname"] if fn else None,
        "message": f["message"],
        "related": f.get("related", []),
    }


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
    elif a.github:
        print(github_annotations(graph, shown))
    else:
        for f in shown:
            d = _flag_dict(graph, f)
            print(f"{f['severity']:<5} {f['kind']:<16} {d['file']}:{d['line']}" + (f"  {d['function']}" if d["function"] else ""))
            print(f"      {f['message']}" + (f"\n      silenced: {f['reason']}" if a.silenced else ""))
        counts = {s: sum(1 for f in graph["flags"] if f["severity"] == s) for s in SEVERITY_ORDER}
        quiet = len(graph.get("silenced", []))
        print(
            f"\n{len(graph['files'])} files · "
            + " · ".join(f"{n} {s}" for s, n in counts.items())
            + (f" · {quiet} silenced (--silenced lists them)" if quiet else "")
            + (f" · showing {len(shown)} new since the baseline" if a.new else "")
        )
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
        raise SystemExit(f"codefactory: query failed: {e}") from None
    finally:
        db.close()
    if a.json:
        print(json.dumps([dict(zip(cols, r, strict=True)) for r in rows], indent=1))
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
    print(f"reaches {len(t['functions'])} functions in {len(t['files'])} files · depth {t['depth']} · {t['loc']} lines of code\n")
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
    if a.github and blocking:
        print(github_annotations(graph, blocking))
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


def cmd_diff(a) -> int:
    """What this change adds: new findings compared with the base branch (merge-base), for pull requests."""
    from . import diff

    root = _repo(a.path)
    base = a.base or diff.default_base(root)
    result = diff.run(root, base, lambda p: load_graph(p, a.lang, not a.no_cache))
    level = SEVERITY_ORDER.get(a.fail_on, 99)
    blocking = [i for i in result["new"] if SEVERITY_ORDER.get(i.severity, 2) <= level]
    if a.json:
        print(
            json.dumps({**result, "new": [vars(i) for i in result["new"]], "fixed": [vars(i) for i in result["fixed"]]}, indent=1)
        )
    elif a.github:
        for i in result["new"]:
            kind = {"high": "error", "warn": "warning"}.get(i.severity, "notice")
            print(f"::{kind} file={i.file},line={max(1, i.line)},title=codefactory {i.kind}::{i.message}")
    else:
        print(diff.markdown(result), end="")
    if a.comment:
        _write(Path(a.comment), diff.markdown(result))
    return 1 if blocking else 0


def cmd_surface(a) -> int:
    from .brief import View
    from .security import SINK_KINDS, function_at, surface, writes

    root = Path(a.path).resolve()
    graph = load_graph(root, a.lang, not a.no_cache)
    v = View(graph)
    s = surface(root, graph, v)
    writers = writes(v)
    scan = scan_sources(root, [f["id"] for f in graph["files"]])
    sinks = {}  # function id -> risky kinds in it
    for kind in SINK_KINDS:
        for e in scan[kind].hits:
            if fid := function_at(v, e.file, e.line):
                sinks.setdefault(fid, set()).add(kind)
    rows = []
    for i, e in enumerate(s.entries):
        reached = {f for f, (j, _) in s.reach.items() if j == i} | _reachable_from(graph, e.fn)
        rows.append({
            "method": e.method, "path": e.path, "framework": e.framework, "handler": f"{e.file}:{e.line}",
            "auth": e.auth, "changes_data": any(f in writers for f in reached),
            "risky": sorted({k for f in reached for k in sinks.get(f, ())}),
        })  # fmt: skip
    if a.json:
        print(json.dumps({"exposure": s.exposure, "evidence": s.exposure_evidence, "endpoints": rows}, indent=1))
        return 0
    if not rows:
        print(
            "No HTTP endpoints found (recognised: FastAPI, Flask, Django/DRF, Express-style, Next.js, Spring, Go, "
            "Rails, Sinatra)."
        )
        return 0
    print(f"{len(rows)} endpoints · listening: {s.exposure}" + (f" ({s.exposure_evidence})" if s.exposure_evidence else ""))
    print(_table(["method", "path", "auth", "changes data", "risky code", "handler"],
                 [(r["method"], r["path"], r["auth"] or "none found", "yes" if r["changes_data"] else "",
                   ", ".join(r["risky"]), r["handler"]) for r in rows], limit=500))  # fmt: skip
    return 0


def _reachable_from(graph: dict, start: str) -> set[str]:
    out_edges: dict[str, list[str]] = {}
    for e in graph["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], []).append(e["dst"])
    seen, q = {start}, [start]
    while q:
        for nxt in out_edges.get(q.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen


def cmd_accept(a) -> int:
    from .accept import append_rules, known_kinds, normalize_where, rules_for_task

    values = list(a.values)
    root = Path(values.pop(0)) if len(values) > 1 and Path(values[0]).is_dir() else Path(".")
    rest = values
    if not rest:
        raise ValueError("say what to accept: a plan task (`codefactory accept 3f9a2c`) or a kind and where")
    if len(rest) == 1:  # a plan task: every finding behind it
        graph = load_graph(root, a.lang, not a.no_cache)
        tasks = make_plan(graph)
        key = rest[0]
        task = tasks[int(key) - 1] if key.isdigit() and len(key) < 4 and 0 < int(key) <= len(tasks) else None
        task = task or next((t for t in tasks if t["id"] == key), None)
        if not task:
            raise ValueError(f"no plan task {key!r}; for a single finding give its kind and where: accept sql_built src/db.py")
        rules = rules_for_task(task, graph)
    else:
        kind, where = rest[0], normalize_where(rest[1])
        if kind not in known_kinds():
            raise ValueError(f"unknown kind {kind!r}; one of: {', '.join(sorted(known_kinds()))}")
        rules = [(kind, where)]
    file = append_rules(root, rules, a.why)
    for kind, where in rules:
        print(f"accepted {kind} at {where}: {a.why}")
    print(f"Recorded in {file}; commit it so everyone (and CI) sees the same list. `codefactory flags --silenced` lists them.")
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


def cmd_review(a) -> int:
    path = Path(a.path)
    if not path.is_dir():
        raise SystemExit("codefactory: review needs the repository folder (it reads manifests, CI files and source text)")
    text = review_markdown(load_graph(path, a.lang, not a.no_cache), path.resolve(), a.for_ai, a.online)
    if a.output:
        _write(Path(a.output), text)
        print(f"Wrote {a.output}")
    else:
        print(text, end="")
    return 0


def cmd_sarif(a) -> int:
    path = Path(a.path)
    graph = load_graph(path, a.lang, not a.no_cache)
    new_keys = None
    base = read_baseline(baseline_path(_repo(a.path)))
    if base is not None:
        from collections import Counter

        from .baseline import issue_key

        fns = {f["id"]: f for f in graph["functions"]}
        new_keys = Counter(issue_key(graph, f, fns) for f in compare(graph, base)[0])
    doc = build_sarif(graph, path.resolve() if path.is_dir() and not a.no_source_checks else None, new_keys, a.min)
    if a.new and new_keys is not None:
        doc["runs"][0]["results"] = [
            r for r in doc["runs"][0]["results"] if r.get("baselineState", "new") == "new" and "suppressions" not in r
        ]
    out = Path(a.output or "codefactory.sarif")
    _write(out, json.dumps(doc, indent=1))
    n = len(doc["runs"][0]["results"])
    quiet = sum(1 for r in doc["runs"][0]["results"] if "suppressions" in r)
    print(
        f"Wrote {out}: {n} results ({quiet} silenced, shown as suppressed). Upload it to GitHub code scanning, or open "
        "it in VS Code with the SARIF Viewer extension."
    )
    return 0


def cmd_skill(a) -> int:
    repo = Path(a.path)
    path = install_skill(repo)
    print(f"Wrote {path}. Claude Code in that repo now knows when and how to use codefactory.")
    if a.hook:
        hook, settings = install_hook(repo)
        print(
            f"Wrote {hook} and registered it in {settings}: each Claude Code session now starts with codefactory "
            "installed, upgraded (at most once a day) and its skill current. Commit .claude/."
        )
    return 0


def cmd_update(a) -> int:
    old, new = update(a.source)
    print(f"codefactory {old} -> {new}" if old != new else f"codefactory {new} is already the latest.")
    if refresh_skill(Path(".")):
        print("Refreshed .claude/skills/codefactory/SKILL.md for the new version.")
    return 0


COMMANDS = {
    "analyze": (cmd_analyze, "write the graph as JSON"),
    "flags": (cmd_flags, "list issues (file:line), or --json for tools"),
    "view": (cmd_view, "write the factory view (HTML) and open it"),
    "sql": (cmd_sql, "write the graph as a SQLite database (tables files, functions, edges, flags)"),
    "query": (cmd_query, 'run a SQL query on the graph: query [repo] "SELECT …"'),
    "trace": (cmd_trace, "everything a function eventually calls (like SQL EXPLAIN): trace [repo] name"),
    "path": (cmd_path, "the shortest call path between two functions: path [repo] from to"),
    "brief": (cmd_brief, "a Markdown map of the repo for an AI agent: layers, hubs, issues by what to do"),
    "context": (cmd_context, "before changing a file or function: callers, calls, impact, tests: context [repo] name"),
    "review": (cmd_review, "a full technical review (summary, system map, findings by severity, gaps), no AI needed"),
    "plan": (cmd_plan, "ranked tasks with steps, tests and a fix prompt each: the work list"),
    "prompt": (cmd_prompt, "a ready-to-paste Claude Code prompt for one task: prompt [repo] <id or rank>"),
    "baseline": (cmd_baseline, "save today's issues (codefactory-baseline.json, commit it) so only new ones fail"),
    "check": (cmd_check, "for CI / pre-commit: fail on issues new since the baseline"),
    "sarif": (cmd_sarif, "write issues as SARIF 2.1.0 for GitHub code scanning, VS Code and CI tools"),
    "diff": (cmd_diff, "what a change adds: new and fixed findings compared with the base branch (for pull requests)"),
    "surface": (
        cmd_surface,
        "the attack surface: every HTTP endpoint, its auth check, and whether it changes data or reaches risky code",
    ),
    "accept": (cmd_accept, "mark a finding as intended, with the reason (writes a [[silence]] rule to factory.toml)"),
    "update": (cmd_update, "upgrade codefactory to the latest version (and refresh this repo's skill)"),
    "skill": (cmd_skill, "teach Claude Code in a repo to use codefactory (writes .claude/skills/codefactory/SKILL.md)"),
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codefactory",
        description="See a codebase as a factory floor, find its problems, and turn them into work.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  codefactory view                 open the factory view of this folder in your browser
  codefactory review -o review.md  a technical review of this repository
  codefactory plan                 ranked tasks; then: codefactory prompt 1
  codefactory context <name>       before changing a function: callers, impact, tests
  codefactory baseline && codefactory check     fail CI only on new issues

Run `codefactory <command> --help` for a command's options.""",
    )
    p.add_argument("--version", action="version", version=f"codefactory {__version__}")
    p.add_argument("--debug", action="store_true", help="show full tracebacks (for reporting a bug)")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, (_, text) in COMMANDS.items():
        s = sub.add_parser(name, help=text, description=text)
        if name in ("query", "trace", "path", "context", "prompt", "accept"):
            s.add_argument("values", nargs="+", metavar="value")
        else:
            s.add_argument("path", nargs="?", default=".", help="the codebase folder (default: here), or a graph .json")
        if name == "diff":
            s.add_argument("--base", help="the branch, tag or commit to compare with (default: origin/HEAD, main or master)")
            s.add_argument("--comment", metavar="FILE", help="also write the pull-request comment (Markdown) to FILE")
            s.add_argument("--github", action="store_true", help="print GitHub Actions annotations for new findings")
            s.add_argument("--fail-on", choices=["high", "warn", "info", "never"], default="never",
                           help="exit 1 when new findings at this level or worse appear (default: never)")  # fmt: skip
        if name == "accept":
            s.add_argument("--why", required=True, help="why it's intended (kept with the rule, shown by flags --silenced)")
        if name == "skill":
            s.add_argument("--hook", action="store_true", help="also add a session-start hook that keeps codefactory current")
        if name == "update":
            s.add_argument("--source", default=SKILL_SOURCE, help="where to install from (default: the GitHub repository)")
        if name not in ("skill", "update"):
            s.add_argument(
                "--lang",
                action="append",
                choices=LANGUAGES,
                help="only these analyzers (other = every language but Python and TypeScript)",
            )
            s.add_argument("--no-cache", action="store_true", help="analyze again even if nothing changed")
        if name in ("flags", "query", "trace", "path", "context", "plan", "surface", "diff"):
            s.add_argument("--json", action="store_true", help="machine-readable output")
        if name in ("trace", "path"):
            s.add_argument("--refs", action="store_true", help="also follow functions passed by name (callbacks)")
        if name in ("analyze", "view", "brief", "baseline", "review", "sarif"):
            s.add_argument("-o", "--output", help="output file")
        if name in ("brief", "context"):
            s.add_argument("--limit", type=int, default=12 if name == "brief" else 20, help="items per list")
        if name == "flags":
            s.add_argument("--min", choices=list(SEVERITY_ORDER), default="info", help="lowest severity to show")
            s.add_argument("--kind", action="append", help="only these kinds (e.g. --kind io_in_loop --kind similar)")
            s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any issue is this severe (for CI)")
            s.add_argument("--new", action="store_true", help="only issues not in the baseline")
            s.add_argument("--silenced", action="store_true", help="list the silenced issues and why")
            s.add_argument("--github", action="store_true", help="print GitHub Actions annotations (::warning file=…)")
        if name == "sarif":
            s.add_argument("--min", choices=list(SEVERITY_ORDER), default="info", help="lowest severity to include")
            s.add_argument("--new", action="store_true", help="only results new since the baseline")
            s.add_argument(
                "--no-source-checks", action="store_true", help="only the graph's issues, not secrets/SQL/… line checks"
            )
        if name == "check":
            s.add_argument("--github", action="store_true", help="also print GitHub Actions annotations for new issues")
            s.add_argument(
                "--fail-on", choices=list(SEVERITY_ORDER), default="warn", help="lowest new severity that fails (default warn)"
            )
        if name == "review":
            s.add_argument("--for-ai", action="store_true", help="append an evidence pack for an AI to finish the review")
            s.add_argument(
                "--online",
                action="store_true",
                help="also check dependencies for known vulnerabilities at OSV.dev (sends package names and versions only)",
            )
        if name == "plan":
            s.add_argument("--top", type=int, default=10, help="how many tasks (default 10)")
        if name == "view":
            s.add_argument("--no-open", action="store_true", help="don't open the browser")
        if name == "sql":
            s.add_argument("-o", "--output", default="codefactory.db", help="database file (default: codefactory.db)")
    return p


def main(argv: list[str] | None = None) -> int:
    """Runs a command. Problems a user can fix (a bad factory.toml, a missing folder, TypeScript not installed) end
    with a one-line message; anything unexpected says how to get the full traceback (--debug) to report it."""
    _safe_stdout()
    a = parser().parse_args(argv)
    debug = a.debug or bool(os.environ.get("CODEFACTORY_DEBUG"))
    repo = Path(getattr(a, "path", None) or ".")
    if a.cmd not in ("skill", "update") and skill_outdated(repo if repo.is_dir() else repo.parent):
        print(
            "codefactory: .claude/skills/codefactory/SKILL.md is from an older version; `codefactory skill` updates it.",
            file=sys.stderr,
        )
    try:
        return COMMANDS[a.cmd][0](a)
    except KeyboardInterrupt:
        print("codefactory: stopped.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, OSError) as e:
        if debug:
            raise
        print(f"codefactory: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # a bug: say so plainly, and how to report it
        if debug:
            raise
        print(
            f"codefactory: unexpected error ({type(e).__name__}: {e}).\n"
            "  Run the same command with --debug for the full traceback, and please report it.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
