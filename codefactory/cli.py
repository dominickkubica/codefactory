"""codefactory command line: map a codebase, list its issues, query it with SQL, trace calls, or open the factory view."""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analyzers import ANALYZERS, analyze
from .config import load_config
from .flags import SEVERITY_ORDER, run_flags
from .graph import Flag, Graph
from .layers import assign_layers
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
    return g


def _load(path: Path, languages: list[str] | None) -> dict:
    if path.is_file() and path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if not path.is_dir():
        raise SystemExit(f"codefactory: {path} is not a folder or a graph .json file")
    return build(path.resolve(), languages).to_dict()


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


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    p = argparse.ArgumentParser(prog="codefactory", description="See a codebase as a factory floor and find its issues.")
    p.add_argument("--version", action="version", version=f"codefactory {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def command(name: str, text: str):
        s = sub.add_parser(name, help=text, description=text)
        s.add_argument("path", nargs="?" if name in ("analyze", "flags", "view", "sql") else None, default=".",
                       help="the codebase folder, or a graph .json")
        s.add_argument("--lang", action="append", choices=sorted(ANALYZERS), help="only these languages")
        return s

    s = command("analyze", "write the graph as JSON")
    s.add_argument("-o", "--output", help="output file (default: print)")
    s = command("flags", "list issues in the terminal")
    s.add_argument("--min", choices=list(SEVERITY_ORDER), default="info", help="lowest severity to show")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any issue is this severe (for CI)")
    s = command("view", "write the factory view (HTML) and open it")
    s.add_argument("-o", "--output", help="output file (default: factory.html)")
    s.add_argument("--no-open", action="store_true", help="don't open the browser")
    s = command("sql", "write the graph as a SQLite database (tables files, functions, edges, flags)")
    s.add_argument("-o", "--output", default="codefactory.db", help="database file (default: codefactory.db)")
    s = command("query", "run a SQL query on the graph and print the result")
    s.add_argument("sql", help="e.g. \"SELECT * FROM function_stats ORDER BY fan_in DESC LIMIT 10\"")
    s = command("trace", "everything a function eventually calls: depth, files and lines (like SQL EXPLAIN)")
    s.add_argument("function", help="a name, Class.method, or file::qualname")
    s.add_argument("--refs", action="store_true", help="also follow functions passed by name (callbacks)")
    s = command("path", "the shortest call path from one function to another")
    s.add_argument("source")
    s.add_argument("target")
    a = p.parse_args(argv)

    # query also accepts a .db written by `sql`
    if a.cmd == "query" and Path(a.path).suffix == ".db":
        import sqlite3
        db = sqlite3.connect(a.path)
    else:
        graph = _load(Path(a.path), a.lang)

    if a.cmd == "analyze":
        text = json.dumps(graph, indent=1)
        if a.output:
            _write(Path(a.output), text)
            print(f"Wrote {a.output}: {len(graph['files'])} files, {len(graph['flags'])} issues")
        else:
            print(text)
        return 0

    if a.cmd == "flags":
        limit = SEVERITY_ORDER[a.min]
        for f in (f for f in graph["flags"] if SEVERITY_ORDER[f["severity"]] <= limit):
            print(f"{f['severity']:<5} {f['kind']:<16} {f['target']}\n      {f['message']}")
        counts = {s: sum(1 for f in graph["flags"] if f["severity"] == s) for s in SEVERITY_ORDER}
        print(f"\n{len(graph['files'])} files · " + " · ".join(f"{n} {s}" for s, n in counts.items()))
        fail = a.fail_on and any(SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[a.fail_on] for f in graph["flags"])
        return 1 if fail else 0

    if a.cmd == "sql":
        if not Path(a.output).resolve().parent.exists():
            raise SystemExit(f"codefactory: can't save {a.output}: its folder doesn't exist")
        to_sqlite(graph, a.output).close()
        print(f"Wrote {a.output}: tables files, functions, edges, flags; views function_stats, file_deps")
        return 0

    if a.cmd == "query":
        if Path(a.path).suffix != ".db":
            db = to_sqlite(graph)
        try:
            cols, rows = run_query(db, a.sql)
        except Exception as e:  # sqlite3.Error, shown plainly
            raise SystemExit(f"codefactory: query failed: {e}")
        finally:
            db.close()
        print(_table(cols, rows) if cols else "(no result)")
        if len(rows) > 200:
            print(f"… {len(rows) - 200} more rows")
        return 0

    kinds = ("call", "ref") if getattr(a, "refs", False) else ("call",)
    if a.cmd == "trace":
        fn = _one_function(graph, a.function)
        t = trace(graph, fn["id"], kinds)
        print(f"{fn['id']}  ({fn['loc']} lines)")
        print(f"reaches {len(t['functions'])} functions in {len(t['files'])} files · depth {t['depth']} · "
              f"{t['loc']} lines of code\n")
        for f in t["functions"]:
            print(f"{'  ' * f['depth']}{f['qualname']}  · {f['file']}:{f['line']}  ({f['loc']} lines)")
        if t["calls_back"]:
            print(f"\ncalls back into {fn['qualname']} (a call loop): " + ", ".join(t["calls_back"]))
        return 0

    if a.cmd == "path":
        src, dst = _one_function(graph, a.source), _one_function(graph, a.target)
        path = shortest_path(graph, src["id"], dst["id"], kinds)
        if not path:
            print(f"{src['qualname']} never reaches {dst['qualname']} (through calls the analyzer could resolve)")
            return 1
        print(f"{len(path) - 1} step(s):")
        for i, fid in enumerate(path):
            print(f"{'  ' * i}{'└ ' if i else ''}{fid}")
        return 0

    out = Path(a.output or "factory.html")
    _write(out, render_html(graph))
    print(f"Wrote {out}: {len(graph['files'])} machines, {len(graph['flags'])} issues")
    if not a.no_open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
