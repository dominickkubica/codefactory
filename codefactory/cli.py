"""codefactory command line: analyze a codebase, list its issues, or open it as a factory floor."""
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
from .graph import Graph
from .layers import assign_layers
from .viewer import render_html


def build(root: Path, languages: list[str] | None = None) -> Graph:
    cfg = load_config(root)
    g = analyze(root, cfg.ignore, languages)
    assign_layers(g, cfg)
    run_flags(g, cfg)
    return g


def _load(path: Path, languages: list[str] | None) -> dict:
    if path.is_file() and path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if not path.is_dir():
        raise SystemExit(f"codefactory: {path} is not a folder or a graph .json file")
    return build(path.resolve(), languages).to_dict()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="codefactory", description="See a codebase as a factory floor and find its issues.")
    p.add_argument("--version", action="version", version=f"codefactory {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, text in (("analyze", "write the graph as JSON"), ("flags", "list issues in the terminal"),
                       ("view", "write the factory view (HTML) and open it")):
        s = sub.add_parser(name, help=text)
        s.add_argument("path", nargs="?", default=".", help="the codebase folder (or, for view/flags, a graph .json)")
        s.add_argument("--lang", action="append", choices=sorted(ANALYZERS), help="only these languages")
        if name in ("analyze", "view"):
            s.add_argument("-o", "--output", help="output file")
        if name == "view":
            s.add_argument("--no-open", action="store_true", help="don't open the browser")
        if name == "flags":
            s.add_argument("--min", choices=list(SEVERITY_ORDER), default="info", help="lowest severity to show")
            s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any issue is this severe (for CI)")
    a = p.parse_args(argv)
    graph = _load(Path(a.path), a.lang)

    if a.cmd == "analyze":
        text = json.dumps(graph, indent=1)
        if a.output:
            Path(a.output).write_text(text, encoding="utf-8")
            print(f"Wrote {a.output}: {len(graph['files'])} files, {len(graph['flags'])} issues")
        else:
            print(text)
        return 0

    if a.cmd == "flags":
        limit = SEVERITY_ORDER[a.min]
        shown = [f for f in graph["flags"] if SEVERITY_ORDER[f["severity"]] <= limit]
        for f in shown:
            print(f"{f['severity']:<5} {f['kind']:<16} {f['target']}\n      {f['message']}")
        counts = {s: sum(1 for f in graph["flags"] if f["severity"] == s) for s in SEVERITY_ORDER}
        print(f"\n{len(graph['files'])} files · " + " · ".join(f"{n} {s}" for s, n in counts.items()))
        if a.fail_on and any(SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[a.fail_on] for f in graph["flags"]):
            return 1
        return 0

    out = Path(a.output or "factory.html")
    out.write_text(render_html(graph), encoding="utf-8")
    print(f"Wrote {out}: {len(graph['files'])} machines, {len(graph['flags'])} issues")
    if not a.no_open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
