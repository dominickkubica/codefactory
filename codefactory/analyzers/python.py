"""Python analyzer: files, functions, imports and calls from the standard library's ast module (nothing is run).

Calls are resolved statically, so the graph is an approximation: plain names, imported names, module.attr,
self.method / cls.method and ClassName() (to __init__) resolve; calls through variables, getattr or dynamic
dispatch don't. A function passed by name (a callback, a decorator argument) is kept as a "ref" edge so it
doesn't look dead.
"""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path

from ..graph import Edge, File, Function, Graph, Site
from ..paths import walk
from . import parallel
from .python_parse import parse_module


def iter_files(root: Path, ignore: list[str]) -> list[Path]:
    skip = set(ignore)
    out = []
    # hidden folders (.claude, .github, .venv…) hold tooling and environments, not the product's code; pruned before
    # descending, so a virtualenv or node_modules isn't walked at all
    for rel in walk(root, suffixes=(".py",), skip=skip, hidden=False):
        if not any(part.endswith(".egg-info") for part in rel.split("/")[:-1]):
            out.append(root / rel)
    return sorted(out)


def module_name(rel: Path, packages: frozenset[str] = frozenset()) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[0] == "src" and len(parts) > 1:
        parts = parts[1:]
    elif len(parts) > 2 and parts[0] not in packages:
        # `lib/streamlit/util.py` is `streamlit.util`: a package's name starts at the top of its `__init__.py` chain
        top = len(parts) - 1
        while top > 0 and "/".join(parts[:top]) in packages:
            top -= 1
        if top < len(parts) - 1:  # (the file sits in a package)
            parts = parts[top:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class _Module:
    def __init__(self, rel: str, name: str, data: dict, is_pkg: bool):
        self.rel, self.name, self.data, self.is_pkg = rel, name, data, is_pkg
        self.funcs: dict[str, Function] = {}  # qualname -> function
        self.classes: set[str] = set(data["classes"])
        self.aliases: dict[str, str] = {}  # local name -> module name
        self.symbols: dict[str, tuple[str, str]] = {}  # local name -> (module name, symbol)
        self.exports: set[str] = set(data["exports"])
        self.load_imports: set[str] = set()  # modules imported when this one loads (not inside functions or TYPE_CHECKING)
        self.consts: set[str] = set(data["consts"])  # module-level names bound to a literal list / tuple / set / dict
        self.tables: dict[str, list] = data["tables"]  # their references: COMMANDS = {"run": (cmd_run, …)}


def _sibling(mod: _Module, name: str, known: dict[str, str]) -> str | None:
    """`from shared import f` in a folder of scripts: Python puts a script's own folder on the path, so a module next
    to it is found by its bare name. Not inside a package, where `from collections import …` is the standard library."""
    if mod.is_pkg or "." not in mod.name:
        return None
    folder = mod.name.rsplit(".", 1)[0]
    if folder in known:  # a package (it has an __init__.py): Python 3 has no implicit relative imports there
        return None
    return known.get(f"{folder}.{name}")


def _resolve_relative(mod: _Module, level: int, target: str | None) -> str:
    base = mod.name.split(".") if mod.is_pkg else mod.name.split(".")[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, target] if target else base)


def _scoped(mod: _Module, imports: list, known: dict[str, str]) -> _Module:
    """The module as one function sees it: its own imports on top of the module's."""
    if not imports:
        return mod
    view = copy.copy(mod)
    view.aliases, view.symbols, view.load_imports = dict(mod.aliases), dict(mod.symbols), set()
    _apply_imports(view, imports, known)
    return view


def _collect(mod: _Module, known: dict[str, str]) -> None:
    _apply_imports(mod, mod.data["imports"], known)


def _apply_imports(mod: _Module, imports: list, known: dict[str, str]) -> None:
    for imp in imports:
        if imp[0] == "import":
            _, name, asname, at_load = imp
            written, name = name, known.get(name, name)  # (`lib.streamlit.util`, the long name of `streamlit.util`)
            if name not in known and (near := _sibling(mod, name, known)):
                name = near
            if asname:
                mod.aliases[asname] = name
            else:
                mod.aliases[written.split(".")[0]] = written.split(".")[0]
                mod.aliases[written] = name
            if at_load:
                mod.load_imports.add(name)
        else:
            _, module, level, name, asname, at_load = imp
            src = _resolve_relative(mod, level, module) if level else known.get(module or "", module or "")
            if not level and src and src not in known and f"{src}.{name}" not in known:
                src = _sibling(mod, src, known) or src
            local = asname or name
            full = f"{src}.{name}" if src else name
            if full in known:
                mod.aliases[local] = full
            else:
                mod.symbols[local] = (src, name)
            if at_load:
                mod.load_imports.add(full if full in known else src)


def _functions(mod: _Module) -> list[tuple[Function, dict]]:
    """Top-level functions and class methods. Nested functions belong to the function that holds them. The same name
    defined twice (a property's getter and setter) gets its line in the id; name lookups keep finding the first, or
    with @overload stubs, the implementation under them: that's what a call runs."""
    out = []
    first: dict[str, dict] = {}
    for d in mod.data["defs"]:
        if d["qualname"] not in first or (first[d["qualname"]].get("overload") and not d.get("overload")):
            first[d["qualname"]] = d
    for d in mod.data["defs"]:
        q = d["qualname"]
        fid = f"{mod.rel}::{q}" if first[q] is d else f"{mod.rel}::{q}@{d['line']}"
        f = Function(
            id=fid, file=mod.rel, name=d["name"], qualname=q, line=d["line"], end=d["end"], loc=d["end"] - d["line"] + 1,
            kind=d["kind"], decorated=d["decorated"], exported=d["exported"], shape=d["shape"], tokens=d["tokens"],
            doc=d.get("doc", 0), branches=d.get("branches", 0),
        )  # fmt: skip
        if first[q] is d:
            mod.funcs[q] = f
        out.append((f, d))
    return out


class _Resolver:
    def __init__(self, modules: dict[str, _Module]):
        self.modules = modules
        # Method names defined exactly once in the codebase: obj.name(...) on an unknown obj probably means it.
        # Only used to keep such methods from looking unused (a "ref"), never drawn as a definite call.
        seen: Counter = Counter()
        owner: dict[str, str] = {}
        for m in modules.values():
            for f in m.funcs.values():
                if f.kind == "method" and not f.name.startswith("__"):
                    seen[f.name] += 1
                    owner[f.name] = f.id
        self.unique_methods = {n: owner[n] for n, c in seen.items() if c == 1}

    def in_module(self, modname: str, symbol: str, depth: int = 0) -> str | None:
        m = self.modules.get(modname)
        if not m or depth > 4:
            return None
        if symbol in m.funcs:
            return m.funcs[symbol].id
        if symbol in m.classes:
            init = m.funcs.get(f"{symbol}.__init__")
            return init.id if init else None
        if symbol in m.symbols:  # re-exported (from .x import f in a package __init__)
            src, name = m.symbols[symbol]
            return self.in_module(src, name, depth + 1)
        return None

    def name(self, mod: _Module, name: str) -> str | None:
        if name in mod.funcs:
            return mod.funcs[name].id
        if name in mod.classes:
            init = mod.funcs.get(f"{name}.__init__")
            return init.id if init else None
        if name in mod.symbols:
            return self.in_module(*mod.symbols[name])
        return None

    def attr(self, mod: _Module, base: str | None, attr: str, dotted: str | None, cls: str | None) -> str | None:
        if base is not None:
            if base in ("self", "cls") and cls:
                f = mod.funcs.get(f"{cls}.{attr}")
                return f.id if f else None
            if base in mod.aliases:
                return self.in_module(mod.aliases[base], attr)
            if base in mod.classes:
                f = mod.funcs.get(f"{base}.{attr}")
                return f.id if f else None
            if base in mod.symbols:  # an imported class: Class.method
                src, cname = mod.symbols[base]
                m = self.modules.get(src)
                f = m.funcs.get(f"{cname}.{attr}") if m else None
                return f.id if f else None
        if dotted:  # package.module.func
            modname, _, sym = dotted.rpartition(".")
            if modname.split(".")[0] in mod.aliases:
                return self.in_module(mod.aliases.get(modname, modname), sym)
        return None

    def expr(self, mod: _Module, e: list | None, cls: str | None) -> str | None:
        if not e:
            return None
        if e[0] == "n":
            return self.name(mod, e[1])
        if e[0] == "a":
            return self.attr(mod, e[1], e[2], e[3], cls)
        return None


def _link(
    evs: list, mod: _Module, cls: str | None, src_id: str, res: _Resolver, calls: Counter, refs: Counter,
    consts: set[str], sites: list | None = None, io: set | None = None,
) -> None:  # fmt: skip
    """Resolves one body's events (see python_parse) into call and ref edges, loop sites and I/O."""
    for ev in evs:
        kind = ev[0]
        if kind == "w":
            if sites is not None:
                sites.append(Site(src_id, "loop_await", ev[1], bounded=ev[2] is not None and all(d in consts for d in ev[2])))
        elif kind == "c":
            _, line, loop, deps, e, sink, attr, tx = ev
            bounded = deps is not None and all(d in consts for d in deps)
            target = res.expr(mod, e, cls)
            if target:
                if target != src_id:
                    calls[(src_id, target)] += 1
                    if loop and sites is not None:
                        sites.append(Site(src_id, "loop_call", line, target=target, bounded=bounded, tx=tx))
                    elif tx and sites is not None:  # called inside a transaction block
                        sites.append(Site(src_id, "tx_call", line, target=target, tx=True))
            elif e and e[0] == "s":  # TABLE[key](…): one of the table's functions runs; link to all of them
                for ref in mod.tables.get(e[1], ()):
                    fid = res.expr(mod, ref, cls)
                    if fid and fid != src_id:
                        refs[(src_id, fid)] += 1
            else:
                if sink and io is not None:
                    io.add(sink)
                    if loop and sites is not None:
                        sites.append(Site(src_id, "loop_io", line, detail=sink, bounded=bounded, tx=tx))
                if attr in res.unique_methods:
                    guess = res.unique_methods[attr]
                    if guess != src_id:
                        refs[(src_id, guess)] += 1
        else:
            target = res.expr(mod, ev[1], cls)
            if target and target != src_id:
                refs[(src_id, target)] += 1


def analyze_python(root: Path, ignore: list[str], cache: bool = True) -> Graph:
    g = Graph(root=str(root), language="python")
    paths = [p.relative_to(root) for p in iter_files(root, ignore)]
    parsed = parallel.run(root, "python", [(rel.as_posix(), (str(root / rel), rel.as_posix())) for rel in paths], parse_module,
                          tool="python-ir-7", cache=cache)  # fmt: skip
    failed: dict[str, dict] = {}  # files this Python couldn't parse: reported, and analyzed by tree-sitter when it can
    for rel in paths:
        data = parsed.get(rel.as_posix())
        if data is None or "error" in data:
            failed[rel.as_posix()] = parsed.pop(rel.as_posix(), None) or {"error": "can't be read", "fallback": None}
    modules: dict[str, _Module] = {}
    packages = frozenset(rel.parent.as_posix() for rel in paths if rel.name == "__init__.py")
    names = {rel: module_name(rel, packages) for rel in paths}
    taken = Counter(names.values()) + Counter(module_name(rel) for rel in paths)
    for rel in paths:
        data = parsed.get(rel.as_posix())
        if data is None:
            continue
        name = names[rel]
        if taken[name] > 1 and name != module_name(rel):
            name = module_name(rel)  # two folders hold a package of that name: keep the full path, never merge them
        m = _Module(rel.as_posix(), name, data, rel.name == "__init__.py")
        modules[m.name] = m
        g.files.append(File(id=m.rel, module=m.name, loc=data["loc"]))
    known = {name: name for name in modules} | {module_name(Path(m.rel)): name for name, m in modules.items()
                                                  if module_name(Path(m.rel)) not in modules}  # fmt: skip
    for m in modules.values():
        _collect(m, known)
    defs = {name: _functions(m) for name, m in modules.items()}
    res = _Resolver(modules)
    calls: Counter = Counter()
    refs: Counter = Counter()
    imports: Counter = Counter()
    for name, m in modules.items():
        # constants defined here, or imported by name from another module of the codebase
        consts = m.consts | {local for local, (src, sym) in m.symbols.items() if src in modules and sym in modules[src].consts}
        top = Function(
            id=f"{m.rel}::<module>", file=m.rel, name="<module>", qualname="<module>", line=1, end=1, loc=0, kind="module"
        )
        g.functions.append(top)
        top_io: set[str] = set()
        for cls, evs in m.data["top"]:  # class bodies' own statements, decorators and module code
            _link(evs, m, cls, top.id, res, calls, refs, consts, g.sites, top_io)
        for fn, d in defs[name]:
            g.functions.append(fn)
            fn_io: set[str] = set()
            _link(d["deco"], m, d["cls"], top.id, res, calls, refs, consts)
            _link(d["body"], _scoped(m, d.get("imports", []), known), d["cls"], fn.id, res, calls, refs, consts, g.sites, fn_io)
            fn.io = sorted(fn_io)
        top.io = sorted(top_io)
        for t in m.load_imports:
            dst = modules.get(t)
            while dst is None and "." in t:  # "pkg.mod.attr" style: the closest known module
                t = t.rpartition(".")[0]
                dst = modules.get(t)
            if dst and dst.rel != m.rel:
                imports[(m.rel, dst.rel)] += 1
    # obj.name anywhere (obj unknown): a method of that name may be what runs, so it isn't reported as unused.
    attr_names = {a for m in modules.values() for a in m.data["attrs"]}
    for fn in g.functions:
        if fn.kind == "method" and fn.name in attr_names:
            fn.dynamic = True
    g.edges += [Edge(s, d, "call", c) for (s, d), c in calls.items()]
    g.edges += [Edge(s, d, "ref", c) for (s, d), c in refs.items() if (s, d) not in calls]
    g.edges += [Edge(s, d, "import", 1) for (s, d) in imports]
    if failed:
        _not_parsed(g, failed)
    return g


def _not_parsed(g: Graph, failed: dict[str, dict]) -> None:
    """Says which files this Python couldn't parse. Those tree-sitter reads cleanly (newer syntax) join the graph,
    matched by name: their functions aren't reported unused, and the names they use count as references."""
    import sys

    from .generic import link

    version = f"Python {sys.version_info[0]}.{sys.version_info[1]}"
    newer = {rel: d["fallback"] for rel, d in failed.items() if d.get("fallback")}
    lost = sorted(set(failed) - set(newer))
    if newer:
        part = link(Graph(root=g.root, language="python"), newer)
        named: dict[str, list[str]] = {}
        for f in g.functions:
            if f.kind != "module":
                named.setdefault(f.name, []).append(f.id)
        for f in part.functions:
            f.dynamic = True
        for rel, d in newer.items():
            for src, owner in [(f"{rel}::<module>", d["top"]), *((f["id"], f) for f in d["functions"])]:
                used = {c[0] for c in owner["calls"]} | set(owner["refs"])
                part.edges += [Edge(src, named[n][0], "ref", 1) for n in sorted(used) if len(named.get(n, ())) == 1]
        g.merge(part)
        print(f"codefactory: {len(newer)} Python files use syntax newer than {version} ({', '.join(sorted(newer)[:3])}"
              f"{' …' if len(newer) > 3 else ''}): analyzed by tree-sitter instead, matching calls by name.",
              file=sys.stderr)  # fmt: skip
    if lost:
        shown = "; ".join(f"{rel} {failed[rel]['error']}" for rel in lost[:3]) + (" …" if len(lost) > 3 else "")
        print(f"codefactory: {len(lost)} Python files aren't analyzed: {version} can't parse them ({shown}).",
              file=sys.stderr)
