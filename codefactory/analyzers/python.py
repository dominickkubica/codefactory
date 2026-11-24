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
from . import parallel
from .python_parse import parse_module


def iter_files(root: Path, ignore: list[str]) -> list[Path]:
    skip = set(ignore)
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        # hidden folders (.claude, .github, .venv…) hold tooling and environments, not the product's code
        if any(part in skip or part.endswith(".egg-info") or part.startswith(".") for part in rel.parts[:-1]):
            continue
        out.append(p)
    return out


def module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[0] == "src" and len(parts) > 1:
        parts = parts[1:]
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


def _resolve_relative(mod: _Module, level: int, target: str | None) -> str:
    base = mod.name.split(".") if mod.is_pkg else mod.name.split(".")[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, target] if target else base)


def _scoped(mod: _Module, imports: list, known: set[str]) -> _Module:
    """The module as one function sees it: its own imports on top of the module's."""
    if not imports:
        return mod
    view = copy.copy(mod)
    view.aliases, view.symbols, view.load_imports = dict(mod.aliases), dict(mod.symbols), set()
    _apply_imports(view, imports, known)
    return view


def _collect(mod: _Module, known: set[str]) -> None:
    _apply_imports(mod, mod.data["imports"], known)


def _apply_imports(mod: _Module, imports: list, known: set[str]) -> None:
    for imp in imports:
        if imp[0] == "import":
            _, name, asname, at_load = imp
            if asname:
                mod.aliases[asname] = name
            else:
                mod.aliases[name.split(".")[0]] = name.split(".")[0]
                mod.aliases[name] = name
            if at_load:
                mod.load_imports.add(name)
        else:
            _, module, level, name, asname, at_load = imp
            src = _resolve_relative(mod, level, module) if level else (module or "")
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
    defined twice (a property's getter and setter) gets its line in the id; name lookups keep finding the first."""
    out = []
    for d in mod.data["defs"]:
        q = d["qualname"]
        fid = f"{mod.rel}::{q}" if q not in mod.funcs else f"{mod.rel}::{q}@{d['line']}"
        f = Function(
            id=fid, file=mod.rel, name=d["name"], qualname=q, line=d["line"], end=d["end"], loc=d["end"] - d["line"] + 1,
            kind=d["kind"], decorated=d["decorated"], exported=d["exported"], shape=d["shape"], tokens=d["tokens"],
            doc=d.get("doc", 0), branches=d.get("branches", 0),
        )  # fmt: skip
        mod.funcs.setdefault(q, f)
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
                return self.in_module(modname, sym)
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
                          tool="python-ir-2", cache=cache)  # fmt: skip
    modules: dict[str, _Module] = {}
    for rel in paths:
        data = parsed.get(rel.as_posix())
        if data is None:
            continue
        m = _Module(rel.as_posix(), module_name(rel), data, rel.name == "__init__.py")
        modules[m.name] = m
        g.files.append(File(id=m.rel, module=m.name, loc=data["loc"]))
    known = set(modules)
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
    return g
