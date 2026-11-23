"""Python analyzer: files, functions, imports and calls from the standard library's ast module (nothing is run).

Calls are resolved statically, so the graph is an approximation: plain names, imported names, module.attr,
self.method / cls.method and ClassName() (to __init__) resolve; calls through variables, getattr or dynamic
dispatch don't. A function passed by name (a callback, a decorator argument) is kept as a "ref" edge so it
doesn't look dead.
"""
from __future__ import annotations

import ast
import hashlib
from collections import Counter
from pathlib import Path

from ..graph import Edge, File, Function, Graph


def iter_files(root: Path, ignore: list[str]) -> list[Path]:
    skip = set(ignore)
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in skip or part.endswith(".egg-info") for part in rel.parts[:-1]):
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


def shape_of(node) -> str:
    """Hash of a function's structure. Local names (arguments, variables) and the docstring are blanked out, so
    a copy with renamed variables still matches; names it uses from outside (calls, attributes) are kept, so two
    small functions that merely look alike don't."""
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    nodes = [n for stmt in body for n in ast.walk(stmt)]
    local = {a.arg for a in ast.walk(node.args) if isinstance(a, ast.arg)}
    local |= {n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    if len(nodes) < 15:  # a line or two (raise NotImplementedError, return self.x): alike by nature, not copies
        return ""
    parts = []
    for n in nodes:
        if True:
            parts.append(type(n).__name__)
            if hasattr(n, "op"):
                parts.append(type(n.op).__name__)
            elif isinstance(n, ast.Compare):
                parts += [type(o).__name__ for o in n.ops]
            elif isinstance(n, ast.Attribute):
                parts.append(n.attr)
            elif isinstance(n, ast.Name) and n.id not in local:
                parts.append(n.id)
    return hashlib.sha1(" ".join(parts).encode()).hexdigest()[:16] if parts else ""


class _Module:
    def __init__(self, rel: str, name: str, tree: ast.Module, is_pkg: bool):
        self.rel, self.name, self.tree, self.is_pkg = rel, name, tree, is_pkg
        self.funcs: dict[str, Function] = {}  # qualname -> function
        self.classes: set[str] = set()
        self.aliases: dict[str, str] = {}  # local name -> module name
        self.symbols: dict[str, tuple[str, str]] = {}  # local name -> (module name, symbol)
        self.exports: set[str] = set()


def _resolve_relative(mod: _Module, level: int, target: str | None) -> str:
    base = mod.name.split(".") if mod.is_pkg else mod.name.split(".")[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, target] if target else base)


def _collect(mod: _Module, known: set[str]) -> None:
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    mod.aliases[a.asname] = a.name
                else:
                    mod.aliases[a.name.split(".")[0]] = a.name.split(".")[0]
                    mod.aliases[a.name] = a.name
        elif isinstance(node, ast.ImportFrom):
            src = _resolve_relative(mod, node.level, node.module) if node.level else (node.module or "")
            for a in node.names:
                local = a.asname or a.name
                full = f"{src}.{a.name}" if src else a.name
                if full in known:
                    mod.aliases[local] = full
                else:
                    mod.symbols[local] = (src, a.name)
    for node in mod.tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                mod.exports |= {e.value for e in node.value.elts if isinstance(e, ast.Constant)}


def _add_function(mod: _Module, node, qualname: str, kind: str) -> Function:
    end = getattr(node, "end_lineno", node.lineno)
    f = Function(
        id=f"{mod.rel}::{qualname}", file=mod.rel, name=node.name, qualname=qualname, line=node.lineno, end=end,
        loc=end - node.lineno + 1, kind=kind, decorated=bool(node.decorator_list),
        exported=node.name in mod.exports or node.name == "main", shape=shape_of(node),
    )
    mod.funcs[qualname] = f
    return f


def _index_defs(mod: _Module) -> list[tuple[Function, ast.AST, str | None]]:
    """Top-level functions and class methods. Nested functions belong to the function that holds them."""
    out = []
    for node in mod.tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((_add_function(mod, node, node.name, "function"), node, None))
        elif isinstance(node, ast.ClassDef):
            mod.classes.add(node.name)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append((_add_function(mod, item, f"{node.name}.{item.name}", "method"), item, node.name))
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

    def attr(self, mod: _Module, node: ast.Attribute, cls: str | None) -> str | None:
        v = node.value
        if isinstance(v, ast.Name):
            if v.id in ("self", "cls") and cls:
                f = mod.funcs.get(f"{cls}.{node.attr}")
                return f.id if f else None
            if v.id in mod.aliases:
                return self.in_module(mod.aliases[v.id], node.attr)
            if v.id in mod.classes:
                f = mod.funcs.get(f"{v.id}.{node.attr}")
                return f.id if f else None
            if v.id in mod.symbols:  # an imported class: Class.method
                src, cname = mod.symbols[v.id]
                m = self.modules.get(src)
                f = m.funcs.get(f"{cname}.{node.attr}") if m else None
                return f.id if f else None
        dotted = _dotted(node)
        if dotted:  # package.module.func
            modname, _, sym = dotted.rpartition(".")
            head = modname.split(".")[0]
            if head in mod.aliases:
                return self.in_module(modname, sym)
        return None


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _edges_from(body_nodes, mod: _Module, cls: str | None, src_id: str, res: _Resolver, calls: Counter, refs: Counter):
    call_funcs = set()
    for stmt in body_nodes:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                call_funcs.add(id(n.func))
                target = res.name(mod, n.func.id) if isinstance(n.func, ast.Name) else (
                    res.attr(mod, n.func, cls) if isinstance(n.func, ast.Attribute) else None)
                if target and target != src_id:
                    calls[(src_id, target)] += 1
                elif not target and isinstance(n.func, ast.Attribute) and n.func.attr in res.unique_methods:
                    guess = res.unique_methods[n.func.attr]
                    if guess != src_id:
                        refs[(src_id, guess)] += 1
    for stmt in body_nodes:
        for n in ast.walk(stmt):
            if id(n) in call_funcs:
                continue
            target = None
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                target = res.name(mod, n.id)
            elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
                target = res.attr(mod, n, cls)
            if target and target != src_id:
                refs[(src_id, target)] += 1


def analyze_python(root: Path, ignore: list[str]) -> Graph:
    g = Graph(root=str(root), language="python")
    modules: dict[str, _Module] = {}
    for path in iter_files(root, ignore):
        rel = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text, filename=str(rel))
        except (SyntaxError, ValueError):
            continue  # not valid for this Python: skip rather than fail the whole map
        m = _Module(rel.as_posix(), module_name(rel), tree, rel.name == "__init__.py")
        modules[m.name] = m
        g.files.append(File(id=m.rel, module=m.name, loc=len(text.splitlines())))
    known = set(modules)
    for m in modules.values():
        _collect(m, known)
    defs = {name: _index_defs(m) for name, m in modules.items()}
    res = _Resolver(modules)
    calls: Counter = Counter()
    refs: Counter = Counter()
    imports: Counter = Counter()
    for name, m in modules.items():
        top = Function(id=f"{m.rel}::<module>", file=m.rel, name="<module>", qualname="<module>", line=1,
                       end=1, loc=0, kind="module")
        g.functions.append(top)
        top_level = [n for n in m.tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for n in top_level:  # class bodies' own statements, decorators and module code
            if isinstance(n, ast.ClassDef):
                stmts = [s for s in n.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
                stmts += [d for s in n.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                          for d in s.decorator_list]
                _edges_from(stmts + n.decorator_list, m, n.name, top.id, res, calls, refs)
            else:
                _edges_from([n], m, None, top.id, res, calls, refs)
        for fn, node, cls in defs[name]:
            g.functions.append(fn)
            _edges_from(node.decorator_list, m, cls, top.id, res, calls, refs)
            _edges_from(node.body, m, cls, fn.id, res, calls, refs)
        targets = set(m.aliases.values()) | {src for src, _ in m.symbols.values()}
        for t in targets:
            dst = modules.get(t)
            while dst is None and "." in t:  # "pkg.mod.attr" style: the closest known module
                t = t.rpartition(".")[0]
                dst = modules.get(t)
            if dst and dst.rel != m.rel:
                imports[(m.rel, dst.rel)] += 1
    # obj.name anywhere (obj unknown): a method of that name may be what runs, so it isn't reported as unused.
    attr_names = {n.attr for m in modules.values() for n in ast.walk(m.tree) if isinstance(n, ast.Attribute)}
    for fn in g.functions:
        if fn.kind == "method" and fn.name in attr_names:
            fn.dynamic = True
    g.edges += [Edge(s, d, "call", c) for (s, d), c in calls.items()]
    g.edges += [Edge(s, d, "ref", c) for (s, d), c in refs.items() if (s, d) not in calls]
    g.edges += [Edge(s, d, "import", 1) for (s, d) in imports]
    return g
