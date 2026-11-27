"""The per-file half of the Python analyzer: one file's ast reduced to plain data (runs in a worker, cached per file).

What a call or name refers to can depend on other modules, so nothing is resolved here. Each reference is kept as a
small expression that python.py resolves once every module is known:
  ["n", name]                       a plain name
  ["a", base or None, attr, dotted]  obj.attr (base: the name at its root, when it's a plain name)
  ["s", table]                      TABLE[key](…): a call through a dispatch table
Events, in source order: ["c", line, in_loop, bounded, expr, io_sink, attr] for calls, ["w", line, bounded] for
awaits in a for/while loop, then ["r", expr] for names used without being called. `bounded` is None (the loop's
length depends on data) or the imported names that must be constants for it to be fixed in the code.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from ..paths import is_test

DB_METHODS = {
    "execute", "executemany", "executescript", "fetchone", "fetchall", "fetchmany", "commit", "rollback", "scalars",
    "scalar", "query", "bulk_create", "bulk_update", "get_or_create", "update_or_create",
}  # fmt: skip
IO_MODULES = {
    "requests", "httpx", "urllib", "aiohttp", "subprocess", "socket", "boto3", "redis", "shutil", "smtplib", "ftplib",
    "sqlite3", "psycopg", "psycopg2", "pymongo", "asyncpg",
}  # fmt: skip
CONTAINER = {"append", "extend", "insert", "pop", "clear", "sort", "reverse", "index", "count", "keys", "values", "items",
             "add", "discard", "setdefault", "popleft", "appendleft"}  # fmt: skip
FRAME = re.compile(r"^(?:df|tb|t|table|frame|data|dataframe|tables)$|(?:^|_)(?:df|tb|frame|dataframe)s?(?:_|$)", re.I)
FILE_METHODS = {"read_text", "write_text", "read_bytes", "write_bytes", "urlopen", "iterdir", "glob", "rglob"}
COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
SMALL = 50
LITERALS = (ast.List, ast.Tuple, ast.Set, ast.Dict)
NONE: frozenset = frozenset()


CACHED_LOOKUPS = {"get_for_id", "get_for_model", "get_for_models", "get_current", "clear_cache"}


def _preorder(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def shape_of(node) -> tuple[str, str]:
    """(hash, tokens) of a function's structure, in source order. Local names (arguments, variables) and the
    docstring are blanked out, so a copy with renamed variables still matches; names it uses from outside (calls,
    attributes) are kept, so two small functions that merely look alike don't. The tokens feed near-duplicate
    detection; the hash, exact duplicates."""
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    nodes = [n for stmt in body for n in _preorder(stmt)]
    local = {a.arg for a in ast.walk(node.args) if isinstance(a, ast.arg)}
    local |= {n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    if len(nodes) < 15:  # a line or two (raise NotImplementedError, return self.x): alike by nature, not copies
        return "", ""
    parts = []
    for n in nodes:
        parts.append(type(n).__name__)
        if hasattr(n, "op"):
            parts.append(type(n.op).__name__)
        elif isinstance(n, ast.Compare):
            parts += [type(o).__name__ for o in n.ops]
        elif isinstance(n, ast.Attribute):
            parts.append(n.attr)
        elif isinstance(n, ast.Name) and n.id not in local:
            parts.append(n.id)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            # a string's words count: two functions differing only in their SQL or messages aren't copies
            parts += [f"S:{w}" for w in n.value.split()[:24]]
        elif isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool):
            parts.append(f"N:{n.value}")
    text = " ".join(parts)
    return hashlib.sha1(text.encode("utf-8", "surrogatepass")).hexdigest()[:16], text


def dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def io_call(func: ast.AST, call: ast.Call | None = None) -> str | None:
    """The I/O call's name ("cursor.execute"), or None. A SQL string starting with SELECT marks a read."""
    full = dotted(func) or ""
    last = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
    head = full.split(".")[0]
    sink = None
    receiver = full.rsplit(".", 1)[0] if "." in full else ""
    if isinstance(func, ast.Name) and last in ("open", "urlopen"):
        sink = last
    elif last in CACHED_LOOKUPS and ".objects." in f".{full}.":
        sink = None  # Django caches these per process: ContentType.objects.get_for_id(pk), Site.objects.get_current()
    elif (head in IO_MODULES and last not in CONTAINER) or ".objects." in f".{full}." or full in ("time.sleep", "asyncio.sleep"):
        sink = full  # (not `requests.append(r)`: a list someone named requests)
    elif (
        isinstance(func, ast.Attribute)
        and (last in DB_METHODS or last in FILE_METHODS)
        and not (last == "query" and FRAME.search(receiver.rsplit(".", 1)[-1]))  # pandas' df.query("x > 1")
    ):
        sink = full or last
    first = call.args[0] if call is not None and call.args else None
    if isinstance(first, ast.JoinedStr) and first.values and isinstance(first.values[0], ast.Constant):
        first = first.values[0]  # f"SELECT … {table}": the leading text says what kind of statement it is
    is_text = isinstance(first, ast.Constant) and isinstance(first.value, str)
    word = re.match(r"\s*(\w+)", first.value) if is_text else None  # (triple-quoted SQL starts on a new line)
    verb = word.group(1).upper() if word else ""
    if sink and verb in ("SELECT", "WITH"):
        sink += '("SELECT …")'
    elif sink and verb in ("INSERT", "UPDATE", "DELETE", "REPLACE", "UPSERT", "MERGE"):
        sink += f'("{verb} …")'  # what it changes is visible: a write, for the security checks
    return sink


def const_deps(e: ast.AST, local: set[str], maybe: set[str]) -> frozenset | None:
    """A sequence whose length is fixed in the code (a literal, a module-level constant holding one, range(N) or
    x[:N] with a small N, or one of those through .items()/sorted()/enumerate()…): the imported names that must turn
    out to be constants for that to hold, or None if it isn't one."""
    if isinstance(e, LITERALS):
        return NONE
    if isinstance(e, ast.Name):
        return NONE if e.id in local else frozenset([e.id]) if e.id in maybe else None
    if isinstance(e, ast.Attribute):
        d = dotted(e) or ""
        if e.attr in local or d in local:
            return NONE
        return frozenset([e.attr]) if e.attr in maybe else None
    if isinstance(e, ast.Subscript) and isinstance(e.slice, ast.Slice):
        up = e.slice.upper
        return NONE if isinstance(up, ast.Constant) and isinstance(up.value, int) and up.value <= SMALL else None
    if isinstance(e, ast.Call):
        f = e.func
        if isinstance(f, ast.Name) and f.id == "range" and e.args:
            last = e.args[1] if len(e.args) > 1 else e.args[0]
            return NONE if isinstance(last, ast.Constant) and isinstance(last.value, int) and last.value <= SMALL else None
        if isinstance(f, ast.Name) and f.id in ("sorted", "reversed", "enumerate", "list", "tuple", "set", "zip") and e.args:
            out = NONE
            for a in e.args[:2]:
                d = const_deps(a, local, maybe)
                if d is None:
                    return None
                out |= d
            return out
        if isinstance(f, ast.Attribute) and f.attr in ("items", "keys", "values"):
            return const_deps(f.value, local, maybe)
    return None


def _and(bounded: frozenset | None, d: frozenset | None) -> frozenset | None:
    return None if bounded is None or d is None else bounded | d


def walk_loops(nodes, local: set[str], maybe: set[str]):
    """Every node under `nodes`, with whether it runs once per iteration of a loop (for/while/comprehension), whether
    that's a for/while statement (where an await waits on each round in turn), its boundedness (see the module
    docstring; None outside loops), and whether it's inside a transaction block. A nested def starts afresh."""
    stack = [(n, False, False, NONE, False) for n in reversed(list(nodes))]
    while stack:
        n, loop, stmt, bounded, tx = stack.pop()
        yield n, loop, stmt, (bounded if loop else None), tx
        if isinstance(n, (ast.With, ast.AsyncWith)) and any(_is_tx(i.context_expr) for i in n.items):
            kids = [(c, loop, stmt, bounded, True) for c in ast.iter_child_nodes(n)]
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            inner = _and(bounded, const_deps(n.iter, local, maybe))
            kids = [(n.target, loop, stmt, bounded, tx), (n.iter, loop, stmt, bounded, tx)]
            kids += [(c, True, True, inner, tx) for c in n.body + n.orelse]
        elif isinstance(n, ast.While):
            kids = [(n.test, True, True, None, tx)] + [(c, True, True, None, tx) for c in n.body + n.orelse]
        elif isinstance(n, COMPREHENSIONS):
            gens = n.generators
            inner = bounded
            for g in gens:
                inner = _and(inner, const_deps(g.iter, local, maybe))
            kids = [(gens[0].iter, loop, stmt, bounded, tx)]
            kids += [(c, True, stmt, inner, tx) for c in ast.iter_child_nodes(n) if c is not gens[0]]
            kids += [(c, True, stmt, inner, tx) for c in ast.iter_child_nodes(gens[0]) if c is not gens[0].iter]
        elif isinstance(n, SCOPES):
            kids = [(c, False, False, NONE, False) for c in ast.iter_child_nodes(n)]
        else:
            kids = [(c, loop, stmt, bounded, tx) for c in ast.iter_child_nodes(n)]
        stack.extend(reversed(kids))


TX = re.compile(
    r"(?:^|\.)(?:session|transaction|atomic|begin|begin_nested|connect|savepoint|batch|bulk_writer|cursor)$"
    r"|^(?:conn|connection|db|tx|txn)$",
    re.I,
)


def _is_tx(expr: ast.AST) -> bool:
    """`with db.session(…):`, `with transaction.atomic():`, `with conn:` (a sqlite3 connection commits once at the end)."""
    target = expr.func if isinstance(expr, ast.Call) else expr
    return bool(TX.search(dotted(target) or ""))


def branches(fn) -> int:
    """Decision points in the function (if, loops, except, case, conditional expressions, and/or)."""
    n = 0
    for x in ast.walk(fn):
        if isinstance(x, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.match_case)):
            n += 1
        elif isinstance(x, ast.BoolOp):
            n += len(x.values) - 1
        elif isinstance(x, ast.comprehension):
            n += 1 + len(x.ifs)
    return n


def _type_checking(test: ast.AST) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _imports(tree: ast.Module):
    """Every import, with whether it runs when the module loads. Imports inside functions (often placed there to
    avoid an import loop) and under `if TYPE_CHECKING:` don't: they can't make a loop at load time."""
    stack = [(n, True) for n in reversed(tree.body)]
    while stack:
        n, at_load = stack.pop()
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            yield n, at_load
            continue
        if isinstance(n, ast.If) and _type_checking(n.test):
            kids = [(c, False) for c in n.body] + [(c, at_load) for c in n.orelse]
        elif isinstance(n, SCOPES):
            kids = [(c, False) for c in ast.iter_child_nodes(n)]
        else:
            kids = [(c, at_load) for c in ast.iter_child_nodes(n)]
        stack.extend(reversed(kids))


class _Ctx:
    """What one module can tell about its own names, to keep only references that could resolve."""

    def __init__(self, tree: ast.Module, imports: list):
        self.funcs = {n.name for n in tree.body if isinstance(n, FUNCS)}
        self.classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
        self.from_locals = {i[3] or i[2] for i in imports if i[0] == "from"}
        self.import_heads = {(i[2] or i[1].split(".")[0]) for i in imports if i[0] == "import"} | {
            i[1] for i in imports if i[0] == "import"
        }
        self.bases = {"self", "cls"} | self.classes | self.from_locals | self.import_heads
        self.local_consts: set[str] = set()
        self.mocked: set[int] = set()  # nodes naming what a test mocks: not a reference to it

    def expr(self, node: ast.AST) -> list | None:
        if isinstance(node, ast.Name):
            return ["n", node.id] if node.id in self.funcs or node.id in self.classes or node.id in self.from_locals else None
        if isinstance(node, ast.Attribute):
            base = node.value.id if isinstance(node.value, ast.Name) else None
            d = dotted(node)
            head = d.split(".")[0] if d else None
            if (base and base in self.bases) or (head and head in self.import_heads | self.from_locals):
                return ["a", base, node.attr, d]
        return None


# A Django QuerySet (and a boto3 collection) is lazy: building one runs nothing, evaluating it runs the query
LAZY_QS = {
    "all", "filter", "exclude", "annotate", "alias", "order_by", "reverse", "distinct", "values", "values_list", "none",
    "union", "intersection", "difference", "select_related", "prefetch_related", "defer", "only", "using", "extra",
    "select_for_update", "dates", "datetimes",
}  # fmt: skip
EVALUATES = {"list", "len", "bool", "tuple", "set", "frozenset", "sorted", "sum", "any", "all", "next", "iter", "dict",
             "enumerate", "zip", "max", "min", "reversed", "print", "str", "repr", "map", "filter"}  # fmt: skip
STORES = {"append", "extend", "insert", "add", "appendleft"}
QS_WRAPPERS = {"Exists", "Subquery", "Q", "Prefetch"}
COMBINE = (ast.BitOr, ast.BitAnd, ast.BitXor)


def _pos(n) -> tuple[int, int]:
    return n.lineno, n.col_offset


class _Lazy:
    """Whether a QuerySet built in a function is ever evaluated there. Where it goes is followed through further
    chaining (`.filter()`), `|`/`&`, Exists()/Subquery() and local variables; returning it, storing it (a list, an
    attribute) or comparing it with `is` runs nothing. Anything else (iteration, len(), indexing, a `.get()`/`.count()`
    /`.delete()`, a call whose result is discarded) counts as evaluating it. Once it has gone through some other call
    (`where_filter(qs, …)`), only chaining or `|`/`&` on the result shows it's still a QuerySet."""

    def __init__(self, roots):
        self.nodes = [n for r in roots for n in ast.walk(r)]
        self.up = {id(c): n for n in self.nodes for c in ast.iter_child_nodes(n)}

    def unevaluated(self, call: ast.Call) -> bool:
        if not (isinstance(call.func, ast.Attribute) and call.func.attr in LAZY_QS):
            return False
        return not self.evaluated(call, set(), False)

    def evaluated(self, e, seen: set, via: bool) -> bool:
        p = self.up.get(id(e))
        if isinstance(p, ast.keyword):
            e, p = p, self.up.get(id(p))
        if isinstance(p, ast.Attribute):
            q = self.up.get(id(p))
            if isinstance(q, ast.Call) and q.func is p:
                return p.attr not in LAZY_QS or self.evaluated(q, seen, False)
            return via  # qs.model, qs.query: reading an attribute runs nothing
        if isinstance(p, ast.Subscript) and p.value is e:
            return not isinstance(p.slice, ast.Slice) or self.evaluated(p, seen, via)
        if isinstance(p, ast.Call) and p.func is not e:
            f = p.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            if isinstance(f, ast.Name) and name in EVALUATES:
                return True
            if isinstance(f, ast.Attribute) and name in STORES:
                return via
            return self.evaluated(p, seen, via or not (name in QS_WRAPPERS or name in LAZY_QS))
        if isinstance(p, ast.BinOp) and isinstance(p.op, COMBINE):
            return self.evaluated(p, seen, False)
        if isinstance(p, ast.IfExp) and p.test is not e:
            return self.evaluated(p, seen, via)
        if isinstance(p, (ast.Return, ast.Yield, ast.Lambda, ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return via
        if isinstance(p, ast.Compare):
            return via or not all(isinstance(o, (ast.Is, ast.IsNot)) for o in p.ops)
        if isinstance(p, (ast.Assign, ast.AnnAssign)) and p.value is e:
            return self.bound(p, seen, via)
        if isinstance(p, ast.AugAssign) and p.value is e:
            return not isinstance(p.op, COMBINE) or self.bound(p, seen, False)
        return True

    def bound(self, stmt, seen: set, via: bool) -> bool:
        """Whether the value a statement binds is evaluated by a later use of the names it binds."""
        if id(stmt) in seen:
            return False
        seen.add(id(stmt))
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        if any(isinstance(t, (ast.Tuple, ast.List, ast.Starred)) for t in targets):
            return True  # a, b = qs: unpacking iterates it
        if via and not all(isinstance(t, ast.Name) for t in targets):
            return True
        for name in {t.id for t in targets if isinstance(t, ast.Name)}:
            for n in self.nodes:
                if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                    # qs |= more: still a QuerySet, under the same name; qs += x reads it
                    if (
                        n is not stmt
                        and self.reaches(stmt, n.target, name)
                        and (not isinstance(n.op, COMBINE) or self.bound(n, seen, False))
                    ):
                        return True
                elif (
                    isinstance(n, ast.Name)
                    and n.id == name
                    and isinstance(n.ctx, ast.Load)
                    and (self.reaches(stmt, n, name) and self.evaluated(n, seen, via))
                ):
                    return True
        return False

    def _ancestors(self, n) -> list:
        out = []
        while (n := self.up.get(id(n))) is not None:
            out.append(n)
        return out

    def _block(self, s):
        p = self.up.get(id(s))
        for field in ("body", "orelse", "finalbody"):
            if any(x is s for x in getattr(p, field, None) or []):
                return id(p), field
        return None if p is not None else "root"

    def reaches(self, a, use, name: str) -> bool:
        """Whether binding `a` may be the one `use` reads: not when a later assignment in an enclosing block always
        runs in between (`x = qs` in a loop, then `x = other` after it)."""
        anc = self._ancestors(use)
        if any(x is a for x in anc):
            return False  # qs = qs.filter(…): the right side reads the earlier binding
        if _pos(use) < _pos(a):  # only through a loop around both
            return any(isinstance(x, (ast.For, ast.AsyncFor, ast.While)) and x in self._ancestors(a) for x in anc)
        blocks = {self._block(s): s for s in anc if isinstance(s, ast.stmt)}
        for b in self.nodes:
            if b is a or not isinstance(b, (ast.Assign, ast.AnnAssign)) or not _pos(a) < _pos(b) < _pos(use):
                continue
            targets = b.targets if isinstance(b, ast.Assign) else [b.target]
            if not any(isinstance(t, ast.Name) and t.id == name for t in targets) or any(x is b for x in anc):
                continue
            s = blocks.get(self._block(b))
            if s is not None and _pos(b) < _pos(s):
                return False
        return True


BY_NAME = {"getattr", "hasattr", "setattr", "delattr"}


def by_name(call: ast.Call) -> str | None:
    """The attribute a getattr/hasattr/setattr call names with a literal string, if it does."""
    if isinstance(call.func, ast.Name) and call.func.id in BY_NAME and len(call.args) >= 2:
        arg = call.args[1]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.isidentifier():
            return arg.value
    return None


def events(nodes, ctx: _Ctx, sites: bool = True) -> list:
    out: list = []
    refs: list = []
    call_funcs = set()
    nodes = list(nodes)
    walked = list(walk_loops(nodes, ctx.local_consts, ctx.from_locals))
    lazy = None
    for n, loop, stmt, bounded, tx in walked:
        b = sorted(bounded) if bounded is not None else None
        if isinstance(n, ast.Await) and stmt and sites:
            out.append(["w", n.lineno, b])
        if isinstance(n, ast.Call):
            call_funcs.add(id(n.func))
            f = n.func
            if isinstance(f, (ast.Name, ast.Attribute)):
                expr = ctx.expr(f)
            elif isinstance(f, ast.Subscript):
                root = f
                while isinstance(root, ast.Subscript):
                    root = root.value
                expr = ["s", root.id] if isinstance(root, ast.Name) else None
            else:
                expr = None
            attr = f.attr if isinstance(f, ast.Attribute) else None
            sink = io_call(f, n)
            if sink and ".objects." in f".{sink}.":
                lazy = lazy or _Lazy(nodes)
                sink = None if lazy.unevaluated(n) else sink
            out.append(["c", n.lineno, bool(loop), b, expr, sink, attr, tx])
            # getattr(obj, "save"): the same as obj.save, written as a string
            name = by_name(n)
            target = n.args[0] if name and isinstance(n.args[0], (ast.Name, ast.Attribute)) else None
            if target is not None and (e := ctx.expr(ast.Attribute(value=target, attr=name, ctx=ast.Load()))):
                refs.append(["r", e])
    for n, *_ in walked:
        if id(n) in call_funcs or id(n) in ctx.mocked:
            continue
        if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(n.ctx, ast.Load) and (e := ctx.expr(n)):
            refs.append(["r", e])
    return out + refs


MOCK_ATTRS = re.compile(
    r"^(?:return_value|side_effect|call_count|called|call_args(?:_list)?|mock_calls|reset_mock"
    r"|assert_\w+)$"
)
MOCKS = re.compile(r"^(?:Mock|MagicMock|AsyncMock|NonCallableMock|create_autospec)$")
SKIP = re.compile(r"(?:^|\.)(?:unittest\.skip|pytest\.mark\.skip|skip)$")


def mock_targets(tree: ast.Module, ctx: _Ctx) -> list:
    """What a test file replaces with mocks: ["s", "pkg.mod.fn"] for patch("…") / monkeypatch.setattr("…", v),
    ["o", expr, "name"] for patch.object(Obj, "name") / monkeypatch.setattr(Obj, "name", v), ["e", expr] for
    `Obj.fn = Mock()` and `Obj.fn.return_value = …`. The nodes naming them go in ctx.mocked: mocking a function
    doesn't run it."""
    out: list = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and (d := dotted(n.func)) and n.args:
            first = n.args[0]
            text = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
            last = d.rsplit(".", 1)[-1]
            if text and (last == "patch" or d.endswith("monkeypatch.setattr")):
                out.append(["s", text])
            elif (d.endswith("patch.object") or d.endswith("monkeypatch.setattr")) and len(n.args) >= 2:
                name = n.args[1]
                if isinstance(name, ast.Constant) and isinstance(name.value, str) and (e := ctx.expr(first)):
                    out.append(["o", e, name.value])
                    ctx.mocked.add(id(first))
        elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            d = dotted(n.value.func) or ""
            if MOCKS.match(d.rsplit(".", 1)[-1]):
                out += [["e", e] for t in n.targets if isinstance(t, ast.Attribute) and (e := ctx.expr(t))]
        elif (
            isinstance(n, ast.Attribute)
            and MOCK_ATTRS.match(n.attr)
            and isinstance(n.value, ast.Attribute)
            and (e := ctx.expr(n.value))  # Obj.fn.return_value = …, Obj.fn.assert_called_once()
        ):
            out.append(["e", e])
            ctx.mocked.add(id(n.value))
    return out


def _skipped(node) -> bool:
    """@unittest.skip / @pytest.mark.skip (not the conditional skipIf): the test never runs."""
    return any(SKIP.search(dotted(x.func if isinstance(x, ast.Call) else x) or "") for x in node.decorator_list)


def _local_imports(fn) -> list:
    """Imports inside a function: they name things for that function only (two functions may import different
    `summarize`s), so they're resolved per function as well as for the module."""
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Import):
            out += [["import", a.name, a.asname, False] for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            out += [["from", n.module, n.level, a.name, a.asname, False] for a in n.names]
    return out


def parse_module(path: str, rel: str) -> dict:
    """The per-file step: everything python.py needs from one file, or {"error": why, "fallback": …} if this Python
    can't parse it (python.py reports those instead of dropping them quietly)."""
    try:
        # (utf-8-sig: a byte-order mark, which Windows editors write, is a syntax error to ast.parse on a str)
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(text, filename=rel)
    except SyntaxError as e:
        return {"error": f"line {e.lineno}: {e.msg}", "fallback": _fallback(path, rel)}
    except OSError as e:
        return {"error": f"can't be read ({e.strerror or type(e).__name__})", "fallback": None}
    except (ValueError, RecursionError) as e:  # (null bytes on older Pythons; nesting too deep for the parser)
        return {"error": type(e).__name__, "fallback": None}
    imports = []  # ["import", name, asname, at_load] / ["from", module, level, name, asname, at_load]
    for node, at_load in _imports(tree):
        if isinstance(node, ast.Import):
            imports += [["import", a.name, a.asname, at_load] for a in node.names]
        else:
            imports += [["from", node.module, node.level, a.name, a.asname, at_load] for a in node.names]
    # the ctx wants (kind, name, asname) shapes: normalise "from" entries to (kind, module, name, asname)
    ctx = _Ctx(tree, [["import", i[1], i[2]] if i[0] == "import" else ["from", i[1], i[3], i[4]] for i in imports])
    tables, consts = {}, []
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if isinstance(value, LITERALS):
            for t in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if isinstance(t, ast.Name):
                    consts.append(t.id)
                    tables[t.id] = [e for x in ast.walk(value) if isinstance(x, (ast.Name, ast.Attribute)) and (e := ctx.expr(x))]
    ctx.local_consts = set(consts)
    mocks = mock_targets(tree, ctx) if is_test(rel) else []
    exports = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
            and isinstance(node.value, (ast.List, ast.Tuple))
        ):
            exports += [e.value for e in node.value.elts if isinstance(e, ast.Constant)]
    defs = []

    def add(node, qualname: str, kind: str, cls: str | None, skip: bool = False) -> None:
        shape, tokens = shape_of(node)
        first = node.body[0] if node.body else None
        doc = (
            first.end_lineno - first.lineno + 1
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
            else 0
        )
        defs.append({
            "qualname": qualname, "name": node.name, "line": node.lineno, "end": getattr(node, "end_lineno", node.lineno),
            "kind": kind, "decorated": bool(node.decorator_list), "exported": node.name in exports or node.name == "main",
            "overload": any((dotted(x) or "").rsplit(".", 1)[-1] == "overload" for x in node.decorator_list),
            "shape": shape, "tokens": tokens, "cls": cls,
            "deco": events(node.decorator_list, ctx, sites=False), "doc": doc,
            "body": [] if is_test(rel) and (skip or _skipped(node)) else events(node.body, ctx),
            "branches": branches(node),
            "imports": _local_imports(node),
        })  # fmt: skip

    top = []
    for node in tree.body:
        if isinstance(node, FUNCS):
            add(node, node.name, "function", None)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, FUNCS):
                    add(item, f"{node.name}.{item.name}", "method", node.name, _skipped(node))
            # the class body's own statements, its methods' decorators and its own decorators
            stmts = [s for s in node.body if not isinstance(s, FUNCS)]
            stmts += [d for s in node.body if isinstance(s, FUNCS) for d in s.decorator_list]
            top.append([node.name, events(stmts + node.decorator_list, ctx)])
        else:
            top.append([None, events([node], ctx)])
    return {
        "loc": len(text.splitlines()),
        "imports": imports,
        "consts": consts,
        "tables": tables,
        "exports": exports,
        "classes": sorted(ctx.classes),
        "defs": defs,
        "top": top,
        "mocks": mocks,
        # names used as obj.name, or as getattr(obj, "name"): a method of that name may be what runs
        "attrs": sorted(
            {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            | {s for n in ast.walk(tree) if isinstance(n, ast.Call) and (s := by_name(n))}
        ),
    }


def _fallback(path: str, rel: str) -> dict | None:
    """Syntax newer than the running Python (PEP 695's `def f[T]()` on 3.11): tree-sitter's grammar parses it without
    errors, so its functions come from the general analyzer rather than vanishing. A real syntax error parses with
    errors there too: None."""
    try:
        from tree_sitter_language_pack import get_parser

        from .treewalk import MAX_BYTES, walk

        source = Path(path).read_bytes()
        parser = get_parser("python")
        if len(source) > MAX_BYTES or parser.parse(source).root_node.has_error:
            return None
        data = walk(source, parser, rel)
    except Exception:  # no language pack, a grammar that can't load: reported as not analyzed
        return None
    data["lang"] = "python"
    return data
