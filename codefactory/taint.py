"""Data flow (taint) for Python: does a value from a network request reach a dangerous call, and through which
variables?

Per function, the analysis finds which parameters (and which sources inside it) reach a sink, and which reach the
return value. Those summaries are combined across the call graph to a fixed point, so a request parameter handed to a
helper that builds SQL is followed into the helper. A value passed through a sanitizer (int(), uuid.UUID(),
shlex.quote, secure_filename, html.escape…) stops being tainted; SQL with bound parameters is never a sink, because
its query text is a constant.

Within a function it's flow-insensitive (a variable tainted anywhere is tainted everywhere) and an unknown call with
a tainted argument returns a tainted value: generous on purpose, because the sinks are specific.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .graph import Flag, Graph

ROUTE_ATTRS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket"}
REQUEST_ATTRS = {"args", "form", "values", "json", "data", "files", "cookies", "headers", "query_params", "path_params",
                 "GET", "POST", "body", "FILES", "COOKIES", "META", "get_json", "query_string"}  # fmt: skip
SANITIZERS = {"int", "float", "bool", "len", "abs", "round", "UUID", "uuid4", "basename", "secure_filename", "quote",
              "escape", "clean", "quote_plus", "urlencode", "isdigit", "isalnum", "hexdigest", "count"}  # fmt: skip
SQL = {"execute", "executemany", "executescript", "raw", "text", "extra"}
SHELL = {"system", "popen", "getoutput", "getstatusoutput"}
SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen"}
CODE = {"eval", "exec", "loads", "load", "compile"}  # loads/load: pickle, marshal, yaml (unsafe loader)
PATHS = {"open", "send_file", "remove", "unlink", "rmtree", "FileResponse", "read_text", "write_text", "read_bytes"}
NETWORK = {"get", "post", "put", "delete", "patch", "request", "urlopen", "head"}
# not `session`: in SQLAlchemy / SQLModel code that's the database (`session.delete(user)`, `session.get(User, id)`)
NETWORK_MODULES = {"requests", "httpx", "urllib", "aiohttp", "client", "http", "http_session", "http_client"}
REDIRECT = {"redirect", "RedirectResponse", "HttpResponseRedirect"}
TEMPLATE = {"render_template_string", "Markup", "mark_safe", "Template"}
DB_RESULTS = {"fetchone", "fetchall", "fetchmany", "first", "one", "one_or_none", "scalar", "scalars", "all", "get_or_404"}
# A request parameter declared with one of these types is converted and validated before the handler runs (FastAPI,
# Django path converters): it can't carry attacker text.
SAFE_TYPES = {"int", "float", "bool", "UUID", "date", "datetime", "time", "Decimal", "conint", "confloat", "PositiveInt",
              "NonNegativeInt", "Literal"}  # fmt: skip
# request *data*, not any mention of "request" (urllib.request, request objects passed around in an HTTP library)
SOURCE_HINT = re.compile(
    r"\b(?:request|req)\.(?:args|form|values|json|data|files|cookies|headers|query_params|path_params|GET|POST|body|"
    r"FILES|COOKIES|META|get_json|query_string)\b|@\w+\.(?:get|post|put|patch|delete|route|api_route)\("
)
SINK_HINT = re.compile(
    r"execute|system|popen|subprocess|eval\(|exec\(|pickle|yaml|open\(|send_file|FileResponse|"
    r"unlink|remove\(|rmtree|requests\.|httpx|urlopen|redirect|Redirect|render_template_string|Markup|mark_safe"
)
KIND_TEXT = {"sql": "SQL query", "shell": "shell command", "code": "code execution", "path": "file path",
             "ssrf": "outgoing request URL", "redirect": "redirect target", "template": "template / HTML"}  # fmt: skip


@dataclass
class Summary:
    params: list[str]
    sinks: dict[int, list[tuple]] = field(default_factory=dict)  # param index -> [(kind, line, call, via, sink fn id)]
    returns: set[int] = field(default_factory=set)  # params that reach the return value
    source_sinks: list[tuple] = field(default_factory=list)  # (source text, kind, line, call, via, sink fn id)
    source_returns: str = ""  # a source the function returns, if any


def _name(func: ast.AST) -> str:
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _root(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def _source(node: ast.AST) -> str:
    """`request.args["q"]`, `request.json`: the text of a source expression, or "". Only network requests count:
    `sys.argv` and `input()` come from whoever runs the program, who already has its rights (a CLI opening the file
    it's given, a debugger running what's typed, are features)."""
    cur = node
    while isinstance(cur, (ast.Subscript, ast.Call, ast.Attribute)):
        if isinstance(cur, ast.Attribute) and cur.attr in REQUEST_ATTRS and _root(cur) in ("request", "req", "self"):
            return ast.unparse(node)[:60]
        cur = cur.func if isinstance(cur, ast.Call) else cur.value
    return ""


def _sink(call: ast.Call) -> tuple[str, list[ast.AST]] | None:
    """(kind, the arguments that matter) when this call is a sink."""
    name, f = _name(call.func), call.func
    root = _root(f) if isinstance(f, ast.Attribute) else ""
    args = list(call.args)
    if name in SQL and isinstance(f, ast.Attribute) and args:
        return "sql", args[:1]
    if name in SHELL and root == "os" and args:
        return "shell", args[:1]
    if name in SUBPROCESS and root == "subprocess" and args:
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in call.keywords)
        first = args[0]
        if shell or isinstance(first, (ast.JoinedStr, ast.BinOp)):
            return "shell", args[:1]
    if name in ("eval", "exec") and isinstance(f, ast.Name) and args:
        return "code", args[:1]
    if name in ("loads", "load") and root in ("pickle", "marshal", "dill", "shelve") and args:
        return "code", args[:1]
    if name == "load" and root == "yaml" and args and not any(k.arg == "Loader" for k in call.keywords):
        return "code", args[:1]
    if name in PATHS and (isinstance(f, ast.Name) or root in ("os", "shutil", "Path", "pathlib")) and args:
        return "path", args[:1]
    if name in NETWORK and root in NETWORK_MODULES and args:
        return "ssrf", args[:1]
    if name == "urlopen" and args:
        return "ssrf", args[:1]
    if name in REDIRECT and args:
        return "redirect", args[:1]
    if name in TEMPLATE and args:
        return "template", args[:1]
    return None


class _Function:
    """Taint inside one function, given which parameters are tainted and the callees' summaries."""

    def __init__(self, node, callees: dict[str, Summary], fid: str = ""):
        self.node, self.callees, self.fid = node, callees, fid
        self.params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]

    def origins(self, expr: ast.AST, env: dict[str, set]) -> set:
        """The taint labels an expression carries: ("param", i) or ("source", text)."""
        if isinstance(expr, ast.Name):
            return set(env.get(expr.id, ()))
        if src := _source(expr):
            return {("source", src)}
        if isinstance(expr, ast.Call):
            name = _name(expr.func)
            if name in SANITIZERS or name in SQL or name in DB_RESULTS:
                return set()  # converted, or read back from a database (second-order injection is out of scope)
            out = set()
            summary = self.callees.get(name)
            parts = list(expr.args) + [k.value for k in expr.keywords]
            if summary is not None:
                for i, a in enumerate(expr.args):
                    if i in summary.returns:
                        out |= self.origins(a, env)
                if summary.source_returns:
                    out.add(("source", summary.source_returns))
                return out
            for a in parts:  # an unknown call: what goes in comes out (str(x), x.strip(), "".join(xs)…)
                out |= self.origins(a, env)
            if isinstance(expr.func, ast.Attribute):
                out |= self.origins(expr.func.value, env)
            return out
        if isinstance(expr, ast.Compare):
            return set()  # a comparison is a yes/no: it carries no attacker text
        out = set()
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                out |= self.origins(child, env)
        return out

    def run(self, tainted_params: set[int]) -> tuple[dict, list, set]:
        env: dict[str, set] = {p: {("param", i)} for i, p in enumerate(self.params) if i in tainted_params}
        body = _body(self.node)
        for _ in range(4):  # assignments to a fixed point (flow-insensitive)
            changed = False
            for n in body:
                targets, value = [], None
                if isinstance(n, ast.Assign):
                    targets, value = n.targets, n.value
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    targets, value = [n.target], n.value
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    targets, value = [n.target], n.iter
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    targets, value = [n.optional_vars], n.context_expr
                if value is None:
                    continue
                labels = self.origins(value, env)
                if not labels:
                    continue
                for t in targets:
                    for name in (x.id for x in ast.walk(t) if isinstance(x, ast.Name)):
                        if not labels <= env.get(name, set()):
                            env[name] = env.get(name, set()) | labels
                            changed = True
            if not changed:
                break
        hits, calls, returns = [], [], set()
        for n in body:
            if isinstance(n, ast.Call):
                sink = _sink(n)
                if sink:
                    kind, args = sink
                    for a in args:
                        if isinstance(a, ast.Constant):
                            continue  # a constant query or command: bound parameters, nothing to inject
                        for label in self.origins(a, env):
                            hits.append((label, kind, n.lineno, ast.unparse(n.func)[:50], "", self.fid))
                summary = self.callees.get(_name(n.func))
                if summary is not None:
                    for i, a in enumerate(n.args):
                        for flow in summary.sinks.get(i, []):
                            for label in self.origins(a, env):
                                via = f"{_name(n.func)}({summary.params[i] if i < len(summary.params) else '…'})"
                                hits.append(
                                    (label, flow[0], flow[1], flow[2], via + (" → " + flow[3] if flow[3] else ""), flow[4])
                                )
                    calls.append(n)
            if isinstance(n, ast.Return) and n.value is not None:
                returns |= self.origins(n.value, env)
        return hits, calls, returns


def _closure(start: set[str], edges: dict[str, list[str]], keep: dict) -> set[str]:
    seen, stack = set(start), list(start)
    while stack:
        for nxt in edges.get(stack.pop(), ()):
            if nxt in keep and nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _body(node) -> list[ast.AST]:
    """Every node inside a function (cached on it: the worklist revisits functions)."""
    cached = getattr(node, "_cf_body", None)
    if cached is None:
        cached = [n for n in ast.walk(node) if n is not node]
        node._cf_body = cached
    return cached


def _has_source(node) -> bool:
    return any(isinstance(n, (ast.Attribute, ast.Call)) and _source(n) for n in _body(node))


def summarize(node, callees: dict[str, Summary], fid: str = "") -> Summary:
    f = _Function(node, callees, fid)
    s = Summary(f.params)
    hits, _, returns = f.run(set(range(len(f.params))))
    for label, kind, line, text, via, where in hits:
        if label[0] == "param":
            s.sinks.setdefault(label[1], []).append((kind, line, text, via, where))
        else:
            s.source_sinks.append((label[1], kind, line, text, via, where))
    s.returns = {lab[1] for lab in returns if lab[0] == "param"}
    s.source_returns = next((lab[1] for lab in returns if lab[0] == "source"), "")
    return s


def _entry(node, source: str) -> str:
    """`GET /search` when the function is a route handler (FastAPI, Flask), else ""."""
    for d in node.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS:
            path = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) else ""
            verb = d.func.attr.upper() if d.func.attr not in ("route", "api_route") else "ROUTE"
            return f"{verb} {path}".strip()
    return ""


def taint_flags(g: Graph, root: Path) -> list[Flag]:
    """Proven flows from request data (or another source) to a sink, one finding per sink line."""
    fns = [f for f in g.functions if f.file.endswith(".py") and f.kind != "module"]
    if not fns:
        return []
    callees_of: dict[str, list[str]] = {}
    for e in g.edges:
        if e.kind == "call":
            callees_of.setdefault(e.src, []).append(e.dst)
    by_id = {f.id: f for f in fns}
    lines_of: dict[str, list[str]] = {}
    for file in {f.file for f in fns}:
        try:
            lines_of[file] = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines_of[file] = []
    text_of = {f.id: "\n".join(lines_of[f.file][max(0, f.line - 4) : f.end]) for f in fns}  # (with decorators)
    # Only functions on a path from a source to a sink matter, and both ends show in the text: functions holding a
    # source (a route decorator, request.args and the like) and functions holding a sink. Keep what's reachable from
    # the first and can reach the second, along call edges, before parsing anything: on big codebases this is a few
    # percent of the functions.
    callers_of: dict[str, list[str]] = {}
    for src, dsts in callees_of.items():
        for d in dsts:
            callers_of.setdefault(d, []).append(src)
    sources = {fid for fid, text in text_of.items() if SOURCE_HINT.search(text)}
    sinks = {fid for fid, text in text_of.items() if SINK_HINT.search(text)}
    if not sources or not sinks:
        return []
    forward = _closure(sources, callees_of, by_id)
    backward = _closure(sinks, callers_of, by_id)
    relevant = forward & backward
    relevant |= {c for fid in list(relevant) for c in callees_of.get(fid, ()) if c in sources}  # request-data helpers
    if not relevant:
        return []
    nodes: dict[str, ast.AST] = {}
    for file in sorted({by_id[fid].file for fid in relevant}):
        try:
            tree = ast.parse("\n".join(lines_of[file]))
        except (SyntaxError, ValueError):
            continue
        wanted = {(by_id[fid].line, by_id[fid].name): fid for fid in relevant if by_id[fid].file == file}
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and (n.lineno, n.name) in wanted:
                nodes[wanted[(n.lineno, n.name)]] = n
    relevant &= set(nodes)
    summaries: dict[str, Summary] = {}
    work = deque(sorted(relevant, key=lambda f: -len(callees_of.get(f, ()))))  # leaves last: callees settle first
    queued, budget = set(work), 8 * len(relevant) + 100
    redone: dict[str, int] = {}
    while work and budget > 0:  # a worklist to a fixed point: a function is redone only when a callee changed
        budget -= 1
        fid = work.popleft()
        queued.discard(fid)
        redone[fid] = redone.get(fid, 0) + 1
        if redone[fid] > 6:  # recursion and long call cycles: enough rounds to settle what matters
            continue
        callees = {by_id[c].name: summaries[c] for c in callees_of.get(fid, []) if c in summaries}
        s = summarize(nodes[fid], callees, fid)
        old = summaries.get(fid)
        if old is None or (s.sinks, s.returns, s.source_sinks, s.source_returns) != (
            old.sinks,
            old.returns,
            old.source_sinks,
            old.source_returns,
        ):
            summaries[fid] = s
            for caller in callers_of.get(fid, ()):
                if caller in relevant and caller not in queued:
                    work.append(caller)
                    queued.add(caller)
    out, seen = [], set()
    for fid, s in summaries.items():
        node, fn = nodes[fid], by_id[fid]
        route = _entry(node, "")
        flows = list(s.source_sinks)
        if route:  # a handler's parameters come from the request (FastAPI path, query and body parameters)
            deps = {a.arg for a, d in _defaults(node) if isinstance(d, ast.Call) and _name(d.func) in ("Depends", "Security")}
            typed = {a.arg for a in node.args.args + node.args.kwonlyargs if _safe_annotation(a.annotation)}
            for i, flows_i in s.sinks.items():
                pname = s.params[i] if i < len(s.params) else "?"
                if (
                    pname in deps
                    or pname in typed
                    or pname in ("self", "cls", "db", "session", "conn", "request", "background_tasks")
                ):
                    continue
                flows += [(f"parameter `{pname}` of {route}", *flow) for flow in flows_i]
        for src, kind, line, text, via, where in flows:
            key = (kind, where, line)
            if key in seen:
                continue
            seen.add(key)
            chain = f"{src} → {fn.qualname}" + (f" → {via}" if via else "") + f" → {text}()"
            sink_fn = by_id.get(where, fn)
            what = KIND_TEXT[kind]
            article = "an" if what[0] in "aeiou" else "a"
            out.append(Flag("taint", "high", sink_fn.id, f"Request data reaches {article} {what}: {chain}",
                            [fid] if fid != sink_fn.id else [], line=line, detail=kind))  # fmt: skip
    return out


def _safe_annotation(ann: ast.AST | None) -> bool:
    """`int`, `uuid.UUID`, `Annotated[int, Path(...)]`, `Literal["a", "b"]`, an Enum-looking name…"""
    if ann is None:
        return False
    modules = {id(n.value) for n in ast.walk(ann) if isinstance(n, ast.Attribute)}  # `uuid` in `uuid.UUID`
    names = {n.id for n in ast.walk(ann) if isinstance(n, ast.Name) and id(n) not in modules} | {
        n.attr for n in ast.walk(ann) if isinstance(n, ast.Attribute)
    }
    names.discard("Annotated")
    names.discard("Optional")
    return bool(names) and (
        names <= SAFE_TYPES | {"None", "Path", "Query"} or any(n.endswith(("Enum", "Kind", "Type")) for n in names)
    )


def _defaults(node) -> list[tuple]:
    a = node.args
    positional = a.posonlyargs + a.args
    pairs = list(zip(positional[len(positional) - len(a.defaults) :], a.defaults, strict=False))
    pairs += [(arg, d) for arg, d in zip(a.kwonlyargs, a.kw_defaults, strict=False) if d is not None]
    return pairs
