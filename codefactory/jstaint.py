"""Data flow (taint) for JavaScript and TypeScript: does a value from a network request reach a dangerous call, and
through which variables? The same analysis as taint.py does for Python, on tree-sitter's syntax trees.

Sources are request data by the names the frameworks give it: `req.query`/`req.params`/`req.body`/`req.cookies`/
`req.headers` (Express, Fastify, Hapi's `request.payload`), `ctx.query`/`ctx.request.body` (Koa), `await
request.json()`/`formData()`/`text()` and `searchParams` in a Next.js route handler, its `params`, and Nest parameters
decorated `@Body()`/`@Query()`/`@Param()`/`@Headers()`. Sinks are a shell (`child_process.exec`, `spawn` with
`shell: true`), SQL text (`.query()`, `.raw()`, `$queryRawUnsafe`…, never a tagged template, which binds its values),
code (`eval`, `new Function`, `vm`), file paths (`fs.*`, `res.sendFile`), outgoing requests whose host the value can
change (`fetch`, `axios`, `got`, `http.request`), redirects and HTML written into a response.

A unit is a named function (a declaration, a method, or a function assigned to a name or property) or a file's top
level; a function passed inline as an argument (an Express handler, a `.forEach` callback) belongs to the unit around
it, so it sees that unit's variables. Per unit the analysis finds which parameters reach a sink or the return value;
summaries are combined across calls to a fixed point. Within a unit it's flow-insensitive, and an unknown call returns
what went into it: generous on purpose, because the sinks are specific.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .graph import Flag, Graph
from .taint import KIND_TEXT, VALIDATOR

EXT_LANG = {".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx", ".js": "javascript",
            ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript"}  # fmt: skip
FUNCS = {"function_declaration", "generator_function_declaration", "function_expression", "function", "arrow_function",
         "method_definition", "generator_function"}  # fmt: skip
SERVER_MODULES = {"express", "fastify", "koa", "@koa/router", "koa-router", "@hapi/hapi", "next/server", "hono",
                  "itty-router", "@nestjs/common", "http", "https", "restify", "polka", "h3", "elysia", "@sveltejs/kit",
                  "@remix-run/node"}  # fmt: skip
REQUEST_BASES = {"req", "request", "ctx"}  # (not `context`: in client code that is anything)
REQUEST_ATTRS = {"query", "params", "body", "cookies", "headers", "payload", "querystring", "searchParams", "signedCookies"}
BODY_READERS = {"json", "formData", "text"}  # `await request.json()` in a Next.js / web-standard route handler
NEST_SOURCES = {"Body", "Query", "Param", "Params", "Headers"}  # (@Req(): only its query/body/params are request data)
SAFE_PIPES = re.compile(r"Parse(?:Int|Float|Bool|UUID|Enum|Array)Pipe|DefaultValuePipe")
# (toQuery: knex's, which escapes its bindings)
SANITIZERS = {"Number", "parseInt", "parseFloat", "Boolean", "encodeURIComponent", "escape", "escapeHtml", "escapeHTML",
              "escapeXml", "sanitize", "sanitizeHtml", "sanitizeUrl", "basename", "quote", "escapeShellArg", "shellEscape",
              "escapeLiteral", "escapeIdentifier", "escapeId", "toFixed", "isValid", "uuidValidate", "validate", "xss",
              "encode", "htmlEscape", "stringify_safe", "toQuery"}  # fmt: skip
# methods whose result is a yes/no or a number: no attacker text comes out
CLEAN_METHODS = {"includes", "startsWith", "endsWith", "test", "indexOf", "lastIndexOf", "has", "some", "every",
                 "isArray", "isInteger", "isNaN", "isFinite", "localeCompare", "getTime", "valueOf", "charCodeAt"}  # fmt: skip
SQL_METHODS = {"query", "raw", "execute", "exec", "$queryRawUnsafe", "$executeRawUnsafe", "unsafe", "whereRaw",
               "orderByRaw", "havingRaw", "joinRaw", "fromRaw", "selectRaw", "groupByRaw", "prepare", "run", "all",
               "get"}  # fmt: skip
UNSAFE_SQL = {"$queryRawUnsafe", "$executeRawUnsafe", "unsafe", "whereRaw", "orderByRaw", "havingRaw", "joinRaw",
              "fromRaw", "selectRaw", "groupByRaw", "raw"}  # fmt: skip
DB_OBJECT = re.compile(r"(?:^|\.|_)(?:db|database|conn|connection|pool|client|knex|sequelize|prisma|sql|pg|mysql|sqlite|"
                       r"tx|trx|queryRunner|manager|entityManager|dataSource|repo|repository|em)$", re.I)  # fmt: skip
SQL_WORDS = re.compile(r"\b(?:select|insert|update|delete|where|from|order\s+by|values|create|drop|alter)\b", re.I)
SHELL_FUNCS = {"exec", "execSync"}
SPAWN_FUNCS = {"spawn", "spawnSync", "execFile", "execFileSync"}
CHILD_PROCESS = {"child_process", "cp", "childProcess", "proc"}
FS_FUNCS = {"readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "unlink",
            "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "appendFile", "appendFileSync", "readdir", "readdirSync",
            "open", "openSync", "copyFile", "rename", "renameSync"}  # fmt: skip
FS_OBJECTS = {"fs", "fsp", "fsPromises", "promises", "fse", "fsExtra"}
SEND_FILE = {"sendFile", "download", "sendfile"}
HTTP_FUNCS = {"fetch", "axios", "got", "ky", "needle", "superagent", "request"}
HTTP_OBJECTS = {"axios", "got", "http", "https", "ky", "needle", "superagent", "httpClient", "fetcher"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "options"}
REDIRECTS = {"redirect", "permanentRedirect"}
DB_READS = {"find", "findOne", "findByPk", "findAll", "findFirst", "findUnique", "findMany", "findOneBy", "findBy",
            "findById", "findOrFail", "findOneOrFail", "findFirstOrThrow", "findUniqueOrThrow", "findAndCountAll", "count",
            "aggregate", "findOneAndUpdate", "getRepository", "create", "retrieve", "upsert", "save", "insert",
            "createQueryBuilder", "getOne", "getMany"}  # fmt: skip
# namespaces whose functions hand back what they were given, transformed: path.join(base, x), JSON.parse(x)…
UTILITY = {"path", "url", "URL", "JSON", "Buffer", "querystring", "qs", "String", "Object", "Array", "_", "lodash", "util",
           "posix", "win32", "decodeURIComponent", "Promise", "Reflect", "TextDecoder", "atob", "btoa", "Utils",
           "utils"}  # fmt: skip
# methods whose result carries what they're given: a schema's parse (z.string() checks the type, not the text), concat
PASS_THROUGH = {"parse", "parseAsync", "safeParse", "cast", "concat", "join", "replace", "replaceAll", "format", "resolve",
                "from", "assign", "push", "fromEntries", "entries", "stringify"}  # fmt: skip
LOOKUP = re.compile(r"(?:load|find|lookup|retrieve|query|select)[A-Z_]|get\w*(?:From|For|By)[A-Z]")
CHECKED = re.compile(r"[Vv]alidat|[Ss]aniti[sz]|[Ss]afe|[Aa]llowed|[Tt]rusted|[Ww]hitelist|[Aa]llowlist|[Vv]erif")
# checks by name beyond VALIDATOR's: assertUrl(x), checkRedirect(x), isPathInside(base, p), isSameOrigin(x)
TARGET = r"(?:Url|URL|Uri|URI|Redirect|Path|Host|Origin|Domain|Webhook|SSRF|Ssrf)"  # what a check of a place is about
GUARD = re.compile(rf"(?:[Aa]ssert|[Cc]heck|[Vv]erify|[Ee]nsure)\w*{TARGET}"
                   r"|(?:[Ii]nside|[Ww]ithin|[Cc]ontained)(?:[A-Z]|$)|[Ss]ame[Oo]rigin")  # fmt: skip
# an agent or fetch that refuses private addresses: ssrfSafeAgent, getSafeAxiosAgents(), request-filtering-agent
SAFE_AGENT = re.compile(r"[Ss]srf\w*(?:Agent|Fetch)|[Ss]afe\w*Agents?\b|[Ff]iltering\w*Agent")
URL_KEYS = {"url", "uri", "baseURL", "baseUrl", "host", "hostname", "href", "origin"}  # an options object's target
ITERATORS = {"map", "forEach", "flatMap", "filter", "find", "findIndex"}
INJECTED = r"(?:private|protected|public|readonly)\s+(?:readonly\s+)?(\w+)\s*[?!]?\s*:\s*([A-Z]\w*)"  # field: Type
RESPONSE_WRITE = {"send", "write", "end"}
SOURCE_HINT = re.compile(
    r"\b(?:req|request|ctx|context|event)\s*\.\s*(?:query|params|body|cookies|headers|payload|querystring|nextUrl|json\(|"
    r"formData\(|text\(|request\b)|searchParams|@(?:Body|Query|Param|Headers)\b|\bparams\b|\.input\(|\binput\s*[,}]"
)
SINK_HINT = re.compile(
    r"\bexec(?:Sync)?\s*\(|spawn|execFile|\.query\s*\(|\.raw\s*\(|Unsafe\s*\(|Raw\s*\(|\beval\s*\(|new\s+Function|vm\.|"
    r"\bfs\b|readFile|writeFile|createReadStream|unlink|sendFile|download\(|fetch\s*\(|axios|\bgot\b|https?\.(?:get|request)|"
    r"redirect\s*\(|\.send\s*\(|\.write\s*\(|\.end\s*\(|\.prepare\s*\(|\.execute\s*\("
)
NEXT_ROUTE = re.compile(r"(?:^|/)app/(?:.*/)?route\.[cm]?[jt]sx?$")
NEXT_API = re.compile(r"(?:^|/)pages/api/")
HTTP_VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
ROUTER_METHODS = {"get", "post", "put", "patch", "delete", "all", "use", "head", "options", "route"}


def available() -> bool:
    try:
        import tree_sitter_language_pack  # noqa: F401
    except ImportError:
        return False
    return True


def _text(n, src: bytes) -> str:
    return src[n.start_byte : n.end_byte].decode("utf-8", "replace")


def _kids(n) -> list:
    return [c for c in n.children if c.is_named]


def _strip(n):
    """Through parentheses, `await`, `as T`, `x!` and `satisfies T` to the expression that matters."""
    while n is not None and n.type in ("parenthesized_expression", "await_expression", "as_expression", "non_null_expression",
                                       "satisfies_expression", "type_assertion"):  # fmt: skip
        named = _kids(n)
        n = named[0] if named else None
    return n


def _callee_name(call, src: bytes) -> tuple[str, str]:
    """(name, receiver text) of a call: `fs.readFile(...)` -> ("readFile", "fs"); `exec(...)` -> ("exec", "")."""
    f = _strip(call.child_by_field_name("function") or call.child_by_field_name("constructor"))
    if f is None:
        return "", ""
    if f.type == "member_expression":
        prop = f.child_by_field_name("property")
        obj = f.child_by_field_name("object")
        return (_text(prop, src) if prop else ""), (_text(obj, src) if obj else "")
    if f.type == "identifier":
        return _text(f, src), ""
    return "", ""


def _args(call) -> list:
    a = call.child_by_field_name("arguments")
    if a is None or a.type == "template_string":  # a tagged template: sql`… ${x}` binds x
        return []
    return [c for c in _kids(a) if c.type != "comment"]


def _member_chain(n, src: bytes) -> tuple[str, list[str]]:
    """`ctx.request.body.name` -> ("ctx", ["request", "body", "name"])."""
    props: list[str] = []
    cur = _strip(n)
    while cur is not None and cur.type in ("member_expression", "subscript_expression"):
        if cur.type == "member_expression":
            p = cur.child_by_field_name("property")
            props.append(_text(p, src) if p else "")
        cur = _strip(cur.child_by_field_name("object"))
    base = _text(cur, src) if cur is not None and cur.type in ("identifier", "this") else ""
    return base, props[::-1]


@dataclass
class Unit:
    """A named function or a file's top level, with the inline callbacks inside it."""

    file: str
    name: str
    node: object
    params: list[list[str]]  # per parameter, the names it binds (a destructured parameter binds several)
    line: int
    entry: str = ""  # "POST /users" when it's a route handler
    sources: set[int] = field(default_factory=set)  # parameters that are request data on entry
    fid: str = ""  # the graph function, when one matches
    parent: int = -1  # the unit around it (index in the file's list): a closure sees its variables
    inline: bool = False  # passed as an argument (a handler, a callback): never called by name
    cls: str = ""  # the class a method belongs to
    source_names: dict[str, str] = field(default_factory=dict)  # names a parameter binds to request data: tRPC `input`


@dataclass
class Summary:
    sinks: dict[int, list[tuple]] = field(default_factory=dict)  # param -> [(kind, line, call text, via, file)]
    returns: set[int] = field(default_factory=set)
    source_sinks: list[tuple] = field(default_factory=list)  # (source, kind, line, call text, via, file)
    source_returns: str = ""


def _pattern_names(n, src: bytes) -> list[str]:
    if n is None:
        return []
    if n.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [_text(n, src)]
    out: list[str] = []
    for c in _kids(n):
        if c.type in ("type_annotation", "decorator"):
            continue
        if c.type == "pair_pattern":
            out += _pattern_names(c.child_by_field_name("value"), src)
        elif c.type in ("assignment_pattern", "object_assignment_pattern"):
            out += _pattern_names(c.child_by_field_name("left") or _kids(c)[0], src)
        else:
            out += _pattern_names(c, src)
    return out


def _params(fn, src: bytes) -> list[tuple[list[str], object]]:
    ps = fn.child_by_field_name("parameters")
    if ps is None:  # `x => …`
        p = fn.child_by_field_name("parameter")
        return [([_text(p, src)], p)] if p is not None else []
    out = []
    for p in _kids(ps):
        if p.type == "comment":
            continue
        target = p.child_by_field_name("pattern") or p
        if target.type in ("required_parameter", "optional_parameter"):
            target = next(
                (c for c in _kids(target) if c.type not in ("decorator", "type_annotation", "accessibility_modifier")), target
            )
        if target.type == "assignment_pattern":
            target = target.child_by_field_name("left") or target
        if target.type == "rest_pattern":
            target = _kids(target)[0] if _kids(target) else target
        out.append((_pattern_names(target, src), p))
    return out


def _fn_name(fn, src: bytes) -> str:
    n = fn.child_by_field_name("name")
    if n is not None:
        return _text(n, src)
    parent = fn.parent
    while parent is not None and parent.type in ("parenthesized_expression", "as_expression", "satisfies_expression"):
        parent = parent.parent
    if parent is None:
        return ""
    if parent.type == "variable_declarator":
        n = parent.child_by_field_name("name")
        return _text(n, src) if n is not None and n.type == "identifier" else ""
    if parent.type == "pair":
        k = parent.child_by_field_name("key")
        return _text(k, src).strip("'\"") if k is not None else ""
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _text(left.child_by_field_name("property") or left, src)
    if parent.type in ("public_field_definition", "field_definition"):
        n = parent.child_by_field_name("name") or parent.child_by_field_name("property")
        return _text(n, src) if n is not None else ""
    return ""


def _route_of(call, src: bytes) -> str:
    """`router.post("/users", …)` -> "POST /users"; "" when the call isn't a route registration."""
    name, recv = _callee_name(call, src)
    if name not in ROUTER_METHODS or not recv:
        return ""
    args = _args(call)
    path = ""
    if args and args[0].type == "string":
        path = _text(args[0], src).strip("'\"`")
    elif recv.endswith(")") and ".route(" in recv:  # router.route("/x").get(handler)
        m = re.search(r"\.route\(\s*['\"`]([^'\"`]*)", recv)
        path = m.group(1) if m else ""
    else:
        return ""
    if name == "use" and not path.startswith("/"):
        return ""
    return f"{name.upper() if name not in ('all', 'use', 'route') else 'ROUTE'} {path}".strip()


def _decorators(param, src: bytes) -> list[str]:
    return [_text(c, src) for c in param.children if c.type == "decorator"]


def units_of(file: str, tree, src: bytes) -> list[Unit]:
    """The units of one file: its named functions, then its top level."""
    out: list[Unit] = []
    root = tree.root_node
    next_route = bool(NEXT_ROUTE.search(file))
    next_api = bool(NEXT_API.search(file))

    out.append(Unit(file, "<top level>", root, [], 1))

    def visit(n, parent: int):
        if n.type in FUNCS:
            inline = n.parent is not None and n.parent.type == "arguments"
            name = "" if inline else _fn_name(n, src)
            if True:
                ps = _params(n, src)
                u = Unit(file, name or "<callback>", n, [names for names, _ in ps], n.start_point[0] + 1,
                         parent=parent, inline=inline or not name)  # fmt: skip
                if inline and (route := _route_of(n.parent.parent, src)):
                    u.entry = route
                if n.type == "method_definition":  # Nest: @Post("x") create(@Body() dto) — decorated parameters
                    for i, (_, p) in enumerate(ps):
                        decs = _decorators(p, src)
                        if any(
                            re.match(r"@(\w+)", d) and re.match(r"@(\w+)", d).group(1) in NEST_SOURCES for d in decs
                        ) and not any(SAFE_PIPES.search(d) for d in decs):
                            u.sources.add(i)
                    if u.sources:
                        u.entry = _nest_route(n, src)
                if next_route and name in HTTP_VERBS:
                    u.entry = f"{name} {_next_path(file)}"
                    if len(ps) > 1:
                        u.sources.add(1)  # { params }
                if next_api and _is_default_export(n):
                    u.entry = f"ROUTE {_next_path(file)}"
                if n.type == "method_definition":
                    u.cls = _class_name(n, src)
                if ps and (trpc := _trpc_input(n, ps[0][1], file, src)):
                    u.source_names = {name: "input" for name in trpc}
                    key = _procedure_key(n, src) if inline else ""
                    u.entry = u.entry or (f"tRPC {key}" if key else "a tRPC procedure")
                out.append(u)
                parent = len(out) - 1
        for c in n.children:
            visit(c, parent)

    visit(root, 0)
    return out


def _class_name(method, src: bytes) -> str:
    cls = method.parent
    while cls is not None and cls.type not in ("class_declaration", "class", "abstract_class_declaration"):
        cls = cls.parent
    n = cls.child_by_field_name("name") if cls is not None else None
    return _text(n, src) if n is not None else ""


def _pattern_keys(pattern, src: bytes) -> dict[str, list[str]]:
    """`{ ctx, input: { id }, body = {} }` -> {"ctx": ["ctx"], "input": ["id"], "body": ["body"]}."""
    keys: dict[str, list[str]] = {}
    if pattern is None or pattern.type != "object_pattern":
        return keys
    for c in _kids(pattern):
        if c.type == "shorthand_property_identifier_pattern":
            keys[_text(c, src)] = [_text(c, src)]
        elif c.type == "pair_pattern" and c.child_by_field_name("key") is not None:
            keys[_text(c.child_by_field_name("key"), src)] = _pattern_names(c.child_by_field_name("value"), src)
        elif c.type == "object_assignment_pattern" and _kids(c):
            keys[_text(_kids(c)[0], src)] = _pattern_names(_kids(c)[0], src)
    return keys


def _trpc_input(fn, first, file: str, src: bytes) -> list[str]:
    """The names a tRPC resolver binds to its client's input: `.input(schema).mutation(({ input }) => …)` inline, or a
    handler in its own file, `export const getHandler = async ({ ctx, input }: GetOptions) => …` (cal.com)."""
    target = first.child_by_field_name("pattern") or first
    if target.type in ("required_parameter", "optional_parameter"):
        target = next((c for c in _kids(target) if c.type not in ("decorator", "type_annotation")), target)
    keys = _pattern_keys(target, src)
    if "input" not in keys:
        return []
    call = fn.parent.parent if fn.parent is not None and fn.parent.type == "arguments" else None
    if call is not None and call.type == "call_expression":
        name, recv = _callee_name(call, src)
        return keys["input"] if name in ("query", "mutation", "subscription") and ".input(" in recv else []
    if "ctx" in keys and (re.search(r"trpc", file, re.I) or file.endswith((".handler.ts", ".handler.js"))):
        return keys["input"]
    return []


def _procedure_key(fn, src: bytes) -> str:
    """`run: publicProcedure.input(…).mutation(fn)` -> "run"."""
    p = fn.parent
    while p is not None and p.type not in ("pair", "statement_block", "program"):
        p = p.parent
    k = p.child_by_field_name("key") if p is not None and p.type == "pair" else None
    return _text(k, src).strip("'\"") if k is not None else ""


def _is_default_export(fn) -> bool:
    p = fn.parent
    return p is not None and p.type == "export_statement" and any(c.type == "default" for c in p.children)


def _next_path(file: str) -> str:
    m = re.search(r"(?:app|pages)(/.*?)(?:/route|/index)?\.[cm]?[jt]sx?$", file)
    return (m.group(1) if m else "/") or "/"


def _nest_route(method, src: bytes) -> str:
    decs: list[str] = []
    p = method.prev_named_sibling
    while p is not None and p.type == "decorator":
        decs.append(_text(p, src))
        p = p.prev_named_sibling
    decs += [_text(c, src) for c in method.children if c.type == "decorator"]
    prefix = ""
    cls = method.parent
    while cls is not None and cls.type not in ("class_declaration", "class"):
        cls = cls.parent
    if cls is not None:
        around = [cls.prev_named_sibling, *cls.children, *(cls.parent.children if cls.parent is not None else [])]
        for c in around:
            if c is not None and c.type == "decorator":
                m = re.match(r"@Controller\(\s*['\"`]([^'\"`]*)", _text(c, src))
                if m:
                    prefix = "/" + m.group(1).strip("/")
    for d in decs:
        m = re.match(r"@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['\"`]([^'\"`]*))?", d)
        if m:
            tail = (m.group(2) or "").strip("/")
            return f"{m.group(1).upper()} {prefix}/{tail}".rstrip("/") if tail or not prefix else f"{m.group(1).upper()} {prefix}"
    return "a Nest handler"


def _own_body(unit: Unit) -> list:
    """Every node in the unit, nested functions left out (they're units of their own)."""
    out = []
    stack = list(unit.node.children)
    while stack:
        n = stack.pop()
        if n.type in FUNCS:
            continue
        if n.type in ("class_declaration", "class") and unit.name == "<top level>":
            # methods are units; field initializers stay
            stack.extend(c for c in n.children if c.type != "class_body")
            body = n.child_by_field_name("body")
            if body is not None:
                stack.extend(c for c in body.children if c.type != "method_definition")
            continue
        out.append(n)
        stack.extend(n.children)
    out.sort(key=lambda n: n.start_byte)
    return out


class _Function:
    def __init__(self, unit: Unit, src: bytes, callees: dict[str, Summary], imports: dict[str, str]):
        self.u, self.src, self.callees, self.imports = unit, src, callees, imports
        # `request.headers` is a request this code received only in server code: a route handler, or a file that
        # imports a server framework. In an HTTP client (Hoppscotch's relay, a fetch wrapper) it's the one being sent.
        self.server = (
            bool(unit.entry)
            or bool(set(imports.values()) & SERVER_MODULES)
            or bool({"reply", "res", "response", "h"} & {name for names in unit.params for name in names})
        )
        self.outer: dict[str, set] = {}  # the enclosing unit's variables, for a closure
        self.items: set = set()  # what its first parameter holds, for a callback over a list: ids.map((id) => …)
        self.callbacks: dict[int, set] = {}  # per callback this unit hands a list's items to (by start byte)
        self.guard: set[str] = set()  # what an `if` around the sink being checked has validated
        self.env: dict[str, set] = {}
        self.body = _own_body(unit)
        self.clean_after = self._replaced_unless_valid()
        self.guarded = self._guards()
        self.line = 0

    # what the analysis treats as a source of request data
    def source(self, n) -> str:
        n = _strip(n)
        if n is None:
            return ""
        if n.type in ("member_expression", "subscript_expression"):
            base, props = _member_chain(n, self.src)
            if base in REQUEST_BASES and props and (base != "request" or self.server):
                if props[0] in REQUEST_ATTRS:
                    return _text(n, self.src)[:60]
                if base in ("ctx", "context") and props[0] == "request" and len(props) > 1 and props[1] in REQUEST_ATTRS:
                    return _text(n, self.src)[:60]
                if props[0] == "nextUrl" and "searchParams" in props:
                    return _text(n, self.src)[:60]
        if n.type == "call_expression":
            name, recv = _callee_name(n, self.src)
            if name in BODY_READERS and recv in ("request", "req") and self.u.entry:
                return _text(n, self.src)[:60]
            if name in ("get", "getAll") and recv.endswith("searchParams"):
                inner = _strip(n.child_by_field_name("function"))
                obj = inner.child_by_field_name("object") if inner is not None else None
                return self.source(obj) or (_text(n, self.src)[:60] if self.u.entry else "")
        if n.type == "new_expression":
            name, _ = _callee_name(n, self.src)
            args = _args(n)
            if name == "URL" and args and _text(args[0], self.src) in ("request.url", "req.url") and self.u.entry:
                return _text(n, self.src)[:60]
        return ""

    def origins(self, n, env: dict[str, set]) -> set:
        n = _strip(n)
        if n is None:
            return set()
        t = n.type
        if t in ("identifier", "member_expression", "subscript_expression") and self.guard and _text(n, self.src) in self.guard:
            return set()  # inside `if (isSafe(x))` / `if (x === "a")`
        if t in ("identifier", "member_expression", "subscript_expression") and self.clean_after:
            name = _text(n, self.src)
            if self.line and self.line > self.clean_after.get(name, self.line):
                return set()  # after `if (!isSafe(x)) return` / `throw`
        if t == "identifier":
            return set(env.get(_text(n, self.src), ()))
        if src := self.source(n):
            return {("source", src)}
        if t in ("string", "number", "true", "false", "null", "undefined", "regex", "template_literal_type"):
            return set()
        if t == "template_string":
            out, query, scheme = set(), False, False
            parts = [c for c in n.children if c.type in ("string_fragment", "template_substitution")]
            for k, c in enumerate(parts):
                if c.type == "string_fragment":
                    s = _text(c, self.src)
                    if scheme and s.startswith("/") and not out:
                        query = True  # `${protocol}://${checkedHost}/${path}`: the host is set, the rest is its path
                    scheme = scheme or "://" in s
                    # past the "?", a fixed "https://host/", a leading "/path" or a leading constant base followed by
                    # "/": what follows can't change where the URL goes
                    if (
                        "?" in s
                        or re.search(r"//[^/?#]+[/?#]", s)
                        or (k == 0 and s.startswith("/") and not s.startswith(("//", "/\\")))
                        or (k == 1 and s.startswith("/") and self._constant_base(parts[0], env))
                    ):
                        query = True
                elif c.type == "template_substitution":
                    if k == 1 and self._constant_base(parts[0], env) and re.search(r"\.pathname\b", _text(c, self.src)):
                        query = True  # `${POSTHOG_URL}${url.pathname}`: a URL's pathname starts with "/"
                    for e in _kids(c):
                        labels = self.origins(e, env)
                        out |= {(*lab[:2], "query") for lab in labels} if query else labels
            return out
        if t in ("member_expression", "subscript_expression"):
            prop = n.child_by_field_name("property")
            if prop is not None and _text(prop, self.src) in ("length", "size"):
                return set()
            return self.origins(n.child_by_field_name("object"), env)
        if t == "binary_expression":
            op = n.child_by_field_name("operator")
            op = _text(op, self.src) if op is not None else ""
            if op in ("===", "==", "!==", "!=", "<", ">", "<=", ">=", "instanceof", "in", "-", "*", "/", "%", "**", "|", "&",
                      "^", "<<", ">>", ">>>"):  # fmt: skip
                return set()
            if op == "&&":
                return self.origins(n.child_by_field_name("right"), env)
            return self.origins(n.child_by_field_name("left"), env) | self.origins(n.child_by_field_name("right"), env)
        if t == "unary_expression":
            return set()  # typeof, !, -, +x (a number), void
        if t == "ternary_expression":
            # `isValidRedirect(x) ? x : "/"`: the branch the check leads to holds a checked x
            cond = n.child_by_field_name("condition")
            checked = self._validated_names(cond, ("===", "==")) if cond is not None else set()
            negated = cond is not None and _text(cond, self.src).lstrip("( ").startswith("!")
            out, saved = set(), self.guard
            for branch, ok in (("consequence", not negated), ("alternative", negated)):
                self.guard = saved | checked if ok else saved
                out |= self.origins(n.child_by_field_name(branch), env)
            self.guard = saved
            return out
        if t in ("call_expression", "new_expression"):
            return self._call_origins(n, env)
        if t in ("arrow_function", "function_expression", "function"):
            return set()
        out = set()
        for c in _kids(n):
            if c.type in ("type_annotation", "type_arguments", "comment"):
                continue
            out |= self.origins(c, env)
        return out

    def _call_origins(self, n, env) -> set:
        name, recv = _callee_name(n, self.src)
        if name in SANITIZERS or name in CLEAN_METHODS or recv == "Math" or name in UNSAFE_SQL or name in DB_READS:
            return set()  # converted or checked; or read back from a database (second-order injection is out of scope)
        if LOOKUP.match(name):
            return set()  # loadShare({ id }), getTeamFromContext(ctx), findUserByEmail(x): a record looked up, not the text
        if CHECKED.search(name):
            return set()  # getValidatedHost(x), sanitizeRedirect(x), toSafeUrl(x): what comes back passed a check
        if recv in ("Number", "Date") or name in ("isUUID", "isInt", "isEmail", "isNumeric"):
            return set()
        args = _args(n)
        if re.match(r"(?:decode|unseal|unsign)", name, re.I) and re.search(
            r"\b(?:secret|key|password)\b", " ".join(_text(a, self.src) for a in args[1:] or args), re.I
        ):
            return set()  # decode({ token, secret }), unsign(cookie, secret): signed by the server, not request text
        summary = self.callees.get(name) if self._direct(recv) else self.callees.get(f"{recv}.{name}")
        if summary is not None:
            out = set()
            for i, a in enumerate(args):
                if i in summary.returns:
                    out |= self.origins(a, env)
            if summary.source_returns:
                out.add(("source", summary.source_returns))
            return out
        f = _strip(n.child_by_field_name("function") or n.child_by_field_name("constructor"))
        receiver = (
            self.origins(f.child_by_field_name("object"), env) if f is not None and f.type == "member_expression" else set()
        )
        if recv and recv.split(".")[0] not in UTILITY and name not in PASS_THROUGH:
            # service.process(x), sp.createLogoutRequest(idp, x), stripe.sessions.create({…x}): an object's own method
            # handed the value returns that object's answer, not the text; a method of the text (x.trim()) keeps it
            return receiver
        if name in ("replace", "replaceAll"):
            args = args[1:]  # what's searched for is taken out, not put in
        out = set(receiver)
        for a in args:
            out |= self.origins(a, env)
        return out

    def _constant_base(self, sub, env) -> bool:
        """`${POSTHOG_URL}`, `${process.env.API}`, `${env.URL}`, `${config.baseUrl}`, `${nconf.get("relative_path")}`,
        `${dev ? "http://localhost" : "https://app.x.dev"}`: a base the request doesn't set."""
        inner = _kids(sub)
        return bool(inner) and self._constant(_strip(inner[0]), env)

    def _constant(self, e, env) -> bool:
        if e is None:
            return False
        if e.type == "string":
            return True
        if e.type == "ternary_expression":
            return all(self._constant(_strip(e.child_by_field_name(b)), env) for b in ("consequence", "alternative"))
        if e.type == "call_expression":  # a settings getter: nconf.get("url"), config.get("app.base")
            args = _args(e)
            if not args or any(a.type != "string" for a in args):
                return False
            return _callee_name(e, self.src)[1].split(".")[0] not in REQUEST_BASES and not self.origins(e, env)
        text = _text(e, self.src)
        return bool(
            re.fullmatch(r"[A-Z][A-Z0-9_]+|(?:process\.)?env\.\w+|(?:this\.)?(?:config|settings|options)\.\w+(?:\.\w+)*", text)
        )

    def _direct(self, recv: str) -> bool:
        """A call by name that a summary can stand for: `helper(x)`, `this.helper(x)`, `utils.helper(x)` (an import)."""
        return not recv or recv == "this" or (recv in self.imports)

    def _validated_names(self, test, equal_ops: tuple = ()) -> set[str]:
        """Names a check looks at: `isSafe(x)`, `ALLOWED.includes(x)`, `/^\\w+$/.test(x)`, `allowed.has(x)`."""
        out = set()
        stack = [test]
        while stack:
            c = stack.pop()
            if c.type == "call_expression":
                name, recv = _callee_name(c, self.src)
                if (
                    VALIDATOR.search(name)
                    or GUARD.search(name)
                    or name in ("includes", "has", "test", "isUUID", "isInt", "matches")
                    or (name == "match" and recv)
                ):
                    for a in _args(c):
                        a = _strip(a)
                        if a is not None and a.type in ("identifier", "member_expression", "subscript_expression"):
                            out.add(_text(a, self.src))
                    if name == "match" and recv and re.fullmatch(r"[\w.]+", recv):
                        out.add(recv)
                elif name == "startsWith" and re.fullmatch(r"[\w.]+", recv) and self._prefix_check(recv, _args(c)):
                    out.add(recv)  # `p.startsWith(base + path.sep)`, `url.startsWith("https://x.com/")`
            elif c.type == "binary_expression" and equal_ops:
                op = c.child_by_field_name("operator")
                if op is not None and _text(op, self.src) in equal_ops:
                    left, right = _strip(c.child_by_field_name("left")), _strip(c.child_by_field_name("right"))
                    for side, other in ((left, right), (right, left)):
                        if other is not None and other.type in ("string", "number") and side is not None and side.type in (
                            "identifier", "member_expression", "subscript_expression"
                        ):  # fmt: skip
                            out.add(_text(side, self.src))  # `x === "a"`: inside, x is that constant
            stack.extend(_kids(c))
        return out

    def _prefix_check(self, recv: str, args) -> bool:
        """A prefix that pins where a value points: a full origin, or any base of a resolved path (`..` gone)."""
        a = _strip(args[0]) if args else None
        if a is None:
            return False
        if a.type == "string" and re.match(r"https?://[^/]+/", _text(a, self.src).strip("'\"`")):
            return True
        for n in self.body:
            if n.type == "variable_declarator" and _text(n.child_by_field_name("name"), self.src) == recv:
                v = _strip(n.child_by_field_name("value"))
                if v is not None and v.type == "call_expression" and _callee_name(v, self.src)[0] in (
                    "resolve", "normalize", "join", "realpath", "realpathSync"
                ):  # fmt: skip
                    return True
        return False

    def _guards(self) -> dict[int, set[str]]:
        """For each call, the names an enclosing `if` validated: `if (isSafe(x)) { redirect(x) }`."""
        out: dict[int, set[str]] = {}
        for n in self.body:
            if n.type != "if_statement":
                continue
            cond = n.child_by_field_name("condition")
            cons = n.child_by_field_name("consequence")
            if cond is None or cons is None or _text(cond, self.src).lstrip("( ").startswith("!"):
                continue
            names = self._validated_names(cond, ("===", "=="))
            if not names:
                continue
            stack = [cons]
            while stack:
                c = stack.pop()
                if c.type == "call_expression":
                    out.setdefault(c.start_byte, set()).update(names)
                stack.extend(c.children)
        return out

    def _replaced_unless_valid(self) -> dict[str, int]:
        """`if (!isSafe(x)) return …` / `throw` / `x = "/"`: from the end of that `if`, x reads as clean. So does a value
        passed back through a checker: `redirect = resolveLoginRedirect(redirect)` (it throws on a bad one)."""
        out: dict[str, int] = {}

        def clean(name: str, line: int):
            out[name] = min(out.get(name, line), line)

        # what a check's result stands for: `const r = await validateWebhookUrl(url)` -> {"r": {"url"}}; likewise
        # `const rel = path.relative(base, p)`, whose `..` or absolute form is what a containment check rejects
        results: dict[str, set[str]] = {}
        for n in self.body:
            if n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), _strip(n.child_by_field_name("right"))
                if left is not None and left.type == "identifier" and right is not None and right.type == "call_expression":
                    name, _ = _callee_name(right, self.src)
                    args = [_text(a, self.src) for a in _args(right)]
                    if _text(left, self.src) in args and (CHECKED.search(name) or re.search(r"resolve\w*(?:Redirect|Url)", name)):
                        clean(_text(left, self.src), n.end_point[0] + 1)
            elif n.type == "variable_declarator":
                left, right = n.child_by_field_name("name"), _strip(n.child_by_field_name("value"))
                if getattr(left, "type", "") == "identifier" and getattr(right, "type", "") == "call_expression":
                    name, recv = _callee_name(right, self.src)
                    args = [_strip(a) for a in _args(right)]
                    if name == "relative" and (not recv or recv.split(".")[-1] in ("path", "posix", "win32")):
                        args = args[1:]
                    elif not self._place_check(name):
                        continue
                    kept = [a for a in args if a is not None and a.type in ("identifier", "member_expression")]
                    results[_text(left, self.src)] = {_text(a, self.src) for a in kept}
            elif n.type == "expression_statement" and (call := _strip(_kids(n)[0] if _kids(n) else None)) is not None:
                # `await assertSafeUrl(url)`, `validateUrlOrThrow(url)`: a check called for its throw
                name, _ = _callee_name(call, self.src) if call.type == "call_expression" else ("", "")
                if re.match(r"(?:assert|ensure|validate|verify|check)", name, re.I) and self._place_check(name):
                    for a in _args(call):
                        a = _strip(a)
                        if a is not None and a.type in ("identifier", "member_expression"):
                            clean(_text(a, self.src), n.end_point[0] + 1)
        for n in self.body:
            if n.type != "if_statement":
                continue
            cond = n.child_by_field_name("condition")
            cons = n.child_by_field_name("consequence")
            if cond is None or cons is None:
                continue
            negated = [c for c in self._walk(cond) if c.type == "unary_expression" and _text(c, self.src).startswith("!")]
            names = set().union(*(self._validated_names(c) for c in negated)) if negated else set()
            names |= self._validated_names(cond, ("!==", "!="))  # `if (x !== "a" && x !== "b") return`
            body = _text(cons, self.src)
            leaves = re.search(r"\b(?:return|throw)\b", body) is not None
            if leaves:  # `if (!check.safe) return`, `if (rel.startsWith("..") || path.isAbsolute(rel)) throw`
                used = {_text(c, self.src) for c in self._walk(cond) if c.type == "identifier"}
                names |= set().union(*(results[r] for r in used & results.keys()))
            for name in names:
                assigned = re.search(rf"(?<![\w.]){re.escape(name)}\s*=(?!=)", body) is not None
                if leaves or assigned:
                    clean(name, n.end_point[0] + 1)
        return out

    @staticmethod
    def _place_check(name: str) -> bool:
        """validateWebhookUrl, assertSafeUrl, isAllowedHost: a check of where a value points (not a schema's parse)."""
        return name not in SANITIZERS and bool(GUARD.search(name) or VALIDATOR.search(name) and re.search(TARGET, name))

    @staticmethod
    def _walk(n):
        stack = [n]
        while stack:
            c = stack.pop()
            yield c
            stack.extend(c.children)

    def _assignments(self):
        for n in self.body:
            if n.type == "variable_declarator":
                yield n.child_by_field_name("name"), n.child_by_field_name("value"), n
            elif n.type in ("assignment_expression", "augmented_assignment_expression", "for_in_statement"):
                yield n.child_by_field_name("left"), n.child_by_field_name("right"), n

    def _targets(self, left) -> list[str]:
        if left is None:
            return []
        left = _strip(left)
        if left.type in ("member_expression", "subscript_expression"):
            base, props = _member_chain(left, self.src)
            if props and props[-1] in ("pathname", "search", "hash"):
                return []  # `next.pathname = x` (a URL's): the host stays what it was
            if base in REQUEST_BASES and props and props[0] in REQUEST_ATTRS:
                return []  # `req.params.slug = x`: request data already, the rest of `req` (its path) isn't x
            return [base] if base and base != "this" else []
        if left.type in ("lexical_declaration", "variable_declaration"):
            return [
                x for d in _kids(left) if d.type == "variable_declarator" for x in self._targets(d.child_by_field_name("name"))
            ]
        return _pattern_names(left, self.src)

    def run(self, tainted: set[int]) -> tuple[list, set]:
        own = {name for names in self.u.params for name in names}
        env: dict[str, set] = {k: set(v) for k, v in self.outer.items() if k not in own}  # a closure's variables
        for i, names in enumerate(self.u.params):
            if i in tainted:
                for name in names:
                    env[name] = {("param", i)}
        for name in self.u.params[0] if self.items and self.u.params else ():
            env[name] = env.get(name, set()) | self.items
        for name, label in self.u.source_names.items():
            env[name] = {("source", label)}
        assigns = list(self._assignments())
        for left, value, _ in assigns:
            for name, label in self._request_parts(left, value).items():
                env[name] = {("source", label)}
        for _ in range(4):
            changed = False
            for left, value, node in assigns:
                if value is None:
                    continue
                self.line = node.start_point[0] + 1
                labels = self.origins(value, env)
                if not labels:
                    continue
                for name in self._targets(left):
                    if not labels <= env.get(name, set()):
                        env[name] = env.get(name, set()) | labels
                        changed = True
            if not changed:
                break
        self.env = env
        self.callbacks = {}
        for n in self.body:
            if n.type == "call_expression" and _callee_name(n, self.src)[0] in ITERATORS:
                f = _strip(n.child_by_field_name("function"))
                fns = [a for a in _args(n) if a.type in ("arrow_function", "function_expression", "function")]
                if fns and f is not None and f.type == "member_expression":
                    self.line = n.start_point[0] + 1
                    if items := self.origins(f.child_by_field_name("object"), env):
                        self.callbacks[fns[0].start_byte] = items
        hits, returns = [], set()
        for n in self.body:
            self.line = n.start_point[0] + 1
            if n.type in ("call_expression", "new_expression"):
                hits += self._sink_hits(n, env)
                hits += self._callee_hits(n, env)
            elif n.type == "jsx_attribute" and _text(n, self.src).startswith("dangerouslySetInnerHTML"):
                for label in _ordered(self.origins(n, env)):
                    hits.append((label, "template", self.line, "dangerouslySetInnerHTML", "", self.u.file))
            elif n.type == "return_statement":
                for c in _kids(n):
                    returns |= self.origins(c, env)
            elif n.type == "arrow_function" and n.parent is not None and n.parent.type != "arguments":
                pass
        return hits, returns

    def _request_parts(self, left, value) -> dict[str, str]:
        """`const { body, query: q } = req` or `= ctx.request`: the names bound to request data."""
        value = _strip(value)
        if left is None or value is None or value.type not in ("identifier", "member_expression"):
            return {}
        if value.type == "member_expression":
            base, props = _member_chain(value, self.src)
        else:
            base, props = _text(value, self.src), []
        if base not in REQUEST_BASES or (base == "request" and not self.server) or props not in ([], ["request"]):
            return {}
        if props and base != "ctx":
            return {}
        whole = _text(value, self.src)
        return {
            name: f"{whole}.{key}"
            for key, names in _pattern_keys(_strip(left), self.src).items()
            if key in REQUEST_ATTRS
            for name in names
        }

    def _sink(self, n) -> tuple[str, list] | None:
        name, recv = _callee_name(n, self.src)
        args = _args(n)
        if not args:
            return None
        if n.type == "new_expression":
            return ("code", args[-1:]) if name == "Function" else None
        base = recv.split(".")[-1] if recv else ""
        if name in SHELL_FUNCS and (base in CHILD_PROCESS or (not recv and self.imports.get(name) == "child_process")
                                    or recv in ("shell", "shelljs")):  # fmt: skip
            return "shell", args[:1]
        if name in SPAWN_FUNCS and (base in CHILD_PROCESS or self.imports.get(name) == "child_process"):
            opts = " ".join(_text(a, self.src) for a in args[1:])
            if re.search(r"\bshell\s*:\s*true", opts):
                return "shell", args[:1]
            return None
        if name == "eval" and not recv:
            return "code", args[:1]
        if name in ("runInNewContext", "runInThisContext", "runInContext", "compileFunction") and base == "vm":
            return "code", args[:1]
        if (
            name in ("setTimeout", "setInterval")
            and not recv
            and _strip(args[0]).type in ("template_string", "binary_expression")
        ):
            return "code", args[:1]
        if name in SQL_METHODS and recv:
            first = _strip(args[0])
            if name in UNSAFE_SQL and name != "raw":
                return "sql", args[:1]
            if first.type in ("template_string", "binary_expression") and SQL_WORDS.search(self._literal(first)):
                return "sql", args[:1]  # the text says it's SQL
            if DB_OBJECT.search(recv) and first.type not in ("template_string", "binary_expression"):
                return "sql", args[:1]
            # (otherwise not SQL: `axios.get(url)` and `map.get(k)` go on to the checks below)
        if name in FS_FUNCS and (
            base in FS_OBJECTS or (not recv and self.imports.get(name) in ("fs", "fs/promises", "fs-extra"))
        ):
            return "path", args[:1]
        if name in SEND_FILE and recv in ("res", "response", "reply"):
            return "path", args[:1]
        own = {p for names in self.u.params for p in names}  # `fetch` a parameter (a loader callback): not the global
        if (name in HTTP_FUNCS and not recv and name not in own) or (name in HTTP_METHODS and base in HTTP_OBJECTS):
            return "ssrf", args[:1]
        if name in REDIRECTS and (recv in ("res", "response", "reply", "ctx", "NextResponse", "Response")
                                  or (not recv and self.imports.get(name) in ("next/navigation", "@remix-run/node",
                                                                              "react-router", "@sveltejs/kit"))):  # fmt: skip
            return "redirect", args[-1:]
        if name in RESPONSE_WRITE and re.match(r"(?:res|response|reply)\b(?:\.\w+\([^()]*\))*$", recv):
            first = _strip(args[0])
            if first.type in ("template_string", "binary_expression") and "<" in _text(first, self.src):
                return "template", args[:1]
        return None

    def _literal(self, n) -> str:
        """The constant parts of a template or a `+` chain: the text around the values."""
        if n.type == "template_string":
            return " ".join(_text(c, self.src) for c in n.children if c.type == "string_fragment")
        if n.type == "binary_expression":
            return " ".join(
                self._literal(_strip(c)) for c in (n.child_by_field_name("left"), n.child_by_field_name("right")) if c
            )
        return _text(n, self.src).strip("'\"`") if n.type == "string" else ""

    def _host_fixed(self, a) -> bool:
        """`https://api.example.com/x/${id}`: the request goes to a fixed host whatever the value."""
        a = _strip(a)
        if a.type == "new_expression" and _callee_name(a, self.src)[0] == "URL" and len(_args(a)) == 2:
            return self._local_path(_args(a)[0])
        lead = ""
        if a.type == "template_string":
            for c in a.children:
                if c.type == "string_fragment":
                    lead += _text(c, self.src)
                elif c.type == "template_substitution":
                    break
        elif a.type == "binary_expression":
            left = _strip(a.child_by_field_name("left"))
            while left is not None and left.type == "binary_expression":
                left = _strip(left.child_by_field_name("left"))
            if left is not None and left.type == "string":
                lead = _text(left, self.src).strip("'\"")
        return bool(re.match(r"(?:https?:)?//[^/?#]+[/?#]", lead)) or (lead.startswith("/") and not lead.startswith("//"))

    def _local_path(self, a) -> bool:
        a = _strip(a)
        if a.type == "new_expression" and _callee_name(a, self.src)[0] == "URL" and len(_args(a)) == 2:
            return self._local_path(_args(a)[0])  # new URL("/booking/x", BASE): stays on BASE
        lead = ""
        if a.type == "string":
            lead = _text(a, self.src).strip("'\"")
        elif a.type == "template_string":
            frags = [c for c in a.children if c.type in ("string_fragment", "template_substitution")]
            lead = _text(frags[0], self.src) if frags and frags[0].type == "string_fragment" else ""
        if lead.startswith(("./", "../", "?", "#")):
            return True  # relative to this page
        return lead.startswith("/") and not lead.startswith("//") and not lead.startswith("/\\")

    def _url_parts(self, a) -> list:
        """What in an outgoing request's argument picks the host: `request({ url, body })` -> [url]."""
        s = _strip(a)
        if s is None or s.type != "object":
            return [a]
        out = []
        for c in _kids(s):
            if c.type == "pair":
                key = c.child_by_field_name("key")
                if key is not None and _text(key, self.src).strip("'\"") in URL_KEYS:
                    out.append(c.child_by_field_name("value"))
            elif c.type == "shorthand_property_identifier" and _text(c, self.src) in URL_KEYS:
                out.append(c)
            elif c.type == "spread_element":
                out += _kids(c)
        return [v for v in out if v is not None]

    def _ssrf_opt_out(self, call) -> bool:
        """Inside `if (isSsrfProtectionDisabled())`: the operator turned the guard off, the code otherwise has one."""
        p = call.parent
        while p is not None and p is not self.u.node:
            if p.type == "if_statement":
                cond = p.child_by_field_name("condition")
                text = _text(cond, self.src) if cond is not None else ""
                if re.search(r"ssrf\w*(?:disabled|off)|disable\w*ssrf", text, re.I):
                    return True
            p = p.parent
        return False

    def _rooted(self, call) -> bool:
        """`res.sendFile(name, { root })`, Fastify's `reply.sendFile(name, root)`: send refuses a path out of root."""
        name, recv = _callee_name(call, self.src)
        args = _args(call)
        if name not in SEND_FILE or len(args) < 2:
            return False
        second = _strip(args[1])
        if second.type == "object":
            return re.search(r"(?<![\w.])root\b", _text(second, self.src)) is not None
        return recv == "reply" and name == "sendFile" and second.type not in ("arrow_function", "function_expression")

    def _sink_hits(self, n, env) -> list:
        sink = self._sink(n)
        if not sink:
            return []
        kind, args = sink
        if kind == "ssrf":
            if SAFE_AGENT.search(" ".join(_text(a, self.src) for a in _args(n))) or self._ssrf_opt_out(n):
                return []
            args = [v for a in args for v in self._url_parts(a)]
        if kind == "path" and self._rooted(n):
            return []
        out = []
        self.guard = self.guarded.get(n.start_byte, set())
        for a in args:
            s = _strip(a)
            if s is None or s.type in ("string", "number"):
                continue
            if kind in ("ssrf",) and self._host_fixed(s):
                continue
            if kind == "redirect" and self._local_path(s):
                continue
            for label in _ordered(self.origins(s, env)):
                if kind in ("redirect", "ssrf") and len(label) > 2:
                    continue  # only in the query string
                text = _text(n.child_by_field_name("function") or n.child_by_field_name("constructor") or n, self.src)
                out.append((label, kind, n.start_point[0] + 1, text[:50], "", self.u.file))
        self.guard = set()
        return out

    def _callee_hits(self, n, env) -> list:
        name, recv = _callee_name(n, self.src)
        summary = self.callees.get(name)
        if re.fullmatch(r"this\.\w+", recv):  # an injected service's method: this.usersService.update(id, dto)
            summary = self.callees.get(f"{recv}.{name}")
        elif summary is None or name in SANITIZERS or (recv and recv != "this" and not re.fullmatch(r"\w+", recv)):
            return []
        if summary is None:
            return []
        out = []
        for i, a in enumerate(_args(n)):
            for flow in summary.sinks.get(i, []):
                for label in _ordered(self.origins(a, env)):
                    if flow[0] in ("redirect", "ssrf") and len(label) > 2:
                        continue  # past a fixed host, as in _sink_hits
                    via = f"{name}()" + (" → " + flow[3] if flow[3] else "")
                    out.append((label, flow[0], flow[1], flow[2], via, flow[4]))
        return out


def _imports(tree, src: bytes) -> dict[str, str]:
    """Local name -> module, for `import { exec } from "child_process"` and `const { exec } = require("child_process")`."""
    out: dict[str, str] = {}
    for n in tree.root_node.children:
        if n.type == "import_statement":
            mod = n.child_by_field_name("source")
            module = _text(mod, src).strip("'\"").removeprefix("node:") if mod is not None else ""
            for spec in _kids(n):
                if spec.type == "import_clause":
                    for x in _pattern_import_names(spec, src):
                        out[x] = module
        elif n.type in ("lexical_declaration", "variable_declaration"):
            for d in _kids(n):
                if d.type != "variable_declarator":
                    continue
                v = _strip(d.child_by_field_name("value"))
                if v is not None and v.type == "call_expression" and _callee_name(v, src)[0] == "require":
                    args = _args(v)
                    if args and args[0].type == "string":
                        module = _text(args[0], src).strip("'\"").removeprefix("node:")
                        for x in _pattern_names(d.child_by_field_name("name"), src):
                            out[x] = module
    return out


def _pattern_import_names(clause, src: bytes) -> list[str]:
    out = []
    stack = [clause]
    while stack:
        c = stack.pop()
        if c.type == "import_specifier":
            alias = c.child_by_field_name("alias") or c.child_by_field_name("name")
            out.append(_text(alias, src))
            continue
        if c.type == "identifier":
            out.append(_text(c, src))
        stack.extend(_kids(c))
    return out


def _ordered(labels: set) -> list:
    """A set's labels in a fixed order: a summary is then the same whatever the hash seed, so the work list settles
    (the same flows in another order counted as a change, and spent its budget) and the same flow wins a sink line."""
    return sorted(labels, key=repr)


def summarize(fn: _Function) -> Summary:
    s = Summary()
    hits, returns = fn.run(set(range(len(fn.u.params))))
    for label, kind, line, text, via, file in hits:
        if label[0] == "param":
            s.sinks.setdefault(label[1], []).append((kind, line, text, via, file))
        else:
            s.source_sinks.append((label[1], kind, line, text, via, file))
    s.returns = {lab[1] for lab in returns if lab[0] == "param"}
    s.source_returns = min((lab[1] for lab in returns if lab[0] == "source"), default="")
    return s


def js_taint_flags(g: Graph, root: Path) -> list[Flag]:
    """Proven flows from request data to a sink in JavaScript and TypeScript, one finding per sink line."""
    if not available():
        return []
    from tree_sitter_language_pack import get_parser

    from .paths import is_doc_sample, is_example_code, is_test

    files = [f.id for f in g.files if Path(f.id).suffix in EXT_LANG and not f.id.endswith(".d.ts")]
    files = [f for f in files if not (is_test(f) or is_doc_sample(f) or is_example_code(f))]
    texts: dict[str, bytes] = {}
    for f in files:
        try:
            data = (root / f).read_bytes()
        except OSError:
            continue
        if len(data) > 400_000 or b"\x00" in data[:2000]:
            continue  # bundles and generated files
        texts[f] = data
    with_source = {f for f, t in texts.items() if SOURCE_HINT.search(t.decode("utf-8", "replace"))}
    with_sink = {f for f, t in texts.items() if SINK_HINT.search(t.decode("utf-8", "replace"))}
    if not with_source or not with_sink:
        return []
    # files on a path from a source to a sink: the source files, and the files they reach (by import) that hold sinks
    deps: dict[str, set[str]] = {}
    for e in g.edges:
        sf, df = e.src.split("::")[0], e.dst.split("::")[0]
        if sf != df:
            deps.setdefault(sf, set()).add(df)
    reach, stack = set(with_source), list(with_source)
    while stack:
        for d in deps.get(stack.pop(), ()):
            if d in texts and d not in reach:
                reach.add(d)
                stack.append(d)
    wanted = sorted((reach & with_sink) | (with_source & with_sink) | {f for f in with_source if deps.get(f, set()) & with_sink})
    wanted = sorted(set(wanted) | {d for f in wanted for d in deps.get(f, ()) if d in with_sink})
    # …and what a handler calls even without a sink there, for what it returns: decodeToken(x) hands back a signed value
    wanted = sorted(set(wanted) | {d for f in wanted if f in with_source for d in deps.get(f, ()) if d in texts})
    units: list[Unit] = []
    trees: dict[str, tuple] = {}
    unloadable: dict[str, str] = {}
    for f in wanted:
        lang = EXT_LANG[Path(f).suffix]
        try:
            tree = get_parser(lang).parse(texts[f])
        except Exception as e:  # a grammar that can't load (offline on first use): leave the file out, and say so
            unloadable.setdefault(lang, f"{type(e).__name__}: {str(e)[:120]}")
            continue
        trees[f] = (tree, _imports(tree, texts[f]))
        base = len(units)
        for u in units_of(f, tree, texts[f]):
            u.parent = base + u.parent if u.parent >= 0 else -1
            units.append(u)
    if unloadable:
        import sys

        from .analyzers import INCOMPLETE

        why = next(iter(unloadable.values()))
        print(f"codefactory: request-data flows in {', '.join(sorted(unloadable))} files weren't traced: the "
              f"tree-sitter grammar couldn't be loaded ({why}).", file=sys.stderr)  # fmt: skip
        INCOMPLETE.extend(sorted(unloadable))  # not cached: the next run tries again
    if not units:
        return []
    # map units to graph functions (for where the finding points), and calls to units by name: same file first
    graph_fns: dict[tuple[str, int], str] = {}
    for fn in g.functions:
        if fn.kind != "module" and fn.file in trees:
            for d in (0, 1, -1, 2):
                graph_fns.setdefault((fn.file, fn.line + d), fn.id)
    by_name: dict[str, list[int]] = {}
    for i, u in enumerate(units):
        u.fid = graph_fns.get((u.file, u.line), "")
        if not u.inline and u.parent >= 0:
            by_name.setdefault(u.name, []).append(i)

    def resolve(i: int, name: str) -> int | None:
        cands = by_name.get(name, [])
        same = [c for c in cands if units[c].file == units[i].file and c != i]
        if same:
            return same[0]
        imported = trees[units[i].file][1]
        if name in imported:
            mod = imported[name]
            others = [c for c in cands if mod.lstrip("./") and Path(units[c].file).stem in mod.split("/")[-1:] or c in cands]
            others = [c for c in cands if units[c].file != units[i].file]
            if len(others) == 1:
                return others[0]
        return None

    # Nest and n8n inject services: `this.usersService.update(dto)` is UsersService's update, by the field's type
    methods = {(u.cls, u.name): i for i, u in enumerate(units) if u.cls}
    field_types: dict[int, dict[str, str]] = {}

    def fields_of(i: int) -> dict[str, str]:
        cls = units[i].node
        while cls is not None and cls.type not in ("class_declaration", "class", "abstract_class_declaration"):
            cls = cls.parent
        if cls is None:
            return {}
        if cls.id not in field_types:
            text = _text(cls, texts[units[i].file])
            field_types[cls.id] = dict(re.findall(INJECTED, text))
        return field_types[cls.id]

    calls_of: dict[int, dict[str, int]] = {}
    callers_of: dict[int, set[int]] = {}
    for i, u in enumerate(units):
        src = texts[u.file]
        text = _text(u.node, src)
        names = {m.group(1) for m in re.finditer(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*\(", text)}
        resolved = {}
        for name in names:
            j = resolve(i, name)
            if j is not None:
                resolved[name] = j
        if methods and "this." in text:
            for fld, name in set(re.findall(r"\bthis\.(\w+)\.(\w+)\s*(?:<[^<>()]*>)?\s*\(", text)):
                typ = fields_of(i).get(fld) or fld[:1].upper() + fld[1:]
                if (j := methods.get((typ, name))) is not None and j != i:
                    resolved[f"this.{fld}.{name}"] = j
        for j in resolved.values():
            callers_of.setdefault(j, set()).add(i)
        calls_of[i] = resolved

    def depth(i: int) -> int:
        d = 0
        while units[i].parent >= 0:
            i, d = units[i].parent, d + 1
        return d

    children: dict[int, set[int]] = {}
    for i, u in enumerate(units):
        if u.parent >= 0:
            children.setdefault(u.parent, set()).add(i)
    summaries: dict[int, Summary] = {}
    # parents before their closures (they need the parent's variables); callees settle as callers are redone
    work = deque(sorted(range(len(units)), key=lambda i: (depth(i), len(calls_of[i]))))
    queued, budget, redone = set(work), 8 * len(units) + 100, {}
    fns: dict[int, _Function] = {}
    while work and budget > 0:
        budget -= 1
        i = work.popleft()
        queued.discard(i)
        redone[i] = redone.get(i, 0) + 1
        if redone[i] > 6:
            continue
        u = units[i]
        callees = {name: summaries[j] for name, j in calls_of[i].items() if j in summaries}
        fn = fns.get(i)
        if fn is None:
            fn = fns[i] = _Function(u, texts[u.file], callees, trees[u.file][1])
        fn.callees = callees
        if u.parent >= 0 and u.parent in fns:
            fn.outer = fns[u.parent].env
            fn.items = fns[u.parent].callbacks.get(u.node.start_byte, set())
        s = summarize(fn)
        old = summaries.get(i)
        if old is None or (s.sinks, s.returns, s.source_sinks, s.source_returns) != (
            old.sinks, old.returns, old.source_sinks, old.source_returns
        ):  # fmt: skip
            summaries[i] = s
            for c in callers_of.get(i, set()) | children.get(i, set()):
                if c not in queued:
                    work.append(c)
                    queued.add(c)
    spans: dict[str, list] = {}
    for fn in g.functions:
        if fn.kind != "module" and fn.file in trees:
            spans.setdefault(fn.file, []).append(fn)

    def containing(file: str, line: int) -> str:
        """The innermost function around a line (the finding points there), else the file."""
        inside = [f for f in spans.get(file, ()) if f.line <= line <= (f.end or f.line)]
        return min(inside, key=lambda f: (f.end or f.line) - f.line).id if inside else file

    def entry_of(i: int) -> str:
        while i >= 0:
            if units[i].entry:
                return units[i].entry
            i = units[i].parent
        return ""

    def named(i: int) -> str:
        while i >= 0 and units[i].inline:
            i = units[i].parent
        return units[i].name if i >= 0 and units[i].parent >= 0 else ""

    out, seen = [], set()
    for i, s in summaries.items():
        u = units[i]
        route = entry_of(i) if u.inline or not u.sources else ""
        flows = [(f"{src} in {route}" if route else src, *rest) for src, *rest in s.source_sinks]
        for p in u.sources:  # a handler's parameters that are request data on entry
            names = u.params[p] if p < len(u.params) else []
            what = f"parameter `{', '.join(names) or p}` of {u.entry}" if u.entry else f"parameter `{', '.join(names)}`"
            flows += [(what, *flow) for flow in s.sinks.get(p, [])]
        for src, kind, line, text, via, file in flows:
            key = (kind, file, line)
            if key in seen:
                continue
            seen.add(key)
            where = f" → {named(i)}" if named(i) else ""
            chain = f"{src}{where}" + (f" → {via}" if via else "") + f" → {text}()"
            target = containing(file, line)
            what = KIND_TEXT[kind]
            article = "an" if what[0] in "aeiou" else "a"
            out.append(Flag("taint", "high", target, f"Request data reaches {article} {what}: {chain}", [], line=line,
                            detail=kind))  # fmt: skip
    return out
