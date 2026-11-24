"""The attack surface: where requests come in, whether they check who's asking, and what risky code they reach.

Entry points are found per framework from the source text around each handler (decorators, route registrations,
file conventions): FastAPI, Flask, Django and DRF, Express-style routers (Express, Koa, Fastify, Hono), Next.js API
routes, Spring, Go net/http and gin/echo/chi, Rails and Sinatra. From each entry, the call graph says which risky
lines it reaches (SQL built from strings, shell commands, eval, raw HTML) and whether it writes data. A finding on a
path from a request is evidence; one no request reaches is a lead at most.

All of it is pattern-based: an auth check done some other way (a gateway, a custom decorator with an unusual name)
is missed, so "no auth check found" is a question to answer, and the report says so.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .brief import View
from .efficiency import kind_of

AUTH = re.compile(
    r"auth|login|logged|jwt|token|session|permission|current_?user|require_?user|verify|protect|guard|admin|"
    r"secured|roles?_?(?:required|allowed)|principal|bearer|api_?key|signed_?in|ensure_?user|clerk|passport",
    re.I,
)
SINK_KINDS = ("sql_built", "shell", "eval", "raw_html")
METHODS = "get|post|put|patch|delete|head|options"

PY_ROUTE = re.compile(rf"@\s*[\w.]+\.({METHODS}|api_route|route|websocket)\(\s*(?:path\s*=\s*)?[rf]?['\"]([^'\"]*)['\"]([^\n]*)")
PY_METHODS = re.compile(r"methods\s*=\s*[\[(]([^\])]*)")
DRF_VIEW = re.compile(r"@\s*api_view\(\s*\[?([^\])]*)")
PY_AUTH_DECORATOR = re.compile(
    r"@\s*[\w.]*(?:login_required|permission_required|jwt_required|token_required|auth\w*_required|requires?_auth\w*|"
    r"admin_required|roles?_(?:required|accepted)|authenticated|protected|user_passes_test|staff_member_required)\b"
)
DEPENDS = re.compile(r"(?:Depends|Security)\(\s*([\w.]+)")
ALIAS = re.compile(r"^(\w+)\s*=\s*Annotated\[[^\n]*?(?:Depends|Security)\(\s*([\w.]+)", re.M)
ROUTER_DEPS = re.compile(r"(?:APIRouter|FastAPI|include_router)\([^)]*dependencies\s*=\s*\[([^\]]*)\]", re.S)
DJANGO_PATH = re.compile(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)")
JS_ROUTE = re.compile(rf"\b(\w+)\.({METHODS}|all)\(\s*['\"`](/[^'\"`]*)['\"`]\s*,([^\n]*)")
JS_APP_AUTH = re.compile(r"\b\w+\.use\(\s*([^\n)]*)")
NEXT_METHOD = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)$")
SPRING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\")?")
SPRING_AUTH = re.compile(r"@(?:PreAuthorize|Secured|RolesAllowed|PostAuthorize)\b")
GO_ROUTE = re.compile(
    r"\b\w+\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Any)\(\s*\"(/[^\"]*)\"\s*,\s*([^\n]*)"
)
SINATRA = re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"](/[^'\"]*)['\"]", re.M)
RAILS_AUTH = re.compile(r"before_action\s+:(\w+)")
LOCAL = re.compile(r"""(?:host|bind|api_host|HOST)(?:\s*:\s*\w+)?\s*[=:]\s*['"](127\.0\.0\.1|localhost|::1)['"]""")
OPEN = re.compile(r"""['"]0\.0\.0\.0['"]""")  # anywhere: a server that can listen on every interface
# What shows a change: the SQL verb, or a call named for it. A bare commit/rollback only ends a transaction (every
# `with db.session():` helper does it), so it isn't evidence that anything changed.
CHANGES = re.compile(
    r"INSERT|UPDATE|DELETE|REPLACE|UPSERT|MERGE|(?:^|\.)(?:save|insert\w*|update\w*|delete\w*|remove\w*|create\w*|"
    r"upsert\w*|put\w*|write\w*|add\w*|set\w*|destroy\w*|bulk_\w+)(?:\(|$)",
)
WRITE_CALL = re.compile(r"(?:^|\.)(?:run|runAsync|runSync|execAsync|execSync|executeUpdate|executemany|executescript)\b")


@dataclass
class Entry:
    fn: str  # the handler's function id (the file's <module> for an inline handler)
    method: str
    path: str
    framework: str
    file: str
    line: int
    auth: str = ""  # what checks the caller ("Depends(get_current_user)", "@login_required", "app-wide …"), or ""


@dataclass
class Surface:
    entries: list[Entry] = field(default_factory=list)
    reach: dict[str, tuple[int, list[str]]] = field(default_factory=dict)  # fn -> (entry index, path of fn ids)
    exposure: str = "unknown"  # local | open | configurable | unknown
    exposure_evidence: str = ""

    def chain(self, fid: str, v: View) -> str:
        if fid not in self.reach:
            return ""
        i, path = self.reach[fid]
        e = self.entries[i]
        names = [v.fn[p]["qualname"] for p in path if p in v.fn and v.fn[p]["kind"] != "module"]
        return f"{e.method} {e.path} → " + " → ".join(names or [Path(e.file).name])


def _read(root: Path, cache: dict, file: str) -> list[str]:
    if file not in cache:
        try:
            cache[file] = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[file] = []
    return cache[file]


def _above(lines: list[str], line: int, limit: int = 12) -> str:
    """Decorators and annotations right above a definition (line is 1-based)."""
    out, i = [], line - 2
    while i >= 0 and len(out) < limit:
        s = lines[i].strip()
        if not s or not (s.startswith("@") or s.endswith((",", "(", ")", "]")) or out and s.startswith(("'", '"', ")"))):
            break
        out.append(lines[i])
        i -= 1
    return "\n".join(reversed(out))


def _signature(lines: list[str], line: int) -> str:
    return "\n".join(lines[line - 1 : line + 8]).split(":\n")[0]


def find_entries(root: Path, g: dict, v: View) -> list[Entry]:
    cache: dict[str, list[str]] = {}
    by_file: dict[str, list[dict]] = {}
    for f in g["functions"]:
        by_file.setdefault(f["file"], []).append(f)
    entries: list[Entry] = []
    aliases = {}  # FastAPI: CurrentUser = Annotated[User, Depends(get_current_user)]
    for file in by_file:
        if file.endswith(".py"):
            for m in ALIAS.finditer("\n".join(_read(root, cache, file))):
                aliases[m.group(1)] = m.group(2)
    for file, fns in by_file.items():
        lines = _read(root, cache, file)
        text = "\n".join(lines)
        module = next((f for f in fns if f["kind"] == "module"), None)
        named = {f["name"]: f for f in fns if f["kind"] != "module"}
        if file.endswith(".py"):
            pm = re.search(r"(?:APIRouter|Blueprint)\([^)]*?(?:prefix|url_prefix)\s*=\s*['\"]([^'\"]*)['\"]", text, re.S)
            prefix = pm.group(1).rstrip("/") if pm else ""
            router_auth = ", ".join(n for m in ROUTER_DEPS.finditer(text) for n in DEPENDS.findall(m.group(1)) if AUTH.search(n))
            for f in fns:
                if f["kind"] == "module":
                    continue
                deco = _above(lines, f["line"])
                route, drf = PY_ROUTE.search(deco), DRF_VIEW.search(deco)
                if not (route or drf):
                    continue
                if route:
                    verb, path, rest = route.group(1).upper(), route.group(2), route.group(3)
                    if verb in ("ROUTE", "API_ROUTE"):
                        ms = PY_METHODS.search(rest)
                        verb = ",".join(re.findall(r"\w+", ms.group(1))).upper() if ms else "GET"
                    framework = "FastAPI" if re.search(r"APIRouter|FastAPI", text) else "Flask"
                else:
                    verb, path, framework = ",".join(re.findall(r"\w+", drf.group(1))).upper() or "GET", f["name"], "DRF"
                sig = _signature(lines, f["line"])
                deps = [d for d in DEPENDS.findall(deco + sig) if AUTH.search(d)]
                deps += [aliases[a] for a in re.findall(r":\s*(\w+)", sig) if a in aliases and AUTH.search(aliases[a])]
                auth = (
                    (PY_AUTH_DECORATOR.search(deco) and PY_AUTH_DECORATOR.search(deco).group(0).strip())
                    or (deps and f"Depends({deps[0]})")
                    or (router_auth and f"router: Depends({router_auth})")
                    or ""
                )
                entries.append(Entry(f["id"], verb, (prefix + path) if route else path, framework, file, f["line"], auth))
            if file.endswith("urls.py"):
                for m in DJANGO_PATH.finditer(text):
                    target = m.group(2).split(".")[-1]
                    for f in g["functions"]:
                        if f["name"] == target or f["qualname"].split(".")[0] == target:
                            deco = _above(_read(root, cache, f["file"]), f["line"])
                            auth = PY_AUTH_DECORATOR.search(deco)
                            entries.append(Entry(f["id"], "ANY", "/" + m.group(1), "Django", f["file"], f["line"],
                                                 auth.group(0).strip() if auth else ""))  # fmt: skip
        elif file.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            app_auth = next((m.group(1) for m in JS_APP_AUTH.finditer(text) if AUTH.search(m.group(1))), "")
            for i, ln in enumerate(lines, 1):
                m = JS_ROUTE.search(ln)
                if not m or m.group(1) in ("axios", "http", "fetch", "client", "api", "request", "supertest", "agent"):
                    continue
                rest = re.sub(r"\)\s*;?\s*(?://.*)?$", "", m.group(4))  # the call's closing `);`
                args = [a.strip() for a in rest.split(",") if a.strip()]
                idents = [a for a in args if re.fullmatch(r"[\w.]+", a)]
                handler = named.get(idents[-1].split(".")[-1]) if idents and not re.search(r"=>|function", args[-1]) else None
                middleware = idents[:-1] if handler else idents
                auth = next((mw for mw in middleware if AUTH.search(mw)), "") or (app_auth and f"app.use({app_auth})")
                target = handler or module
                if target:
                    entries.append(Entry(target["id"], m.group(2).upper(), m.group(3), "Express-style", file, i, auth))
            api_route = re.search(r"(?:^|/)pages/api/", file) or re.search(r"(?:^|/)app/.*route\.[jt]sx?$", file)
            if api_route:
                for f in fns:
                    if f["kind"] == "module" or not (NEXT_METHOD.match(f["name"]) or f.get("exported")):
                        continue
                    body = "\n".join(lines[f["line"] - 1 : f["end"]])
                    auth = re.search(r"getServerSession|getToken|auth\(\)|currentUser|requireAuth|clerk|withAuth", body)
                    path = "/" + re.sub(r"^.*?(?:pages/api|app)/|/?route\.[jt]sx?$|\.[jt]sx?$", "", file)
                    method = f["name"] if NEXT_METHOD.match(f["name"]) else "ANY"
                    entries.append(Entry(f["id"], method, path, "Next.js", file, f["line"], auth.group(0) if auth else ""))
        elif file.endswith((".java", ".kt")):
            for f in fns:
                if f["kind"] == "module":
                    continue
                deco = _above(lines, f["line"])
                m = SPRING.search(deco)
                if m:
                    auth = SPRING_AUTH.search(deco)
                    verb = "ANY" if m.group(1) == "Request" else m.group(1).upper()
                    entries.append(
                        Entry(f["id"], verb, m.group(2) or "", "Spring", file, f["line"], auth.group(0) if auth else "")
                    )
        elif file.endswith(".go"):
            for i, ln in enumerate(lines, 1):
                m = GO_ROUTE.search(ln)
                if m:
                    args = re.findall(r"[\w.]+", m.group(3))
                    handler = next((named[a.split(".")[-1]] for a in reversed(args) if a.split(".")[-1] in named), None)
                    auth = next((a for a in args if AUTH.search(a)), "")
                    verb = "ANY" if m.group(1) in ("HandleFunc", "Handle", "Any") else m.group(1).upper()
                    if handler or module:
                        entries.append(Entry((handler or module)["id"], verb, m.group(2), "Go", file, i, auth))
        elif file.endswith(".rb"):
            for m in SINATRA.finditer(text):
                if module:
                    line = text[: m.start()].count("\n") + 1
                    entries.append(Entry(module["id"], m.group(1).upper(), m.group(2), "Sinatra", file, line))
            if re.search(r"(?:^|/)app/controllers/.*_controller\.rb$", file):
                private_at = next((i for i, ln in enumerate(lines, 1) if re.match(r"\s*(private|protected)\s*$", ln)), 10**9)
                guard = next((a for a in RAILS_AUTH.findall(text) if AUTH.search(a)), "")
                for f in fns:
                    if f["kind"] == "method" and f["line"] < private_at:
                        action = f"{Path(file).stem.removesuffix('_controller')}#{f['name']}"
                        entries.append(
                            Entry(f["id"], "ANY", action, "Rails", file, f["line"], guard and f"before_action :{guard}")
                        )
    return entries


def exposure(root: Path, files: list[str]) -> tuple[str, str]:
    local = opened = ""
    for file in files:
        try:
            text = (root / file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not local and (m := LOCAL.search(text)):
            local = f"{file}: {m.group(0)}"
        if not opened and (m := OPEN.search(text)):
            opened = f"{file}: {m.group(0)}"
    if local and opened:
        return "configurable", f"{local}; {opened}"
    if local:
        return "local", local
    if opened:
        return "open", opened
    return "unknown", ""


def surface(root: Path, g: dict, v: View) -> Surface:
    entries = find_entries(root, g, v)
    s = Surface(entries=entries)
    s.exposure, s.exposure_evidence = exposure(root, [f["id"] for f in g["files"] if not f["id"].startswith(("test", "tests/"))])
    out_edges: dict[str, list[str]] = {}
    for e in g["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], []).append(e["dst"])
    parent: dict[str, str | None] = {}
    origin: dict[str, int] = {}
    q: deque[str] = deque()
    for i, e in enumerate(entries):
        if e.fn not in origin:
            origin[e.fn], parent[e.fn] = i, None
            q.append(e.fn)
    while q:
        cur = q.popleft()
        for nxt in out_edges.get(cur, ()):
            if nxt not in origin:
                origin[nxt], parent[nxt] = origin[cur], cur
                q.append(nxt)
    for fid in origin:
        path, cur = [], fid
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        s.reach[fid] = (origin[fid], list(reversed(path)))
    return s


def function_at(v: View, file: str, line: int) -> str | None:
    """The innermost function holding a line (a sink's owner), else the file's top-level code."""
    best = None
    for f in v.fns_in.get(file, []):
        if f["line"] <= line <= f["end"] and (best is None or f["line"] >= best["line"]):
            best = f
    return best["id"] if best else (f"{file}::<module>" if f"{file}::<module>" in v.fn else None)


def writes(v: View) -> set[str]:
    """Functions that visibly change something themselves: a database write (INSERT/UPDATE/DELETE, commit, save…), a
    file write, or a program run. An `execute` whose SQL can't be seen doesn't count (it may well be a read), and
    neither does a bare commit."""
    out = set()
    for fid, f in v.fn.items():
        if "migrat" in f["name"].lower() or "migration" in f["file"].lower():
            continue  # schema setup runs on every open: not a change a request makes
        for io in f.get("io", []):
            kind = kind_of(io)
            if kind == "process" or (kind in ("write", "file") and (CHANGES.search(io) or WRITE_CALL.search(io))):
                out.add(fid)
                break
    return out
