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
from .paths import is_test

AUTH = re.compile(
    r"auth|login|logged|jwt|token|session|permission|current_?user|require_?user|verify|protect|guard|admin|"
    r"secured|roles?_?(?:required|allowed)|principal|bearer|api_?key|signed_?in|ensure_?user|clerk|passport|"
    r"require_?account|require_?user|authenticated",
    re.I,
)
SINK_KINDS = ("sql_built", "shell", "eval", "raw_html")
METHODS = "get|post|put|patch|delete|head|options"

PY_ROUTE = re.compile(
    rf"@\s*(?!mock\.|patch\.|unittest\.)[\w.]+\.({METHODS}|api_route|route|websocket)\(\s*(?:path\s*=\s*)?[rf]?['\"]([^'\"]*)['\"]([^\n]*)"
)
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
# Laravel (routes/*.php) and Symfony attributes
LARAVEL_ROUTE = re.compile(
    r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(\s*(?:\[[^\]]*\],\s*)?['\"]([^'\"]+)['\"]"
)
SYMFONY_ROUTE = re.compile(r"#\[Route\(\s*(?:path:\s*)?['\"]([^'\"]+)['\"][^\]]*?(?:methods:\s*\[([^\]]*)\])?")
# Rust: Rocket / Actix attribute macros, Axum's router
RUST_ATTR_ROUTE = re.compile(r"#\[(get|post|put|patch|delete|head|options|route)\(\s*\"([^\"]*)\"")
AXUM_ROUTE = re.compile(r"\.route\(\s*\"(/[^\"]*)\"\s*,\s*(get|post|put|patch|delete|any)\(\s*([\w:]+)")
RUST_GUARD = re.compile(r"impl\s*(?:<[^>]*>)?\s*FromRequest(?:Parts)?\s*(?:<[^>]*>)?\s*for\s+(\w+)")
# ASP.NET: minimal APIs and controller attributes
ASPNET_MAP = re.compile(r"(\w+)\.Map(Get|Post|Put|Patch|Delete|Methods)\(\s*\"([^\"]*)\"")
ASPNET_GROUP = re.compile(r"(?:var\s+)?(\w+)\s*=\s*[^;]*?MapGroup\([^;]*;", re.S)
ASPNET_ATTR = re.compile(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*\"([^\"]*)\"\s*\))?\]")
# Phoenix (Elixir) router
PHOENIX_ROUTE = re.compile(r"^\s*(get|post|put|patch|delete|live|resources|forward)\s+\"(/[^\"]*)\"(?:\s*,\s*([\w.]+))?", re.M)
SINATRA = re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"](/[^'\"]*)['\"]", re.M)
RAILS_AUTH = re.compile(r"before_action\s+:(\w+[!?]?)")
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


RAILS_CLASS = re.compile(r"^\s*class\s+([\w:]+)\s*<\s*([\w:]+)", re.M)
RAILS_SKIP = re.compile(r"skip_before_action\s+:(\w+)(?:[^\n]*?only:\s*\[?([^\]\n]*))?")


class _RailsControllers:
    """Auth a Rails controller gets from the controllers it inherits from (`before_action :authenticate_user!` in
    ApplicationController or an API base controller), and what it skips with `skip_before_action`."""

    def __init__(self, root: Path, files: list[str], cache: dict):
        self.own: dict[str, tuple[str, str]] = {}  # class short name -> (guard, parent short name)
        self.concerns: dict[str, str] = {}  # concern module name -> the auth before_action its `included` block adds
        for file in files:
            text = "\n".join(_read(root, cache, file))
            if "/concerns/" in file:
                guard = next((a for a in RAILS_AUTH.findall(text) if AUTH.search(a)), "")
                m = re.search(r"^\s*module\s+([\w:]+)", text, re.M)
                if guard and m:
                    self.concerns[m.group(1).split("::")[-1]] = guard
        for file in files:
            text = "\n".join(_read(root, cache, file))
            m = RAILS_CLASS.search(text)
            if m and "/concerns/" not in file:
                self.own[m.group(1).split("::")[-1]] = (self._own(text), m.group(2).split("::")[-1])

    def _own(self, text: str) -> str:
        """The controller's own auth before_action, or one an included concern adds (`include Authentication`)."""
        own = next((a for a in RAILS_AUTH.findall(text) if AUTH.search(a)), "")
        if own:
            return own
        for line in re.findall(r"^\s*include\s+([^\n]+)", text, re.M):
            for name in re.findall(r"[\w:]+", line):
                if name.split("::")[-1] in self.concerns:
                    return self.concerns[name.split("::")[-1]]
        return ""

    def guard(self, text: str) -> tuple[str, str]:
        """(the auth before_action that applies, "from <Parent>" when inherited)."""
        m = RAILS_CLASS.search(text)
        own = self._own(text)
        if own or not m:
            return own, ""
        parent, seen = m.group(2).split("::")[-1], set()
        while parent in self.own and parent not in seen:
            seen.add(parent)
            guard, grand = self.own[parent]
            if guard:
                return guard, f"from {parent}"
            parent = grand
        return "", ""

    @staticmethod
    def skipped(text: str) -> set[str] | None:
        """Actions an auth before_action is skipped for: None (not skipped), empty (all), or the `only:` ones."""
        for m in RAILS_SKIP.finditer(text):
            if AUTH.search(m.group(1)):
                return set(re.findall(r"\w+", m.group(2) or ""))
        # a concern's helper: `skip_authentication only: :new` (Rails 8's generator, and many apps)
        for m in re.finditer(r"^\s*(?:skip_\w*auth\w*|allow_unauthenticated_access)\b([^\n]*)", text, re.M):
            only = re.search(r"only:\s*\[?([^\]\n]*)", m.group(1))
            return set(re.findall(r"\w+", only.group(1))) if only else set()
        return None


def _php_entries(file: str, lines: list[str], text: str, module, fns: list[dict]) -> list[Entry]:
    out = []
    if module and re.search(r"(?:^|/)routes/[\w/]+\.php$", file):
        auth_until = []  # brace depths of open groups whose middleware checks who's asking
        depth = 0
        for i, ln in enumerate(lines, 1):
            if re.search(r"middleware\(", ln) and AUTH.search(ln) and ("{" in ln or "group(" in ln):
                auth_until.append(depth)
            m = LARAVEL_ROUTE.search(ln)
            if m:
                verb = {"any": "ANY", "match": "ANY", "resource": "ANY", "apiresource": "ANY"}.get(m.group(1).lower(),
                                                                                                m.group(1).upper())  # fmt: skip
                guard = "middleware(auth) group" if auth_until else ""
                if re.search(r"->middleware\(", ln) and AUTH.search(ln.split("->middleware(", 1)[1]):
                    guard = "->middleware(auth)"
                out.append(Entry(module["id"], verb, "/" + m.group(2).lstrip("/"), "Laravel", file, i, guard))
            depth += ln.count("{") - ln.count("}")
            while auth_until and depth <= auth_until[-1]:
                auth_until.pop()
    for f in fns:  # Symfony: #[Route('/x', methods: ['POST'])] on a controller method
        if f["kind"] == "module":
            continue
        head = "\n".join(lines[max(0, f["line"] - 6) : f["line"] + 1])
        m = SYMFONY_ROUTE.search(head)
        if m:
            verb = ",".join(re.findall(r"\w+", m.group(2) or "")).upper() or "ANY"
            auth = re.search(r"#\[IsGranted|denyAccessUnlessGranted|#\[Security", head + "\n".join(lines[f["line"] : f["end"]]))
            out.append(Entry(f["id"], verb, m.group(1), "Symfony", file, f["line"], auth.group(0) if auth else ""))
    return out


def _rust_entries(file, lines, text, module, named, fns, guards: set[str]) -> list[Entry]:
    out = []
    for f in fns:  # Rocket / Actix: the attribute is on (or just above) the function's first line
        if f["kind"] == "module":
            continue
        # the attributes stacked directly above (or starting) this function, then its signature up to the body
        start = f["line"] - 1
        while start > 0 and re.match(r"\s*(?:#\[|///)", lines[start - 1]):
            start -= 1
        attrs = "\n".join(ln for ln in lines[start : f["line"]] if re.match(r"\s*#\[", ln))
        sig = "\n".join(lines[f["line"] - 1 : f["line"] + 6]).split("{")[0]
        m = RUST_ATTR_ROUTE.search(attrs + "\n" + sig.split("fn ", 1)[0])
        if m:
            auth = next((g for g in guards if re.search(rf":\s*{g}\b", sig)), "") or ((a := AUTH.search(sig)) and a.group(0))
            out.append(Entry(f["id"], m.group(1).upper(), m.group(2), "Rust", file, f["line"], auth or ""))
    for i, ln in enumerate(lines, 1):  # Axum: .route("/x", get(handler))
        m = AXUM_ROUTE.search(ln)
        if m and (handler := named.get(m.group(3).split("::")[-1]) or module):
            out.append(Entry(handler["id"], m.group(2).upper(), m.group(1), "Axum", file, i, ""))
    return out


def _aspnet_entries(file, lines, text, module, fns) -> list[Entry]:
    out = []
    authed = {m.group(1) for m in ASPNET_GROUP.finditer(text) if "RequireAuthorization" in m.group(0)}
    class_auth = re.search(r"\[Authorize[\](]", text) and not re.search(r"\[AllowAnonymous\]", text)
    for i, ln in enumerate(lines, 1):  # minimal APIs: app.MapGet("/x", ...), group.MapPost(...)
        m = ASPNET_MAP.search(ln)
        if m and module:
            tail = " ".join(lines[i - 1 : i + 3])
            auth = "RequireAuthorization()" if (m.group(1) in authed or "RequireAuthorization" in tail) else ""
            out.append(Entry(module["id"], m.group(2).upper(), m.group(3), "ASP.NET", file, i, auth))
    for f in fns:  # controllers: [HttpGet("x")] on a method, [Authorize] on it or its class
        if f["kind"] == "module":
            continue
        head = "\n".join(lines[max(0, f["line"] - 6) : f["line"] + 1])
        m = ASPNET_ATTR.search(head)
        if m:
            auth = "[Authorize]" if ("[Authorize" in head or class_auth) and "[AllowAnonymous]" not in head else ""
            out.append(Entry(f["id"], m.group(1).upper(), m.group(2) or "", "ASP.NET", file, f["line"], auth))
    return out


def _phoenix_entries(file, lines, module, plugs: dict[str, str]) -> list[Entry]:
    """Routes from a Phoenix router. Auth: a `pipe_through` or `live_session` with an auth plug or hook, or a `plug`
    in the controller (or LiveView) the route points at."""
    out, piped, session = [], "", ""
    for i, ln in enumerate(lines, 1):
        if m := re.search(r"pipe_through\s+(.+)", ln):
            piped = m.group(1)
        elif re.match(r"\s*scope\b", ln):
            piped = ""
        if m := re.match(r"\s*live_session\s+(.+)", ln):
            session = m.group(1)
        elif session and re.match(r"\s*end\b", ln) and len(ln) - len(ln.lstrip()) <= 4:
            session = ""
        m = PHOENIX_ROUTE.match(ln)
        if m and module:
            target = (m.group(3) or "").split(".")[-1]
            auth = (
                (AUTH.search(piped) and f"pipe_through {piped.strip()}")
                or (AUTH.search(session) and f"live_session {session.strip()[:60]}")
                or (target in plugs and f"{target}: plug {plugs[target]}")
                or ""
            )
            verb = "ANY" if m.group(1) in ("live", "resources", "forward") else m.group(1).upper()
            out.append(Entry(module["id"], verb, m.group(2), "Phoenix", file, i, auth))
    return out


def find_entries(root: Path, g: dict, v: View) -> list[Entry]:
    cache: dict[str, list[str]] = {}
    by_file: dict[str, list[dict]] = {}
    for f in g["functions"]:
        by_file.setdefault(f["file"], []).append(f)
    entries: list[Entry] = []
    rust_guards: set[str] = set()  # request guards that check a token or session (`impl FromRequest for Headers`)
    for f in (f for f in by_file if f.endswith(".rs")):
        rust_text = "\n".join(_read(root, cache, f))
        rust_guards |= {m.group(1) for m in RUST_GUARD.finditer(rust_text) if AUTH.search(rust_text[m.end() : m.end() + 3000])}
    phoenix_plugs: dict[str, str] = {}  # controller or LiveView short name -> the auth plug / on_mount hook it uses
    for f in (f for f in by_file if f.endswith(".ex")):
        ex_text = "\n".join(_read(root, cache, f))
        mod = re.search(r"^\s*defmodule\s+([\w.]+)", ex_text, re.M)
        guard = next((m.group(1) for m in re.finditer(r"^\s*(?:plug|on_mount)\s+([\w.:]+)", ex_text, re.M)
                      if AUTH.search(m.group(1))), "")  # fmt: skip
        if mod and guard:
            phoenix_plugs[mod.group(1).split(".")[-1]] = guard
    by_name: dict[str, list[dict]] = {}  # Django URL handlers by name, and class-based views' methods by class
    by_class: dict[str, list[dict]] = {}
    for fn in g["functions"]:
        if fn["kind"] != "module":
            by_name.setdefault(fn["name"], []).append(fn)
        if fn["kind"] == "method":
            by_class.setdefault(fn["qualname"].split(".")[0], []).append(fn)
    rails = _RailsControllers(root, [f for f in by_file if f.endswith("_controller.rb") or "controllers/concerns/" in f], cache)
    aliases = {}  # FastAPI: CurrentUser = Annotated[User, Depends(get_current_user)]
    for file in by_file:
        if file.endswith(".py"):
            for m in ALIAS.finditer("\n".join(_read(root, cache, file))):
                aliases[m.group(1)] = m.group(2)
    for file, fns in by_file.items():
        if is_test(file):  # a test's `@mock.patch(...)` or a fake server isn't the product's surface
            continue
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
                here = file.rsplit("/", 1)[0] if "/" in file else ""
                for m in DJANGO_PATH.finditer(text):
                    dotted = m.group(2).split(".")
                    target, module = dotted[-1], (dotted[-2] if len(dotted) > 1 else "views")
                    # one handler per URL: the function (or class-based view) of that name, nearest the urls.py and
                    # in the module it names; not every function called `index` in the project
                    cands = by_name.get(target, []) or by_class.get(target, [])
                    if not cands:
                        continue
                    f = min(cands, key=lambda c: (not c["file"].startswith(here + "/") if here else False,
                                                  Path(c["file"]).stem != module, c["file"].count("/"), c["line"]))  # fmt: skip
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
                    auth = re.search(
                        r"getServerSession|getToken|auth\(\)|currentUser|requireAuth|clerk|withAuth|"
                        r"verify\w*(?:user|access|auth|session|token)\w*\(|"
                        r"constructEvent\(|verify\w*signature|webhooks?\.verify",  # a webhook checks its signature
                        body,
                        re.I,
                    )
                    path = "/" + re.sub(r"^.*?(?:pages/api|app)/|/?route\.[jt]sx?$|\.[jt]sx?$", "", file)
                    method = f["name"] if NEXT_METHOD.match(f["name"]) else "ANY"
                    entries.append(Entry(f["id"], method, path, "Next.js", file, f["line"], auth.group(0) if auth else ""))
        elif file.endswith((".java", ".kt")):
            for f in fns:
                if f["kind"] == "module":
                    continue
                # tree-sitter starts a Java/Kotlin method at its annotations: read them from the method's own lines
                head = "\n".join(lines[f["line"] - 1 : f["line"] + 8]).split("{")[0]
                deco = _above(lines, f["line"]) + "\n" + head
                m = SPRING.search(deco)
                if m:
                    auth = SPRING_AUTH.search(deco)
                    verb = "ANY" if m.group(1) == "Request" else m.group(1).upper()
                    entries.append(
                        Entry(f["id"], verb, m.group(2) or "", "Spring", file, f["line"], auth.group(0) if auth else "")
                    )
        elif file.endswith(".php"):
            entries += _php_entries(file, lines, text, module, fns)
        elif file.endswith(".rs"):
            entries += _rust_entries(file, lines, text, module, named, fns, rust_guards)
        elif file.endswith(".cs"):
            entries += _aspnet_entries(file, lines, text, module, fns)
        elif file.endswith(".ex") and file.endswith("router.ex"):
            entries += _phoenix_entries(file, lines, module, phoenix_plugs)
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
                guard, inherited = rails.guard(text)
                skipped = rails.skipped(text)
                for f in fns:
                    if f["kind"] == "method" and f["line"] < private_at:
                        action = f"{Path(file).stem.removesuffix('_controller')}#{f['name']}"
                        open_here = skipped is not None and (not skipped or f["name"] in skipped)
                        auth = "" if open_here else (f"before_action :{guard}" + (f" ({inherited})" if inherited else "")
                                                     if guard else "")  # fmt: skip
                        entries.append(Entry(f["id"], "ANY", action, "Rails", file, f["line"], auth))
    return entries


def exposure(root: Path, files: list[str]) -> tuple[str, str]:
    local = opened = ""
    for file in files:
        if is_test(file):  # a test's server on 0.0.0.0 says nothing about the product's
            continue
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
