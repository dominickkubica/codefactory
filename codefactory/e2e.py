"""Pages a browser end-to-end test opens (Playwright, Puppeteer, Cypress, WebdriverIO): loading a page by its URL runs
the page's code, and everything it renders, without a call the graph could link to the test. The visited URLs are
matched to file-based routes (Next.js, Nuxt, SvelteKit, TanStack Router, Remix) and to `<Route path=…>` /
`{path, component}` tables (react-router, Vue Router, Angular); a URL that maps to no page confidently marks nothing.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from pathlib import Path

from .paths import is_test

JS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte")
_LIT = r"""(?:"([^"\n]*)"|'([^'\n]*)'|`([^`]*)`)"""
# page.goto('/x'), cy.visit(`/p/${id}`), browser.url(base + '/#/x'), expect(page).toHaveURL(new RegExp(`…`)),
# expect(page.url()).toContain('/clients')
_VISIT = re.compile(r"(?:\.(?:goto|visit|navigate|navigateTo|url)\(|toHaveURL\(|url\(\)\)\.toContain\()\s*"
                    r"(?:new RegExp\(\s*)?(?:[\w.]+\s*\+\s*)?" + _LIT)  # fmt: skip
_SPA_PATH = re.compile(r"""\bpath\s*[:=]\s*\{?\s*["'`](/?[\w\-/:.]*)["'`]""")
_SPA_COMPONENT = re.compile(r"element\s*[:=]\s*\{?[^<]{0,80}<([A-Z]\w*)|[cC]omponent\s*[:=]\s*\{?\s*([A-Z]\w*)")


def visited(texts: list[str]) -> set[tuple[str, ...]]:
    """URL paths the tests open, as segments; `${…}` is any one segment ("*")."""
    out = set()
    for text in texts:
        for m in _VISIT.finditer(text):
            s = re.sub(r"\$\{[^}]*\}", "\0", next(g for g in m.groups() if g is not None)).replace("\\", "")
            s = re.sub(r"^(?:\w+:)?//[^/#]*|^\0", "", s)  # the host, or a `${baseURL}` standing for it
            s = s.split("#", 1)[1] if "#/" in s else s.split("#", 1)[0]  # a hash router's path is after the #
            if not s.startswith("/"):
                continue
            segs = tuple("*" if "\0" in p else p for p in s.split("?", 1)[0].split("/") if p)
            if segs:  # "/" alone: every page is under it
                out.add(segs)
    return out


def _seg(p: str, pathless_underscore: bool) -> str | None:
    """A route file's or folder's segment: "$" a parameter, "" no segment of the URL, None a catch-all."""
    if re.fullmatch(r"\[\[?\.\.\.\w*\]\]?|\$|\*\w*", p):
        return None  # catch-all: a not-found page as often as not
    if re.fullmatch(r"\[\w+\]|\$\w+|:\w+", p) or (p.startswith("_") and not pathless_underscore):
        return "$"
    if re.fullmatch(r"\(.*\)|@\w+|index|_index|route", p) or (p.startswith("_") and pathless_underscore):
        return ""
    return p.rstrip("_")  # Remix/TanStack `projects_`: the URL segment without its parent's layout


def route_of(path: str, project: Callable[[str], bool] = lambda d: True) -> tuple[tuple[str, ...], bool] | None:
    """A file-based route's URL segments, and whether it is a layout (renders for the URLs under it too). `project`
    says whether a folder is a JavaScript project's (has a package.json): `src/components/pages/` isn't a router's."""
    parts = path.split("/")
    stem, dot, ext = parts[-1].partition(".")
    if not dot or "." + ext.rsplit(".", 1)[-1] not in JS or any(p.startswith("-") for p in parts):
        return None

    def under(folder: str, parents: tuple[str, ...]) -> list[str] | None:
        if folder not in parts[:-1]:
            return None
        i = max(j for j, p in enumerate(parts[:-1]) if p == folder)
        top = parts[:i]
        if top and top[-1] in parents:
            top = top[:-1]
        return parts[i + 1 : -1] if project("/".join(top)) else None

    if stem in ("+page", "+layout") and (segs := under("routes", ("src",))) is not None:  # SvelteKit
        layout, pathless = stem == "+layout", True
    elif stem in ("page", "layout") and (segs := under("app", ("src",))) is not None:  # Next.js app router
        layout, pathless = stem == "layout", True
    elif not stem.startswith("_") and (segs := under("pages", ("src", "app"))) is not None:  # Next.js pages, Nuxt
        segs, layout, pathless = segs + [stem], False, False
        if segs[0] == "api":
            return None
    elif stem != "__root" and (segs := under("routes", ("src", "app"))) is not None:  # TanStack Router, Remix
        segs, layout, pathless = segs + [stem] + ext.split(".")[:-1], True, True
    else:
        return None
    out = [_seg(p, pathless) for p in segs]
    if None in out:
        return None
    route = tuple(p for p in out if p)
    return (route, layout) if route else None


def _score(route: tuple[str, ...], visit: tuple[str, ...], layout: bool) -> int | None:
    """How many literal segments match (more is more specific), or None when the route doesn't render for the URL."""
    if len(route) > len(visit) or (not layout and len(route) != len(visit)):
        return None
    score = 0
    for r, v in zip(route, visit, strict=False):
        if r == v and v != "*":
            score += 1
        elif r != "$" and v != "*":
            return None
    return score


def _best(routes: list[tuple[object, tuple[str, ...], bool]], visits) -> set:
    """For each URL, the routes that render it: the most specific at each depth (`mysql` over `$dbKind`)."""
    out = set()
    for visit in visits:
        by_depth: dict[int, list[tuple[int, object]]] = {}
        for key, route, layout in routes:
            if (s := _score(route, visit, layout)) is not None:
                by_depth.setdefault(len(route), []).append((s, key))
        for found in by_depth.values():
            top = max(s for s, _ in found)
            out |= {key for s, key in found if s == top}
    return out


def _spa_routes(texts: dict[str, str], fn: dict) -> list[tuple[object, tuple[str, ...], bool]]:
    """`<Route path="/clients" element={<Clients />}>`, `{path: '/clients', component: Clients}`: the component's
    functions, when its name is defined in one file only."""
    by_name: dict[str, set[str]] = {}
    for fid, f in fn.items():
        if not is_test(f["file"]):
            by_name.setdefault(f["qualname"].split(".", 1)[0], set()).add(fid)
    out = []
    for text in texts.values():
        angular = "@angular/router" in text
        found = list(_SPA_PATH.finditer(text))
        for i, m in enumerate(found):
            if not (m.group(1).startswith("/") or angular):
                continue  # a nested route's relative path: its parent isn't known here
            end = min(m.end() + 300, found[i + 1].start() if i + 1 < len(found) else len(text))
            c = _SPA_COMPONENT.search(text, m.end(), end)
            fids = by_name.get(c and (c.group(1) or c.group(2)) or "", set())
            route = tuple(_seg(p, False) for p in m.group(1).split("/") if p)
            if len({fn[x]["file"] for x in fids}) == 1 and route and None not in route:
                out.append((frozenset(fids), route, False))
    return out


def _extends(root: Path, rel: str, sub: str, base: str, cache: dict) -> bool:
    if rel not in cache:
        try:
            cache[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            cache[rel] = ""
    return re.search(rf"\bclass\s+{re.escape(sub)}\b[^{{]*\bextends\s+{re.escape(base)}\b", cache[rel]) is not None


def _reach(root: Path, g: dict, fn: dict, seeds: set[str]) -> set[str]:
    """What the pages run: everything they call or hand on, and a subclass's override of a base method that runs
    (`BaseStore.refresh` calls `this.requestItems()`: `ClientStore.requestItems`, when the page uses a ClientStore)."""
    edges: dict[str, list[str]] = {}
    for e in g["edges"]:
        if e["kind"] in ("call", "ref"):
            edges.setdefault(e["src"], []).append(e["dst"])
    methods: dict[str, list[str]] = {}
    for fid, f in fn.items():
        if f["kind"] == "method" and "." in f["qualname"] and not is_test(f["file"]):
            methods.setdefault(f["name"], []).append(fid)
    seen, q, texts = set(seeds), deque(seeds), {}
    while q:
        while q:
            for nxt in edges.get(q.popleft(), []):
                if nxt not in seen and nxt in fn:
                    seen.add(nxt)
                    q.append(nxt)
        used = {fn[x]["qualname"].split(".", 1)[0] for x in seen if fn[x]["kind"] == "method"}
        for fid in [x for x in seen if fn[x]["kind"] == "method" and "." in fn[x]["qualname"]]:
            base = fn[fid]["qualname"].split(".", 1)[0]
            for other in methods.get(fn[fid]["name"], ()):
                sub = fn[other]["qualname"].split(".", 1)[0]
                if other in seen or sub == base or sub not in used:
                    continue
                if _extends(root, fn[other]["file"], sub, base, texts):
                    seen.add(other)
                    q.append(other)
    return seen


_IMPORT = re.compile(r"""import\s+(?:type\s+)?(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s+["']([@~#]/[^"']+)["']""")


def _aliased(root: Path, rel: str, project: Callable[[str], bool], by_file: dict[str, set[str]], fn: dict) -> set[str]:
    """What a page imports through a path alias (`@/components/…`, `~/lib/…`): a monorepo app's own tsconfig paths
    can be ones the graph didn't resolve, which left the page linked to nothing it renders."""
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    parts = rel.split("/")[:-1]
    top = next(("/".join(parts[:i]) for i in range(len(parts), -1, -1) if project("/".join(parts[:i]))), None)
    out: set[str] = set()
    for default, named, spec in _IMPORT.findall(text) if top is not None else ():
        names = {default} | {n.split(" as ")[0].replace("type ", "").strip() for n in named.split(",")}
        base = spec.split("/", 1)[1]
        for cand in (f"{d}{base}{ext}" for d in ("src/", "") for ext in ("", *JS, *(f"/index{e}" for e in JS))):
            if (got := by_file.get(f"{top}/{cand}".lstrip("/"))) is not None:
                out |= {x for x in got if fn[x]["qualname"].split(".", 1)[0] in names}
                break
    return out


def pages_reached(root: Path, g: dict, fn: dict, test_texts: list[str]) -> set[str]:
    """Functions the pages e2e tests open run (with what they reach)."""
    visits = visited(test_texts)
    if not visits:
        return set()
    by_file: dict[str, set[str]] = {}
    for fid, f in fn.items():
        by_file.setdefault(f["file"], set()).add(fid)
    projects: dict[str, bool] = {}

    def project(folder: str) -> bool:
        if folder not in projects:
            projects[folder] = (root / folder / "package.json").is_file()
        return projects[folder]

    routes = [(frozenset(by_file[rel]), *r) for rel in by_file if not is_test(rel) and (r := route_of(rel, project))]
    texts = {}
    for rel in by_file:
        if rel.endswith(JS) and not is_test(rel):
            try:
                text = (root / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "path" in text and ("Route" in text or "component" in text.lower()):
                texts[rel] = text
    seeds = set().union(*_best(routes + _spa_routes(texts, fn), visits))
    for rel in {fn[x]["file"] for x in seeds}:
        seeds |= _aliased(root, rel, project, by_file, fn)
    return _reach(root, g, fn, seeds) if seeds else set()
