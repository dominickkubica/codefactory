"""Issue detectors. They read only the Graph, so they work the same for every language."""

from __future__ import annotations

import re
from collections import defaultdict

from .config import Config
from .efficiency import efficiency_flags
from .graph import Flag, Graph
from .paths import is_doc_sample, is_test, platform_variants
from .similar import near_duplicates

SEVERITY_ORDER = {"high": 0, "warn": 1, "info": 2}


# Methods a framework calls by name: React class components, web components, Angular, Django / DRF class-based views.
FRAMEWORK_METHODS = {
    "render",
    "componentDidMount",
    "componentDidUpdate",
    "componentWillUnmount",
    "shouldComponentUpdate",
    "getSnapshotBeforeUpdate",
    "componentDidCatch",
    "getDerivedStateFromError",
    "getDerivedStateFromProps",
    "UNSAFE_componentWillMount",
    "UNSAFE_componentWillReceiveProps",
    "UNSAFE_componentWillUpdate",
    "constructor",
    "connectedCallback",
    "disconnectedCallback",
    "attributeChangedCallback",
    "adoptedCallback",
    "ngOnInit",
    "ngOnDestroy",
    "ngOnChanges",
    "ngAfterViewInit",
    "ngAfterContentInit",
    "ngDoCheck",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "dispatch",
    "get_queryset",
    "get_object",
    "get_context_data",
    "get_serializer_class",
    "perform_create",
    "perform_update",
    "perform_destroy",
    "form_valid",
    "form_invalid",
    "clean",
    "save",
    "run",
    "handle",
}


# Functions a runner calls by name from outside the code: migrations (Alembic, Django), CLI and job entry points,
# serverless handlers, a Yeoman generator's run loop.
ENTRY_NAMES = {"main", "run", "upgrade", "downgrade", "handler", "lambda_handler", "create_app", "app", "setup",
               "teardown", "writing", "prompting", "initializing", "configuring", "install", "end", "default"}  # fmt: skip
# Template and component files the analyzers don't parse: a name used there is used (`:placeholder="draftComposed"`,
# a helper imported by a .vue file)
VIEW_FILES = (".vue", ".svelte", ".astro", ".html", ".htm", ".erb", ".haml", ".slim", ".blade.php", ".twig", ".hbs",
              ".njk", ".jinja", ".jinja2", ".j2", ".liquid", ".ejs", ".pug", ".mdx", ".xml", ".yml", ".yaml")  # fmt: skip
IMPORT_LIST = re.compile(r"\b(?:import|export)\s*(?:type\s*)?\{([^}]*)\}")
PROPERTY = re.compile(r"(?:this|self)\.([A-Za-z_$][\w$]{2,})\b(?!\s*\()")
QUOTED_NAME = re.compile(r"""['"`]([A-Za-z_$][\w$]{2,})['"`]""")
WORD = re.compile(r"[A-Za-z_$][\w$]{2,}")


def _mentioned(g: Graph) -> set[str]:
    """Names used where calls can't be followed: quoted in source (a method looked up by its name, a route handler
    named in config) or written in a template or component file."""
    import os
    from pathlib import Path

    root = Path(g.root)
    out: set[str] = set()
    for f in g.files:
        try:
            text = (root / f.id).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out.update(QUOTED_NAME.findall(text))
        # imported or re-exported by name (`import { useDeleteEscalation } from "@/lib/…"`: an alias or a route file
        # the analyzer couldn't resolve still names what it uses), or read as a property (a getter: `this.hash`)
        for m in IMPORT_LIST.finditer(text):
            out.update(WORD.findall(m.group(1)))
        out.update(PROPERTY.findall(text))
    skip = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "target", ".next"}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
        for name in filenames:
            if name.endswith(VIEW_FILES) and not name.startswith("codefactory") and seen < 20_000:
                seen += 1
                try:
                    if os.path.getsize(os.path.join(dirpath, name)) < 2_000_000:
                        with open(os.path.join(dirpath, name), encoding="utf-8", errors="replace") as fh:
                            out.update(WORD.findall(fh.read()))
                except OSError:
                    continue
    return out


def _rust_attributed(g: Graph, fn, cache: dict) -> bool:
    """A Rust function with an attribute above it (#[test], #[tokio::test], #[bench], #[wasm_bindgen], #[no_mangle]):
    a harness or the other side of a binding calls it."""
    from pathlib import Path

    if fn.file not in cache:
        try:
            cache[fn.file] = (Path(g.root) / fn.file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[fn.file] = []
    lines = cache[fn.file]
    above = [ln.strip() for ln in lines[max(0, fn.line - 4) : fn.line - 1]]
    return any(ln.startswith("#[") for ln in above)


def _is_entry(fn) -> bool:
    n = fn.name
    return (
        fn.kind == "module"
        or (fn.kind == "function" and n in ENTRY_NAMES)
        or fn.exported
        or fn.decorated
        or n.startswith("__")
        or n.startswith("test")
        or (fn.kind == "method" and n in FRAMEWORK_METHODS)
        or n in ("setUp", "tearDown", "setUpClass", "tearDownClass")
        or is_test(fn.file)
        or is_doc_sample(fn.file)  # a tutorial's handler is there to be read and copied, not called
    )


def dead_code(g: Graph) -> list[Flag]:
    file_of = {fn.id: fn.file for fn in g.functions}
    used = {e.dst for e in g.edges if e.kind in ("call", "ref")}
    used_by_code = {e.dst for e in g.edges if e.kind in ("call", "ref") and not is_test(file_of.get(e.src, ""))}
    imported = {e.dst for e in g.edges if e.kind == "import"}
    out = []
    mentioned: set[str] | None = None
    lines: dict = {}
    for fn in g.functions:
        # A file nothing imports is loaded by a framework, a runner or a user: its exports are entry points.
        if _is_entry(fn) or (fn.public and fn.file not in imported):
            continue
        if fn.id not in used and not fn.dynamic and fn.kind != "method":
            if mentioned is None:
                mentioned = _mentioned(g)
            if fn.name in mentioned or (fn.file.endswith(".rs") and _rust_attributed(g, fn, lines)):
                continue
        if fn.id in used:
            if fn.id not in used_by_code and not is_test(fn.file):
                out.append(Flag("test_only", "info", fn.id, f"{fn.qualname} is only called from tests"))
            continue
        if fn.dynamic:  # its name is used where the analyzer can't tell which definition runs: maybe this one
            continue
        private = re.match(r"_[a-z]", fn.name) is not None  # `_helper`: no one outside the class is meant to call it
        if fn.kind == "method" and not private:  # often called through an instance or a framework: only a hint
            out.append(
                Flag(
                    "unused",
                    "info",
                    fn.id,
                    f"{fn.qualname} has no callers found (it may be called through an instance or a framework)",
                )
            )
        else:
            out.append(Flag("unused", "warn", fn.id, f"{fn.qualname} is never called or referenced"))
    return out


TEST_COPY = " (all in tests: one table-driven or parametrized test, or a shared helper, would hold it once)"


def duplicates(g: Graph, cfg: Config) -> list[Flag]:
    from .paths import BUILD_OUTPUT, is_vendored

    groups = defaultdict(list)
    for fn in g.functions:
        # (not a build's output or a vendored library: phoenix's priv/static bundles copy its own sources, by design)
        if fn.shape and fn.loc >= cfg.duplicate_min_lines and not BUILD_OUTPUT.search(fn.file) and not is_vendored(fn.file):
            groups[fn.shape].append(fn)
    out = []
    for group in groups.values():
        # the same file for another platform (x_linux.go / x_darwin.go) copies on purpose: keep one of each set
        fns = [
            f
            for i, f in enumerate(group)
            if not any(platform_variants(f.file, o.file) or (f.file == o.file and f.name == o.name) for o in group[:i])
        ]  # (and overloads: one method per type, in one file)
        if len(fns) < 2:
            continue
        ids = [f.id for f in fns]
        # tests, and tutorials shown in several variants, repeat themselves on purpose: a lead, not a task
        in_tests = all(is_test(f.file) or is_doc_sample(f.file) for f in fns)
        for f in fns:
            others = [o for o in fns if o is not f]
            names = ", ".join(f"{o.qualname} ({o.file})" for o in others[:3]) + (" …" if len(others) > 3 else "")
            message = f"Same code as {names}" + (TEST_COPY if in_tests else "")
            out.append(Flag("duplicate", "info" if in_tests else "warn", f.id, message, [i for i in ids if i != f.id]))
    return out


ENTRY_FILES = {"__init__.py", "index.ts", "index.tsx", "index.js", "index.mjs", "index.jsx"}
NOT_PRODUCT = re.compile(r"(?:^|/)(?:database/factories|database/seeders|factories|seeds?|seeders)/")


def _cs_projects(g: Graph):
    """For C#: whether one file can depend on another. A file belongs to the nearest .csproj above it, and a project
    sees only itself and the projects it references (transitively): `using` resolved by namespace can't point from
    MediaBrowser.Controller into Emby.Server.Implementations when the project file has no such reference."""
    import os
    from pathlib import Path

    root = Path(g.root)
    projects: dict[str, set[str]] = {}  # project dir (relative) -> referenced project dirs
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("bin", "obj", "node_modules")]
        for name in filenames:
            if name.endswith(".csproj"):
                here = Path(dirpath)
                try:
                    text = (here / name).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                refs = set()
                for ref in re.findall(r'ProjectReference\s+Include="([^"]+)"', text):
                    target = os.path.normpath(here / ref.replace("\\", "/")).rsplit(os.sep, 1)[0]
                    refs.add(os.path.relpath(target, root).replace(os.sep, "/"))
                projects[os.path.relpath(here, root).replace(os.sep, "/")] = refs
    if not projects:
        return lambda a, b: True

    def project_of(path: str) -> str | None:
        parts = path.split("/")[:-1]
        while parts:
            if "/".join(parts) in projects:
                return "/".join(parts)
            parts.pop()
        return "." if "." in projects else None

    reach: dict[str, set[str]] = {}

    def sees(p: str) -> set[str]:
        if p not in reach:
            reach[p] = {p}
            for r in projects.get(p, ()):
                reach[p] |= sees(r)
        return reach[p]

    def allowed(a: str, b: str) -> bool:
        pa, pb = project_of(a), project_of(b)
        return pa is None or pb is None or pb in sees(pa)

    return allowed


def import_cycles(g: Graph) -> list[Flag]:
    """Strongly connected groups of files in the import graph (Tarjan)."""
    adj = defaultdict(set)
    for e in g.edges:
        # a Rust crate compiles as one unit, so its modules may use each other; tests and factories (fixtures for
        # tests and seeding, like Laravel's model <-> factory pairs) aren't part of the product's structure
        # (nor samples and playgrounds: vite's playground/ keeps circular imports on purpose, to test them)
        if e.kind == "import" and not any(
            x.endswith(".rs") or is_test(x) or is_doc_sample(x) or NOT_PRODUCT.search(x) for x in (e.src, e.dst)
        ):
            adj[e.src].add(e.dst)
    if any(k.endswith(".cs") for k in adj):
        allowed = _cs_projects(g)
        for src in list(adj):
            if src.endswith(".cs"):
                adj[src] = {d for d in adj[src] if allowed(src, d)}
    index, low, stack, on, comps, counter = {}, {}, [], set(), [], [0]

    def visit(v: str) -> None:
        work = [(v, iter(sorted(adj[v])))]
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        while work:
            node, it = work[-1]
            nxt = next(it, None)
            if nxt is None:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp.append(w)
                        if w == node:
                            break
                    if len(comp) > 1:
                        comps.append(sorted(comp))
            elif nxt not in index:
                index[nxt] = low[nxt] = counter[0]
                counter[0] += 1
                stack.append(nxt)
                on.add(nxt)
                work.append((nxt, iter(sorted(adj[nxt]))))
            elif nxt in on:
                low[node] = min(low[node], index[nxt])

    for v in sorted({f.id for f in g.files}):
        if v not in index:
            visit(v)
    out = []
    for comp in comps:
        path = _shortest_loop(comp, adj)  # a real chain of imports, not the group's members in name order
        loop = " → ".join(c.split("/")[-1] for c in path)
        more = f" ({len(comp)} files in the loop)" if len(comp) > len(path) - 1 else ""
        # Python and JavaScript run a module's code as it's imported, so a loop can break loading: high. Classes in
        # Java, Kotlin, C#, Swift… load lazily, so a loop works at runtime and is a design smell (they can't be
        # understood, tested or reused apart): warn.
        lazy = all(c.endswith(LAZY_LOADING) for c in comp)
        # through a package's entry file (`__init__.py`, `index.ts` re-exporting its submodules): the usual layout of
        # mature libraries (FastAPI, Django, Vue), which loads as long as the entry file orders its imports; a debt to
        # untangle, not a loading failure waiting to happen
        entry = any(c.rsplit("/", 1)[-1] in ENTRY_FILES for c in comp)
        sev, what = ("warn", "Dependency loop") if lazy else ("warn", "Import loop") if entry else ("high", "Import loop")
        for f in comp:
            out.append(Flag("cycle", sev, f, f"{what}: {loop}{more}", [c for c in comp if c != f],
                            detail=" → ".join(path)))  # fmt: skip
    return out


def _shortest_loop(comp: list[str], adj: dict) -> list[str]:
    """The shortest import chain from the group's first file back to itself (breadth-first, inside the group)."""
    inside, start = set(comp), comp[0]
    prev: dict[str, str] = {}
    frontier, seen = [start], {start}
    while frontier:
        nxt = []
        for v in frontier:
            for w in sorted(adj[v]):
                if w == start:
                    chain = [v]
                    while chain[-1] != start:
                        chain.append(prev[chain[-1]])
                    return [*reversed(chain), start]
                if w in inside and w not in seen:
                    seen.add(w)
                    prev[w] = v
                    nxt.append(w)
        frontier = nxt
    return [*comp, comp[0]]


LAZY_LOADING = (".java", ".kt", ".kts", ".scala", ".sc", ".groovy", ".cs", ".swift", ".dart", ".fs", ".m", ".mm")


def size_flags(g: Graph, cfg: Config) -> list[Flag]:
    out = []
    for f in g.files:
        if f.loc > cfg.large_file:
            out.append(Flag("large_file", "info", f.id, f"{f.loc} lines (over {cfg.large_file})"))
    for fn in g.functions:
        if fn.kind != "module" and fn.loc > cfg.long_function:
            out.append(Flag("long_function", "info", fn.id, f"{fn.qualname} is {fn.loc} lines (over {cfg.long_function})"))
    return out


def hubs(g: Graph, cfg: Config) -> list[Flag]:
    """Functions called from many different files: a change there ripples everywhere."""
    file_of = {fn.id: fn.file for fn in g.functions}
    callers = defaultdict(set)
    for e in g.edges:
        if e.kind == "call" and file_of.get(e.src) != file_of.get(e.dst):
            callers[e.dst].add(file_of.get(e.src))
    by_id = {fn.id: fn for fn in g.functions}
    return [
        Flag("hub", "info", fid, f"{by_id[fid].qualname} is called from {len(files)} files")
        for fid, files in callers.items()
        if len(files) >= cfg.hub_callers and fid in by_id
    ]


def layer_violations(g: Graph, cfg: Config) -> list[Flag]:
    if not cfg.forbid:
        return []
    layer_of = {f.id: f.layer for f in g.files}
    forbidden = set(cfg.forbid)
    out = []
    for e in g.edges:
        if e.kind != "import":
            continue
        pair = (layer_of.get(e.src), layer_of.get(e.dst))
        if pair in forbidden:
            out.append(
                Flag(
                    "layer_violation",
                    "high",
                    e.src,
                    f"{e.src} ({pair[0]}) imports {e.dst} ({pair[1]}), which factory.toml forbids",
                    [e.dst],
                )
            )
    return out


def run_flags(g: Graph, cfg: Config) -> None:
    g.flags = [
        *import_cycles(g),
        *layer_violations(g, cfg),
        *duplicates(g, cfg),
        *near_duplicates(g, cfg),
        *efficiency_flags(g),
        *dead_code(g),
        *hubs(g, cfg),
        *size_flags(g, cfg),
    ]
    by_id = {fn.id: fn for fn in g.functions}
    for f in g.flags:  # every issue points at a line, for editors and for Claude Code
        if not f.line and f.target in by_id:
            f.line = by_id[f.target].line
    g.flags.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.kind, f.target))
    for fn in g.functions:  # only needed for the checks above; keeps the saved graph and the HTML small
        fn.tokens = ""
