"""Every other language, through tree-sitter (optional: `pip install "codefactory[languages]"`).

Go, Java, Kotlin, Swift, Rust, C, C++, C#, Ruby, PHP, Scala, Dart, Lua, Elixir and more get the map, copied code,
calls and I/O in loops, sizes and unused-code hints. Calls are matched by name, not by type: a call links to a
definition in the same file, then the same folder, then a file it imports, then the only definition of that name
anywhere. A name defined in several places that none of those settle links to each as a "ref" (so none of them
looks unused) but not as a call. That is less exact than the Python and TypeScript analyzers, and says so.

Grammars download on first use per language and are cached (tree-sitter-language-pack); after that it works offline.
"""

from __future__ import annotations

import functools
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from ..graph import Edge, File, Function, Graph, Site
from ..paths import link_copies, links_outside
from . import parallel

# extension -> tree-sitter language. Python and TypeScript/JavaScript have their own analyzers.
LANGS = {
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".scala": "scala",
    ".sc": "scala",
    ".dart": "dart",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".zig": "zig",
    ".pl": "perl",
    ".pm": "perl",
    ".r": "r",
    ".R": "r",
    ".jl": "julia",
    ".m": "objc",
    ".mm": "objc",
    ".fs": "fsharp",
    ".groovy": "groovy",
    ".clj": "clojure",
    ".erl": "erlang",
    ".sol": "solidity",
    ".f90": "fortran",
    ".gleam": "gleam",
    ".nim": "nim",
    ".cr": "crystal",
    ".vb": "vb",
    ".sh": "bash",
    ".bash": "bash",
}
JS_LANGS = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}
# I/O by the receiver's or callee's name: a database, the network, files. Matched on calls nothing in the codebase
# defines, so the codebase's own functions are followed instead.
IO_RECEIVER = re.compile(
    r"(?:^|[.:>])(?:db|database|conn|connection|cursor|session|repo|repository|dao|client|httpClient|api|"
    r"redis|em|entityManager|jdbc|mongo|stmt|statement|pool|tx|s3|bucket|requests|"
    r"_db|_repo|_client|_http|\$db|\$pdo|pdo|DB|HttpClient)\s*(?:\.|->|::)\s*\w+$",
    re.I,
)
# `http.` / `https.` is a package or module: only its request functions talk to the network (Go's http.SetCookie,
# http.HandleFunc, http.Error and http.NewRequest don't)
HTTP_PACKAGE = re.compile(r"(?:^|[.:>])(?:http|https|Http)\s*(?:\.|->|::)\s*(?:get|post|put|patch|delete|head|"
                          r"request|do|send|fetch|postform|urlopen)\w*$", re.I)  # fmt: skip
# migrations step through their changes one at a time on purpose (each its own statement, in order)
MIGRATION = re.compile(r"(?i)migrat|schema_?lock|upgrade_?schema")
# startup code runs once, over what's configured (a loop per server, per registry): not a loop over data
STARTUP = re.compile(r"(?:^|::|\.)(?:main|init|boot\w*|setup\w*|Setup\w*|New\w*|new_\w*|Register\w*|register\w*|"
                     r"Start\w*|start\w*|Init\w*|Configure\w*|configure\w*|Bootstrap\w*|Must\w*|Load\w*Config\w*)$")  # fmt: skip
IO_NAME = re.compile(
    r"(?:^|[.:>])(?:query|execute|executeQuery|executeUpdate|exec_query|rawQuery|QueryRow|QueryContext|ExecContext|"
    r"Exec|urlopen|fetch|findById|findOne|findAll|find_by|"
    r"Get|Post|Do|send|request|download|upload|read_to_string|readFile|writeFile|File\.(?:read|write|open)\w*|"
    r"fopen|fread|fwrite|curl_exec|file_get_contents|sqlite3_exec|PQexec)$"
)
# ORM verbs (Active Record, Eloquent): in Ruby and PHP `x.save` / `->update()` is a database call; in Rust, Go, Java,
# Kotlin or C# `map.insert(k, v)`, `set.update()` or `list.select()` is a collection
# methods any value has, on a receiver whose name sounds like I/O (`conn.Close()`, `client.String()`, `tx.Lock()`): not
# a query or a request each time a loop calls them
NOT_IO_METHOD = re.compile(
    r"(?:\.|->|::)(?:close|Close|shutdown|Shutdown|String|Error|Lock|Unlock|RLock|RUnlock|Len|len|clone|Clone|push|"
    r"append|add|keys|values|items|map|filter|iter|is_\w+|Is\w+|has_\w+|Has\w+|set_?\w*[Tt]imeout|Set\w*Deadline|"
    r"Context|Name|ID|Id|Key|Type|Copy|Reset|Wait|Done|Err|Cancel|Release|release|dispose|Dispose|toString|equals|"
    r"hashCode|getClass|log\w*|Log\w*|debug|info|warn|error)$"
)
# receivers whose methods share I/O names but aren't I/O: Go's sync.Once (`once.Do(f)`), an exception's factory
# (`Error::query(…)`), Symfony's Finder, a statement or query *builder*, a getter for the engine (`db.GetEngine()`)
NOT_IO_RECEIVER = re.compile(
    r"(?:^|[.:>])\w*[oO]nce\s*\.\s*Do$|(?:^|[^\w$])(?:\w*Error|\w*Exception|Finder|Statement|\w*Builder)\s*::\s*\w+$|"
    r"(?:\.|->)GetEngine$|(?:\.|->)getEngine$|"
    # a constant table or pattern, or a hash's keys: `POLICY_FLAGS.keys.select { … }`, `PEM_REGEX.findAll(text)`
    r"(?:^|[^\w$])[A-Z][A-Z0-9]*_?(?:REGEX|RE|PATTERN|FLAGS|MAP|TABLE|LIST|KEYS|NAMES|TYPES|SET)\s*(?:\.|::)|"
    r"\.(?:keys|values|entries|items|to_a|to_h)(?:\(\))?\s*\.\s*\w+$"
)
ORM_NAME = re.compile(r"(?:^|[.:>])(?:where|save!?|create!?|update!?|destroy|insert|select|delete!?)$")
ORM_LANGS = (".rb", ".php")
# a receiver declared as a repository, DAO, entity manager or database context: `owners.save(o)` where
# `OwnerRepository owners` (Spring Data), `dao.insert(x)` (Room), `context.save()` (Core Data)
IO_TYPE = re.compile(r"(?:Repository|Repo|Dao|DAO|Mapper|EntityManager|JdbcTemplate|DbContext|ManagedObjectContext|"
                     r"ModelContext|Realm|SQLiteDatabase|Connection|DataSource|Session|Client)$")  # fmt: skip
IO_VERB = re.compile(r"(?:^|[.:>])(?:find\w*|get\w*|save\w*|delete\w*|remove\w*|insert\w*|update\w*|upsert\w*|"
                     r"query\w*|exists\w*|count\w*|fetch\w*|execute\w*|persist|merge|flush|commit)$")  # fmt: skip


# Core Data, SwiftData and Realm: saving or fetching through a context is disk I/O
SWIFT_STORE = re.compile(r"(?:^|\.)(?:context|viewContext|managedObjectContext|backgroundContext|moc|modelContext|realm)\."
                         r"(?:save|fetch\w*|delete|insert|perform\w*|count|write|objects|add)$")  # fmt: skip


def _typed_io(callee: str, types: dict[str, str]) -> bool:
    parts = [p for p in re.split(r"\.|->|::|\?\.", callee) if p]
    if len(parts) < 2:
        return False
    receiver = parts[-2].lstrip("$_")
    typ = types.get(receiver) or types.get("_" + receiver) or ""
    return bool(IO_TYPE.search(typ))


# Ruby on Rails: ActiveRecord class methods load from the database (`Report.find(id)` in a loop is the N+1)
AR = re.compile(r"(?:^|[^\w.])[A-Z]\w*(?:::[A-Z]\w*)*\.(?:find|find_by\w*|where|first|last|count|pluck|exists\?)$")

ENTRY_NAMES = {"main", "Main", "init", "setup", "teardown", "initialize", "new", "default", "drop", "fmt", "deinit"}
GENERATED = re.compile(rb"Code generated .* DO NOT EDIT|@generated|<auto-generated|autogenerated by|DO NOT EDIT")


def available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_language_pack  # noqa: F401
    except ImportError:
        return False
    return True


def find_files(root: Path, ignore: list[str], include_js: bool) -> list[tuple[str, str]]:
    skip = set(ignore)
    exts = {**LANGS, **(JS_LANGS if include_js else {})}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.startswith(".") and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1]
            lang = exts.get(ext) or exts.get(ext.lower())
            rel = Path(dirpath, name).relative_to(root).as_posix()
            if lang and not name.endswith((".d.ts", ".min.js")) and not links_outside(root, rel):
                out.append((rel, lang))
    copies = link_copies(root, [rel for rel, _ in out])
    return [f for f in out if f[0] not in copies]


_PARSERS: dict = {}


def parse_file(path: str, rel: str, lang: str) -> dict | None:
    """The per-file step (runs in a worker)."""
    from tree_sitter_language_pack import get_parser

    from .treewalk import MAX_BYTES, walk

    try:
        source = Path(path).read_bytes()
    except OSError:
        return None
    if len(source) > MAX_BYTES or b"\0" in source[:4096]:
        return None  # data or binary
    try:
        parser = _PARSERS.get(lang) or _PARSERS.setdefault(lang, get_parser(lang))
        data = walk(source, parser, rel)
    except Exception:  # an unknown grammar, a download that failed offline, a crash in one file: skip that file
        return None
    data["lang"] = lang
    if GENERATED.search(source[:2000]):
        # generated code: nobody edits it, so its copies and dead ends aren't findings, but what it calls is used
        for f in data["functions"]:
            data["top"]["calls"] += f["calls"]
            data["top"]["refs"] = sorted({*data["top"]["refs"], *f["refs"]})
        data["functions"] = []
    return data


def _import_index(rels: list[str]) -> dict[str, list[str]]:
    """Path suffixes without extension (and folders) -> files, to match what an import names."""
    idx: dict[str, list[str]] = defaultdict(list)
    for rel in rels:
        parts = rel.rsplit(".", 1)[0].split("/")
        for i in range(len(parts)):
            idx["/".join(parts[i:])].append(rel)
        for i in range(len(parts) - 1):  # the folder: Go packages, Java packages
            idx["/".join(parts[i:-1]) + "/"].append(rel)
    return idx


def _go_modules(root: Path) -> list[tuple[str, str]]:
    """(module path, its folder) for each go.mod: a Go import is the repository's own only under one of them."""
    from ..paths import walk

    out = []
    for rel in walk(root, names=("go.mod",)):
        try:
            m = re.search(r"^module\s+(\S+)", (root / rel).read_text(encoding="utf-8", errors="replace"), re.M)
        except OSError:
            continue
        if m:
            out.append((m.group(1).strip('"'), rel.rsplit("/", 1)[0] if "/" in rel else ""))
    return sorted(out, key=lambda x: -len(x[0]))  # the longest (most specific) module first


def _go_package(source: str, idx: dict[str, list[str]], mods: list[tuple[str, str]]) -> list[str]:
    """A Go import, by its full path: `example.com/app/internal/sync` is the folder internal/sync; `sync`, or anything
    outside the module, is the standard library or a dependency, whatever folders the repository happens to have."""
    source = source.strip().strip('"`')
    for mod, folder in mods:
        if source == mod or source.startswith(mod + "/"):
            key = "/".join(p for p in (folder, source[len(mod) :].strip("/")) if p)
            files = [f for f in idx.get(key + "/", []) if not _is_test(f) and f.rsplit("/", 1)[0] == key]
            return sorted(files, key=lambda f: (Path(f).stem != key.rsplit("/", 1)[-1], f))[:1]
    return []


def _resolve_import(source: str, idx: dict[str, list[str]], lang: str, go_mods: list | None = None) -> list[str]:
    """The file(s) an import names: the longest path suffix that is a file (C's "net/socket.h", Java's a.b.Orders),
    else a package folder, linked through one file (its namesake if there is one). Go imports always name packages
    (by their full path, when there's a go.mod). Among several equal matches the shallowest folder wins; more than
    three equal files is too ambiguous to link."""
    if lang == "go" and go_mods:
        return _go_package(source, idx, go_mods)
    s = re.sub(r"\.(?:h|hpp|hh|rb|php|lua|dart|go|rs|java|kt|swift|cs|ex|js|ts)$", "", source.strip())
    parts = [p for p in re.split(r"[./\\:]+", s) if p and p not in ("crate", "self", "super", "~", "@", "..")]
    if lang == "ruby" and len(parts) == 1 and not source.startswith("."):
        # `require "prometheus_exporter"`: a gem, or a file on the load path (lib/), not any file of that name
        return [f for f in idx.get(parts[0], []) if f.startswith("lib/") or "/lib/" in f][:1]
    loose = lang in ("c", "cpp")  # an include names a header among the search paths: a few candidates are normal
    # the path as written, then without its last part: `import a.b.fn` (Kotlin, Java static) names something inside a.b
    for named in (parts, parts[:-1]):
        for i in range(len(named)):
            key = "/".join(named[i:])
            # (`Utopia\DNS\Validator\DNS` isn't every file called DNS: a qualified name needs its folder too)
            last = len(named) > 1 and i == len(named) - 1 and not loose
            if lang != "go" and not last and key in idx:
                if len(idx[key]) == 1 or (loose and len(idx[key]) <= 3):
                    return idx[key]
                break  # several files end the same way: don't guess which one
            # (not PHP: `use Predis\Command\Redis\FLUSHDB` names a class, and a `Redis/` folder here isn't it; nor, for a
            # dotted package name, by its last part alone: `org.junit.jupiter.api.Tag` isn't whatever this repository
            # keeps in an `api/` folder. A Go import's last part is its folder's name: `example.com/shop/store` is store/)
            dotted = lang in ("java", "kotlin", "scala", "csharp")
            if key + "/" in idx and lang != "php" and not (last and dotted):  # a package: its folder stands for its files
                files = [f for f in idx[key + "/"] if not _is_test(f)]
                if not files:
                    continue
                top = min(f.count("/") for f in files)  # the shallowest folder with that name
                files = [f for f in files if f.count("/") == top]
                return sorted(files, key=lambda f: (Path(f).stem != named[-1], f))[:1]
    return []


def _is_test(rel: str) -> bool:
    from ..paths import is_test

    return is_test(rel)


def analyze_generic(root: Path, ignore: list[str], include_js: bool = False, cache: bool = True) -> Graph:
    g = Graph(root=str(root), language="")
    found = find_files(root, ignore, include_js)
    if not found:
        return g
    if not available():
        langs = sorted({lang for _, lang in found})
        print(
            f"codefactory: {len(found)} files in {', '.join(langs[:6])}{' …' if len(langs) > 6 else ''} aren't analyzed. "
            'Install the language pack to include them: pip install "codefactory[languages]"',
            file=sys.stderr,
        )
        return g
    # load each grammar here, once, before the workers: a grammar that can't load (offline on first use, a failed
    # download) would otherwise drop every file of that language one by one, quietly, and cache them as unparseable
    missing = _unloadable({lang for _, lang in found})
    if missing:
        lost = [rel for rel, lang in found if lang in missing]
        print(f"codefactory: {len(lost)} files in {', '.join(sorted(missing))} aren't analyzed: the tree-sitter "
              f"grammar couldn't be loaded ({next(iter(missing.values()))}). Grammars download on first use, so "
              "run once online.", file=sys.stderr)  # fmt: skip
        from . import INCOMPLETE

        INCOMPLETE.extend(sorted(missing))  # not cached: the next run tries again
        found = [(rel, lang) for rel, lang in found if lang not in missing]
    items = [(rel, (str(root / rel), rel, lang)) for rel, lang in found]
    parsed = parallel.run(root, "generic", items, parse_file, tool="treewalk-6", cache=cache)
    if dropped := [rel for rel, _ in found if rel not in parsed]:  # (the review's limits count them too)
        print(f"codefactory: {len(dropped)} files aren't analyzed: over 1 MB, binary or not parseable "
              f"({', '.join(dropped[:3])}{' …' if len(dropped) > 3 else ''}).", file=sys.stderr)  # fmt: skip
    return link(g, parsed, rails_associations(root, [rel for rel, _ in found if rel.endswith(".rb")]))


def _unloadable(langs: set[str]) -> dict[str, str]:
    """Languages whose grammar can't be loaded -> why (and the rest download now, not in several workers at once)."""
    from tree_sitter_language_pack import get_parser

    out = {}
    for lang in sorted(langs):
        try:
            _PARSERS[lang] = _PARSERS.get(lang) or get_parser(lang)
        except Exception as e:  # DownloadError, LanguageNotFoundError, a broken cache…
            out[lang] = f"{type(e).__name__}: {str(e)[:120]}"
    return out


def rails_associations(root: Path, files: list[str]) -> re.Pattern | None:
    """`user.posts.count` loads from the database when the models say `has_many :posts`: a call through an
    association, matched on the names the models declare (so an array attribute called `items` doesn't count)."""
    names: set[str] = set()
    for rel in files:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names |= set(re.findall(r"^\s*(?:has_many|has_and_belongs_to_many)\s+:(\w+)", text, re.M))
    if not names:
        return None
    alt = "|".join(sorted(map(re.escape, names)))
    return re.compile(rf"(?:^|[^\w.])[a-z_]\w*\.(?:{alt})\.(?:count|where|find_by\w*|find|pluck|sum|exists\?|first|last)$")


@functools.cache
def _qualname(fid: str) -> str:
    """A function id's qualified name without an overload's line (asked for the same candidates again and again)."""
    return re.sub(r"@\d+$", "", fid.split("::", 1)[-1])


def _typed(callee: str, src: str, types: dict[str, str], cands: list[str]) -> str | None:
    """`repo.find` with `repo: Repo` declared → Repo.find; `self.find` / `this.find` → a method of the caller's class.
    Only when exactly one candidate fits."""
    parts = [p for p in re.split(r"\.|->|::|\?\.", callee) if p]
    if len(parts) < 2:
        return None
    receiver = parts[-2].lstrip("$_") if parts[-2] not in ("self", "this", "$this") else None
    if receiver is None:  # a method of the caller's own class
        cls = src.split("::", 1)[-1].rsplit(".", 1)[0] if "." in src.split("::", 1)[-1] else ""
        want = f"{cls}.{parts[-1]}" if cls else None
    else:
        typ = types.get(receiver) or types.get("_" + receiver) or (receiver if receiver[:1].isupper() else None)
        want = f"{typ}.{parts[-1]}" if typ else None
    if not want:
        return None
    # (overloads carry their line in the id: `Validate.isTrue@312`; several overloads fitting is still ambiguous)
    qual = [_qualname(c) for c in cands]
    fits = [c for c, q in zip(cands, qual, strict=True) if q == want or q.endswith("." + want)]
    return fits[0] if len(fits) == 1 else None


def link(g: Graph, parsed: dict[str, dict], associations: re.Pattern | None = None) -> Graph:
    """Turns per-file results into the graph: functions, import edges, name-matched calls, loop sites."""
    langs = Counter(d["lang"] for d in parsed.values())
    g.language = "+".join(sorted(langs))
    idx = _import_index(list(parsed))
    go_mods = _go_modules(Path(g.root)) if g.root and any(d["lang"] == "go" for d in parsed.values()) else []
    defs: dict[str, list[str]] = defaultdict(list)  # name -> function ids
    file_of: dict[str, str] = {}
    kind_of: dict[str, str] = {}
    imported: dict[str, set[str]] = {}
    resolved: dict[tuple[str, str], list[str]] = {}  # (import, language) -> files: the same import recurs in many files

    def files_of(src: str, lang: str) -> list[str]:
        if (src, lang) not in resolved:
            resolved[(src, lang)] = _resolve_import(src, idx, lang, go_mods)
        return resolved[(src, lang)]

    for rel, d in sorted(parsed.items()):
        g.files.append(File(id=rel, module=rel.rsplit(".", 1)[0].replace("/", "."), loc=d["loc"]))
        imported[rel] = {dst for src in d["imports"] for dst in files_of(src, d["lang"]) if dst != rel}
        g.edges += [Edge(rel, dst, "import") for dst in sorted(imported[rel])]
        top = Function(id=f"{rel}::<module>", file=rel, name="<module>", qualname="<module>", line=1, end=1, loc=0, kind="module")
        g.functions.append(top)
        seen: set[str] = set()
        for f in d["functions"]:
            fid = f"{rel}::{f['qualname']}"
            if fid in seen:
                fid = f"{fid}@{f['line']}"
            seen.add(fid)
            f["id"] = fid
            g.functions.append(
                Function(
                    id=fid,
                    file=rel,
                    name=f["name"],
                    qualname=f["qualname"],
                    line=f["line"],
                    end=f["end"],
                    loc=f["end"] - f["line"] + 1,
                    kind=f["kind"],
                    public=f["public"],
                    # exported API (and what a runtime calls by name) isn't dead code: name matching can't tell
                    exported=f["public"] or f["name"] in ENTRY_NAMES,
                    shape=f["shape"],
                    tokens=f["tokens"],
                    doc=f.get("doc", 0),
                    branches=f.get("branches", 0),
                )
            )
            defs[f["name"]].append(fid)
            file_of[fid] = rel
            kind_of[fid] = f["kind"]
    by_id = {f.id: f for f in g.functions}
    calls: Counter = Counter()
    refs: Counter = Counter()
    ambiguous: set[str] = set()
    for rel, d in parsed.items():
        here = rel.rsplit("/", 1)[0] if "/" in rel else ""
        owners = [(f"{rel}::<module>", d["top"])] + [(f["id"], f) for f in d["functions"]]

        types = d.get("types", {})

        def resolve(
            name: str, src: str, bare: bool = False, callee: str = "", rel: str = rel, here: str = here, types: dict = types
        ) -> tuple[str | None, list[str]]:
            cands = [c for c in defs.get(name, ()) if c != src]
            typed = _typed(callee, src, types, cands)
            if typed:
                return typed, cands
            same = [c for c in cands if file_of[c] == rel]
            if len(same) == 1:
                return same[0], cands
            if bare and not same:  # f(x) with no receiver: a plain function, unless only methods have that name
                cands = [c for c in cands if kind_of[c] != "method"] or cands
            # the only definition anywhere, for a method called on a value of unknown type, only when the name is
            # distinctive: `n.Int64()`, `scope.preload()` are the standard library's or a framework's far more often
            # than the one project function that happens to share the name
            receiver_call = bool(re.search(r"\.|->|::", callee)) and not re.match(r"(?:self|this|@)\b", callee)
            only = cands if len(cands) == 1 and (not receiver_call or len(name) >= 8) else []
            for pick in (
                same,
                [c for c in cands if file_of[c].rsplit("/", 1)[0] == here and "/" in file_of[c]] if here else [],
                [c for c in cands if file_of[c] in imported[rel]],
                only,
            ):
                if len(pick) == 1:
                    return pick[0], cands
                if pick:
                    break  # several equally likely: don't guess
            return None, cands

        for src, rec in owners:
            io: set[str] = set()
            for name in rec.get("refs", ()):
                if name in defs:
                    target, cands = resolve(name, src)
                    for c in [target] if target else cands if len(cands) <= 3 else ():
                        refs[(src, c)] += 1
            startup = bool(STARTUP.search(src) or MIGRATION.search(src))
            for name, line, in_loop, callee, *rest in rec["calls"]:
                route = bool(rest and rest[0])
                target, cands = resolve(name, src, bare=not re.search(r"\.|->|::", callee), callee=callee)
                if target:
                    calls[(src, target)] += 1
                    if in_loop:
                        g.sites.append(Site(src, "loop_call", line, target=target, bounded=startup))
                    continue
                if len(cands) <= 3:
                    for c in cands:
                        refs[(src, c)] += 1
                else:  # called by a name many things define (String, Error, Read): any of them may be what runs
                    ambiguous.add(name)
                if (
                    not cands
                    and not route
                    and not NOT_IO_METHOD.search(callee)
                    and not NOT_IO_RECEIVER.search(callee)
                    and (
                        IO_RECEIVER.search(callee)
                        or HTTP_PACKAGE.search(callee)
                        or IO_NAME.search(callee)
                        or (src.split("::")[0].endswith(ORM_LANGS) and ORM_NAME.search(callee))
                        or (src.split("::")[0].endswith(".swift") and SWIFT_STORE.search(callee))
                        or (_typed_io(callee, types) and (ORM_NAME.search(callee) or IO_VERB.search(callee)))
                        or (src.split("::")[0].endswith(".rb") and AR.search(callee))
                        or (associations and src.split("::")[0].endswith(".rb") and associations.search(callee))
                    )
                ):
                    io.add(callee)
                    if in_loop:
                        g.sites.append(Site(src, "loop_io", line, detail=callee, bounded=startup))
            if src in by_id:
                by_id[src].io = sorted(io)
    framework = {f["id"] for d in parsed.values() for f in d["functions"] if f.get("framework")}
    for f in g.functions:
        if f.name in ambiguous or f.id in framework:
            f.dynamic = True
    g.edges += [Edge(s, d, "call", c) for (s, d), c in calls.items()]
    g.edges += [Edge(s, d, "ref", c) for (s, d), c in refs.items() if (s, d) not in calls]
    return g
