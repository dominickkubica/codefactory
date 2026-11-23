# codefactory

See a codebase as a top-down factory floor, then use it to find what's wrong: dead code, copy-pasted functions,
import loops, layer violations, oversized files and hubs everything depends on.

Reads **Python** and **TypeScript / JavaScript** (including React and React Native: hooks, JSX components, path aliases).

| On the floor | In the code |
|---|---|
| **Zone** | A layer: a top-level folder (`api/`, `db/`…), one you define, or for flat projects a level of import depth |
| **Machine** | A file. Size = lines; the bars inside are its functions |
| **Belt** | Calls (or imports) between files. Thicker = more call sites; dots show the direction |
| **Dashed orange belt** | Flows backwards: a lower layer reaching back up into a higher one |
| **Grey machine** | Idle: nothing calls in or out |
| **Status light** | Its worst issue: red = high, amber = warn, blue = info |

Zones run left to right from the code that uses others (entry points, UI) to the code everything relies on (data,
utilities), like raw materials arriving on the right and finished goods leaving on the left.

## Install and run

Needs Python 3.11+, with no Python dependencies. For TypeScript / JavaScript it also needs
[Node.js](https://nodejs.org) and the `typescript` package: the analyzed repo's own `node_modules/typescript` is used
(so `npm install` there is enough), else a global one (`npm install -g typescript`), or set `CODEFACTORY_TYPESCRIPT`
to its folder. Without them, Python is still mapped and TypeScript is skipped with a note.

```bash
pip install git+https://github.com/<you>/codefactory      # or, from a clone: pip install -e .

codefactory view path/to/repo        # writes factory.html and opens it in your browser
codefactory flags path/to/repo       # issues in the terminal
codefactory analyze path/to/repo -o repo.graph.json      # the raw graph, for other tools
codefactory flags path/to/repo --fail-on high            # exit 1 on any high-severity issue (CI)
codefactory trace path/to/repo checkout            # everything checkout() eventually calls (like SQL EXPLAIN)
codefactory path path/to/repo checkout tax_for     # the shortest call path between two functions
codefactory sql path/to/repo -o repo.db            # the graph as a SQLite database
codefactory query path/to/repo "SELECT qualname, fan_in FROM function_stats ORDER BY fan_in DESC LIMIT 10"
```

`python -m codefactory …` works the same without installing. The HTML page is self-contained: no server, no
network, so it can be emailed or attached to a PR.

**Zoomed out**, a big codebase shows as halls, one per zone, each with a summary card (files, functions, lines,
issues, its most-used files) and one conveyor per pair of halls labelled with how many calls (or imports) it carries.
Forward conveyors arch over the top; dashed orange ones under the floor run backwards. Hover a hall to see only its
conveyors; click it, or zoom in, and the halls fade into their machines.

**In the viewer:** drag to pan, scroll to zoom, `f` to fit. **Tests** shows or hides test files (hidden at first when
they're a big share of the code). Hover a machine to see only its belts; click it for its
functions (lines, callers, callees), issues and neighbours. **Calls / Imports** switches what the belts show. The
Issues tab filters by kind; clicking an issue flies to its machine. Click a function's name to **trace** it: the
floor lights up only the machines it reaches, and the panel lists every function it calls, by depth, with the total
lines involved.

## Ask it anything with SQL

`codefactory sql` (or `query`, which builds the database in memory) gives you:

| Table / view | Columns |
|---|---|
| `files` | id, module, loc, layer |
| `functions` | id, file, name, qualname, line, end_line, loc, kind, decorated, exported, dynamic |
| `edges` | src, dst, kind (`call`, `ref`, `import`), count |
| `flags` | kind, severity, target, message |
| `function_stats` (view) | id, file, qualname, loc, fan_in, fan_out, caller_files |
| `file_deps` (view) | src_file, dst_file, calls |

```sql
-- big functions everyone depends on: the riskiest code to change
SELECT qualname, file, loc, caller_files FROM function_stats WHERE loc > 40 AND caller_files >= 5 ORDER BY caller_files DESC;
-- which files does the api layer pull from the db layer?
SELECT d.* FROM file_deps d JOIN files a ON a.id = d.src_file JOIN files b ON b.id = d.dst_file
WHERE a.layer = 'api' AND b.layer = 'db';
```

**Saved queries become flags.** Add them to `factory.toml`; each row returned is one issue, with a `target` column (a
file or function id), an optional `message`, and any other columns appended to the message:

```toml
[[queries]]
name = "risky_hub"
severity = "warn"
message = "Large function called from many files"
sql = "SELECT id AS target, loc, caller_files FROM function_stats WHERE loc > 40 AND caller_files >= 5"
```

## What it flags

| Issue | Severity | Meaning |
|---|---|---|
| Import loop | high | Files that import each other in a circle (Tarjan's algorithm on the import graph) |
| Layer violation | high | An import your `factory.toml` forbids, e.g. `ui -> db` |
| Duplicate | warn | Functions with the same structure, even with renamed variables (≥ 6 lines, not one-liners) |
| Unused | warn / info | Functions nothing calls or references. Methods are only "info", and skipped when their name is used as `obj.name` anywhere |
| Hub | info | A function called from 12+ files: change it carefully |
| Test only | info | Code nothing but tests calls: dead in the product, still kept alive by its tests |
| Large file / long function | info | Over 400 / 60 lines |

## factory.toml (optional)

Put it at the root of the analyzed repo:

```toml
ignore = ["migrations", "fixtures"]      # extra folder names to skip (.venv, node_modules… are skipped already)

[layers]                                  # first match wins; unmatched files keep the inferred layer
ui = ["app/screens/**", "app/components/**"]
logic = ["app/services/**"]
db = ["app/db/**"]

[rules]
forbid = ["ui -> db", "db -> ui"]

[thresholds]
large_file = 400
long_function = 60
duplicate_min_lines = 6
hub_callers = 12
```

## How accurate is it?

Analysis is static (nothing is run), so the graph is a good approximation, not the truth.

**TypeScript / JavaScript** uses the TypeScript compiler's type checker with the repo's own `tsconfig.json`, so it
follows most calls:

- imports through path aliases (`@/db/steps`), re-exports and `require()`; `import type` doesn't count as an import
- methods on typed objects (`store.save()`), functions handed out by hooks (`const { logSet } = useRun(); logSet()`),
  JSX components (`<Button />` is a call to `Button`), `new Class()` to its constructor
- named functions inside functions (a hook's handlers) are machines' functions of their own, qualified by their
  owner (`useRun.logSet`); inline callbacks (`onPress={() => …}`) belong to the function around them
- not "unused": default exports, exports of files nothing imports (routes and screens a framework loads), functions
  kept in objects (`{ label, onPress }`), tests. Exports nobody uses in imported files are reported.

**Python:**

- **Resolved:** plain calls, imported names (absolute and relative, through package re-exports), `module.func()`,
  `self.method()`, `cls.method()`, `ClassName()` (to `__init__`), and functions passed by name (callbacks).
- **Not resolved:** calls through variables, `getattr`, dependency injection, or most `obj.method()` where `obj`'s type
  isn't known. Those methods are protected from false "unused" reports, but their belts don't show.
- Decorated functions, `__all__` names, `main`, dunders and tests are treated as entry points and never "unused".

Speed: Python about 15 ms per file; TypeScript about 30 s for a 600-file React Native app (the type checker dominates).

## Layout

```
codefactory/
  analyzers/python.py   Python → graph (stdlib ast). Add a language by adding a module and registering it
  analyzers/typescript.py, ts_helper.js   TypeScript/JavaScript → graph (TypeScript compiler, run in Node)
  graph.py              The language-neutral graph (files, functions, edges, flags)
  layers.py             Zones and their order
  flags.py              Issue detectors (read only the graph, so they work for every language)
  sqlgraph.py           The graph as SQLite; saved queries -> flags
  trace.py              trace (EXPLAIN for a function) and shortest call path
  config.py             factory.toml
  viewer/               The factory page (canvas, no libraries), inlined into one HTML file
  cli.py                analyze / flags / view
tests/                  unittest; fixtures/shop is a small app with planted problems
```

## Roadmap

- **More languages** via tree-sitter (Go, Rust, Java, C#, Swift).
- **Graph diffs, like schema migrations:** compare two commits and report what a change added (new import loops, rule
  breaks, duplicates, files that grew), as a CLI command and a PR check.
- **Constraints beyond `forbid`:** allow-lists ("only `services/` may import `db/`"), limits ("no file over 600 lines",
  "no function with over 15 callees") and must-go-through rules, runnable as a pre-commit hook.
- **Low cohesion ("normalize this file"):** flag files whose functions never call each other and serve separate
  callers, and suggest how to split them.
- **Readable layouts at scale:** order machines inside each zone to minimise belt crossings (layered/Sugiyama layout),
  show call counts at belt ends like crow's-foot notation, and save named views (e.g. "the checkout flow").
- **Data dictionary:** docstrings in the machine panel; per-machine count of calls the analyzer couldn't resolve, so
  you know how far to trust its belts.
- **Live traffic:** load OpenTelemetry traces or a small Python profiler so real calls move along the belts and slow or
  repeated calls (N+1) pile up visibly.
- **Agent view:** a Claude Code hook that logs which files each AI session reads and edits, shown as workers walking
  the floor.
- Function-level drill-down (a machine opens into its own little line of functions).
- Near-duplicate detection (similar, not identical, structure).
