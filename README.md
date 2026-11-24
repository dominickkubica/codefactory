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
codefactory brief path/to/repo                     # a Markdown map for an AI agent (or you)
codefactory context path/to/repo useGuidedWorkout  # before changing it: callers, calls, impact, tests to run
codefactory skill path/to/repo                     # teach Claude Code in that repo to use all of this
codefactory review path/to/repo -o review.md       # a full technical review, no AI (add --for-ai for an AI to finish it)
codefactory plan path/to/repo                      # the work list: ranked tasks with steps and tests
codefactory prompt path/to/repo 1                  # task #1 as a ready-to-paste Claude Code prompt
codefactory baseline path/to/repo                  # save today's issues (commit codefactory-baseline.json)
codefactory check path/to/repo                     # CI / pre-commit: fail only on issues new since the baseline
codefactory sarif path/to/repo -o codefactory.sarif   # issues inline in GitHub code scanning and VS Code
```

Commands that take a name also work from inside the repo without the path: `codefactory context setDayMarks`.
The first run analyzes; later runs reuse `.codefactory/graph.json` (it ignores itself in git) until a source file
changes, so repeated questions answer in well under a second.

`python -m codefactory …` works the same without installing. The HTML page is self-contained: no server, no
network, so it can be emailed or attached to a PR.

**Zoomed out**, a big codebase shows as halls, one per zone, each with a summary card (files, functions, lines,
issues, its most-used files) and one conveyor per pair of halls labelled with how many calls (or imports) it carries.
Forward conveyors arch over the top; dashed orange ones under the floor run backwards. Hover a hall to see only its
conveyors; click it, or zoom in, and the halls fade into their machines.

**Lenses** (the Lens menu) recolour the floor for one kind of problem:

- **Duplication**: machines tinted by how many lines sit in copied functions; dashed purple arcs join files that
  hold copies of each other's code, labelled with how similar they are. Click a duplicate in the Issues list to light
  up every copy.
- **Efficiency**: machines tinted by loop problems; belts that carry a loop's calls into database or network code
  turn red; a drum marks files that do I/O themselves. Hall cards count N+1 loops per layer.
- **Size**: machines tinted by lines of code.

**In the viewer:** drag to pan, scroll to zoom, `f` to fit. **Tests** shows or hides test files (hidden at first when
they're a big share of the code). Hover a machine to see only its belts; click it for its
functions (lines, callers, callees), issues and neighbours. **Calls / Imports** switches what the belts show. The
Issues tab filters by kind; clicking an issue flies to its machine. Click a function's name to **trace** it: the
floor lights up only the machines it reaches, and the panel lists every function it calls, by depth, with the total
lines involved.

## A technical review without an AI

`codefactory review` writes the report a principal engineer would: **executive summary** (what the system is,
overall health as Strong / Adequate / Fragile / At risk with what drives it, top 5 actions with effort), **system
map** (layers and how they call each other, data stores, external services, trust boundaries, most-depended-on
code), **findings** by severity (Critical, High, Medium, Low), each with file:line evidence, impact, fix and effort,
**what is working**, **testing and release gaps**, **open questions** and **review limits**.

On top of everything above (structure, copies, loops, dead code), it checks:

| Area | Checks |
|---|---|
| Security | credentials in source, committed `.env` files, SQL built from strings (naming what's interpolated), eval / exec / pickle / unsafe YAML, shell commands built at runtime, TLS checks turned off, raw HTML injection, plain-HTTP URLs |
| Reliability | swallowed errors, React UI without an error boundary, network calls without a timeout, module-level mutable state, N+1 loops |
| Testing | no tests; which important code (I/O, widely used) no test reaches, from the call graph |
| Delivery | CI present, what it runs, whether it runs on pushes; lockfile; dependencies on `*` / `latest` / git; unpinned Python requirements; runtime version pinned; README with run instructions |

Silence a check that doesn't apply with the same comments as other issues (`codefactory: ignore shell — <why>`).

**`--for-ai`** appends an evidence pack: instructions plus the riskiest functions' code (those that delete databases
or files, swallow errors, branch a lot, do I/O and that no test reaches). An AI confirms or rejects each finding from
the cited lines and judges the risky code, reading a few thousand tokens instead of the whole repository. On a
600-file React Native app the whole report with the pack is about 2,600 words.

What it can't judge: intent, product context, runtime and concurrency behaviour that no rule describes. Those are
what the evidence pack points an AI or a person at.

## From issues to fixes

**`codefactory plan`** turns issues into ranked tasks. Related issues become one job: a group of copies is one merge
(it picks which copy to keep, from the layer the others can import, and lists every caller to repoint), a function's
loop calls are one batching job (naming the function to give a batched variant), dead code is one cleanup. Each task
has steps, the tests that exercise the code, and a check that it's done. Scores favour high severity, more lines
saved and more callers; tests and one-off scripts count less.

**`codefactory prompt <id or rank>`** prints a task as a self-contained prompt for Claude Code: what, where, why,
steps, constraints (keep behaviour, update every caller) and when it's done. In the viewer, every issue has a
**Copy fix prompt** button that copies the same thing.

**Silence what's intended**, so the list stays worth reading. A comment on the function's line, the flagged line,
or the line above either, in any comment style:

```ts
// codefactory: ignore io_in_loop — one query per table, there are 7
// codefactory: ignore unused, test_only: called by the router by name
// codefactory: ignore — every issue on this function
// codefactory: ignore-file duplicate — generated code      (anywhere in a file: the whole file)
```

or in `factory.toml`:

```toml
[[silence]]
kind = "io_in_loop"        # or "*"
where = "src/db/backup.ts" # a file or file::function glob
reason = "bounded by the number of tables"
```

Silenced issues leave the list but not the record: `codefactory flags --silenced` shows each with its reason.

**The ratchet.** `codefactory baseline` saves today's issues to `codefactory-baseline.json`; commit it.
`codefactory check` then fails only on issues that weren't there (by kind, file and function, so moving code around
doesn't count), and reports what's been fixed since. Adopt it on a messy codebase today; the count can only go down.
Run `codefactory baseline` again after a cleanup to lock the gains in.

```yaml
# .github/workflows/codefactory.yml
on: pull_request
jobs:
  structure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: actions/setup-node@v4        # TypeScript / JavaScript repos
        with: { node-version: 22 }
      - run: npm ci                        # the repo's own typescript
      - run: pip install git+https://github.com/<you>/codefactory
      - run: codefactory check
```

As a git pre-commit hook: put `codefactory check` in `.git/hooks/pre-commit` (fast after the first run: unchanged
code comes from the cache).

## Issues on the line: SARIF and GitHub annotations

`codefactory sarif` writes SARIF 2.1.0 (validated against the OASIS schema), the format GitHub code scanning,
VS Code and most CI tools read. Every issue, plus the line-level review checks (credentials, SQL built from strings,
shell strings, swallowed errors…), appears on its line, with:

- a rule per kind, with help text and a fix; security rules carry a `security-severity` so GitHub ranks them
- links between related places (each copy of duplicated code links to the others)
- stable fingerprints (kind, file, function: not line numbers), so an alert follows its code through edits
- silenced issues included as suppressed, with your reason
- with a baseline, `baselineState` new or unchanged on every result; `--new` keeps only new ones

`--min warn` leaves out the info-level notes (long functions, hubs…), which is usually what you want on pull requests.

**GitHub code scanning** (free on public repos; private repos need GitHub Advanced Security):

```yaml
      - run: codefactory sarif --min warn -o codefactory.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: codefactory.sarif, category: codefactory }
```

**Without code scanning**, `--github` prints GitHub Actions annotations instead, which show on the pull request's
changed lines on any plan:

```yaml
      - run: codefactory check --github     # annotations for new issues, and fails on them
```

(`codefactory flags --github --min warn` annotates every issue instead of only new ones.)

**VS Code:** install Microsoft's *SARIF Viewer* extension and open `codefactory.sarif`: issues list in a panel and
squiggle in the editor.

## With Claude Code (or another AI coding agent)

Run `codefactory skill` in a repo once. It writes `.claude/skills/codefactory/SKILL.md`, which tells Claude Code
when to reach for which command: `brief` at the start of a restructure or cleanup, `context` before changing or
deleting anything (callers, impact, the tests to run afterwards), `trace` and `path` when debugging how one part
reaches another, `flags --json` for work lists, and how to read each issue (and which ones are only hints).
Everything prints `file:line`, and `--json` is there for scripts.

A typical restructure then goes: `plan` → `prompt 1` (or click **Copy fix prompt** in the viewer) → Claude follows
it, using `context` before each change → `check` confirms nothing new appeared → run the listed tests → next task.

## Ask it anything with SQL

`codefactory sql` (or `query`, which builds the database in memory) gives you:

| Table / view | Columns |
|---|---|
| `files` | id, module, loc, layer |
| `functions` | id, file, name, qualname, line, end_line, loc, kind, decorated, exported, dynamic |
| `edges` | src, dst, kind (`call`, `ref`, `import`), count |
| `flags` | kind, severity, target, message, line |
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
| Calls in loops (`io_in_loop`) | warn / info | A database, network or file call, or a call into the codebase that eventually makes one, runs once per loop iteration. Reads and network = warn (the N+1 pattern); writes and files = info. Loops over a list fixed in the code (a literal, a constant, `Object.entries(CONST)`, `range(5)`, `.slice(0, 10)`) and loops in migrations are info: they can't grow with the data |
| Duplicate | warn | Functions with the same structure, even with renamed variables (≥ 6 lines, not one-liners) |
| Near-duplicate (`similar`) | warn / info | Copies that were edited afterwards: 75%+ of their structure in common (MinHash over 4-token shingles); 85%+ = warn |
| Searches in loops (`quadratic_scan`) | info | `find` / `filter` / `includes` / `indexOf`… on an array inside a loop or `.map`: O(n²) on long lists (TypeScript) |
| Awaits in loops (`sequential_await`) | info | Each round waits for the last; independent ones could run together (not reported again where a call-in-loop already explains it) |
| Unused | warn / info | Functions nothing calls or references. Methods are only "info", and skipped when their name is used as `obj.name` anywhere or a framework calls them by name (React lifecycle methods, web components, Angular hooks, Django/DRF views). Code loaded with `require()` / `import()` on demand counts as used |
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
  similar.py            Near-duplicates (MinHash + LSH over structure tokens)
  efficiency.py         Calls, searches and awaits in loops; which functions reach I/O
  brief.py              brief and context: Markdown/JSON views for AI agents
  cache.py              .codefactory/graph.json, reused while no source file changed
  skill_template/       The Claude Code skill `codefactory skill` installs
  plan.py               Issues -> ranked tasks with steps, tests and prompts
  suppress.py           Silencing by comment or factory.toml
  baseline.py           The baseline file and the comparison `check` uses
  review.py, checks.py  The review report and its security / reliability / delivery checks
  sarif.py              SARIF 2.1.0 and GitHub annotations
  sqlgraph.py           The graph as SQLite; saved queries -> flags
  trace.py              trace (EXPLAIN for a function) and shortest call path
  config.py             factory.toml
  viewer/               The factory page (canvas, no libraries), inlined into one HTML file
  cli.py                The commands
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
