# codefactory design

How codefactory works, why it's built the way it is, and where its limits are. For using it, see the
[usage guide](USAGE.md).

- [Goals](#goals)
- [Architecture](#architecture)
- [The graph](#the-graph)
- [Analyzers](#analyzers)
- [Layers](#layers)
- [Checks](#checks)
- [Silencing, baselines and fingerprints](#silencing-baselines-and-fingerprints)
- [The review](#the-review)
- [The plan](#the-plan)
- [The viewer](#the-viewer)
- [Caching](#caching)
- [Working with AI agents](#working-with-ai-agents)
- [Testing](#testing)
- [Decisions and trade-offs](#decisions-and-trade-offs)
- [Known limitations](#known-limitations)
- [Extending codefactory](#extending-codefactory)
- [Roadmap](#roadmap)

## Goals

1. **Make structure visible.** A codebase's architecture lives in hundreds of files; a picture of who depends on whom,
   at the right level of detail, makes redundancy, bottlenecks and tangles obvious.
2. **Find problems that cost money**, with evidence: copied logic, per-item database calls, dead code, import loops,
   untested critical code, and the common security, reliability and delivery mistakes. Every finding cites
   `file:line` so a person can verify it in seconds.
3. **Turn findings into work**: ranked tasks with steps, tests to run, and a check that the work is done.
4. **Make AI coding agents cheap and safe to use on large codebases.** An agent that reads a 3,000-token map and the
   ten files a task needs, instead of the whole repository, costs a fraction as much and makes fewer mistakes.
5. **Never get in the way.** Read-only, offline, no account, no server, no telemetry, and no Python dependencies.

**Non-goals.** codefactory is not a type checker, a linter for style, a test runner or a vulnerability database. It
doesn't execute code and doesn't fetch anything from the network.

## Architecture

```
            ┌─────────────────────────────── analyze (once, then cached) ───────────────────────────────┐
 repository │  analyzers/python.py  ── stdlib ast ──┐                                                    │
 (on disk)  │  analyzers/typescript.py + ts_helper.js ── the repo's TypeScript compiler, in Node ──┐      │
            │                                       ▼                                              ▼      │
            │                         Graph: files · functions · edges · sites                            │
            │                                       │                                                     │
            │      layers.py (zones and their order) │  config.py (factory.toml)                          │
            │                                       ▼                                                     │
            │  checks: flags.py · similar.py · efficiency.py · saved SQL queries (sqlgraph.py)           │
            │                                       ▼                                                     │
            │  suppress.py: issues marked as intended move to Graph.silenced, with their reason          │
            └───────────────────────────────────────┬──────────── cache.py: .codefactory/graph.json ──────┘
                                                    ▼
     ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
     viewer/        review.py      plan.py        sarif.py       brief.py       baseline.py
     (HTML map)     + checks.py    (tasks,        (SARIF,        (brief,        (baseline,
                    (report)       prompts)       annotations)   context)       check)
                                     trace.py (trace, path) · sqlgraph.py (query, sql)
```

Everything after analysis reads the same language-neutral **graph**, so every check and every output works the same
for every language, and adding a language means writing one analyzer.

The code is organised the same way:

| Module | Responsibility |
|---|---|
| `analyzers/` | Source → graph, one module per language |
| `graph.py` | The data model |
| `layers.py`, `config.py` | Zones and their order; `factory.toml` |
| `flags.py`, `similar.py`, `efficiency.py`, `sqlgraph.py` | Checks on the graph |
| `suppress.py`, `baseline.py`, `paths.py` | Silencing; the ratchet; what counts as a test or a script |
| `checks.py`, `review.py` | Source-text and repository checks; the review report |
| `plan.py`, `brief.py`, `trace.py`, `sarif.py` | Outputs |
| `viewer/` | The HTML map (template, CSS, JavaScript; no libraries) |
| `cache.py`, `cli.py`, `skill.py` | Caching; the command line; the Claude Code skill, its self-refresh, the session hook and `update` |

## The graph

```text
File      id (posix path from the repo root) · module · loc · layer
Function  id ("file::Qualified.name") · file · name · qualname · line · end · loc
          kind (function | method | module) · decorated · exported · public · dynamic
          io (I/O calls it makes itself) · shape (structure hash) · tokens (structure, dropped after checks)
Edge      src · dst · kind (call | ref | import) · count
Site      fn · kind (loop_call | loop_io | loop_await | loop_scan) · line · target · detail · bounded
Flag      kind · severity (high | warn | info) · target (file or function id) · message · related · line · score · reason
```

- Every file has a `<module>` pseudo-function for top-level code, so calls made at import time count.
- **`call`** edges are calls the analyzer resolved; **`ref`** edges are functions referenced without being called
  (callbacks, values returned from hooks, dispatch-table entries). Refs keep functions from looking unused and are
  followed when computing test reach, but aren't drawn as belts.
- **`import`** edges are file-to-file and count only imports that run at load time (see [cycles](#import-loops)).
- **Sites** record notable spots inside a function for the efficiency checks: a resolved call inside a loop, an
  unresolved I/O call inside a loop, an await inside a `for`/`while`, an array search inside a loop. `bounded` says
  whether every loop around it iterates over a list fixed in the code.

The graph serialises to JSON (`codefactory analyze`) and loads into SQLite (`codefactory sql`) without loss of
anything the checks use.

## Analyzers

### Python

Uses only the standard library `ast` module; nothing is imported or executed.

- **Functions:** top-level functions and class methods. Nested functions belong to the function around them.
- **Resolution:** plain names, imported names (absolute and relative, through package re-exports), `module.func()`,
  `self.method()` / `cls.method()`, `ClassName()` to `__init__`, and `Class.method()`. A method name defined exactly
  once in the codebase is linked as a `ref` when called on an unknown object.
- **Dispatch tables:** a call like `COMMANDS[name][0](args)`, where `COMMANDS` is a module-level literal, links (as
  refs) to every function the literal mentions.
- **Imports at load time:** imports inside functions and under `if TYPE_CHECKING:` are recorded for resolution but
  not as import edges, because they can't create a loop when the module loads.
- **Loops:** a walker tracks, for each node, whether it runs once per iteration (`for`, `while`, comprehensions),
  whether that's a statement loop (where an `await` serialises), and whether every enclosing loop is **bounded**:
  iterating a literal, a module-level constant (also imported), `range(N)` or `x[:N]` with N ≤ 50, or those through
  `.items()`, `sorted()`, `enumerate()`. Nested functions start afresh.
- **I/O calls** are recognised on calls the analyzer couldn't resolve to the codebase's own functions: DB-API methods
  (`execute`, `fetchall`, `commit`…), Django ORM chains, `open()`, `pathlib` reads and writes, and modules like
  `requests`, `httpx`, `subprocess`, `sqlite3`. A SQL string starting with `SELECT` marks a read.
- **Structure tokens** for duplicate detection: node types in source order, operators, attribute names, names not
  local to the function, and the words of string literals and numeric literals. Local names (arguments, variables)
  are left out so renamed copies still match; literals are kept so two functions that differ only in their SQL don't.

### TypeScript and JavaScript

TypeScript can only be analyzed faithfully by the TypeScript compiler, so `analyzers/typescript.py` runs
`ts_helper.js` in Node with **the analyzed project's own** `typescript` package and `tsconfig.json`. That gives the
exact module resolution the project uses (path aliases like `@/…`, `baseUrl`, `paths`) and its type information.

- **Functions:** declarations, methods, arrow functions and function expressions with a name: their own, or the
  variable, property or `memo` / `forwardRef` / `useCallback` they're assigned to. Named functions inside functions
  (a hook's handlers) are functions of their own (`useCart.add`). Inline callbacks, such as `onPress={() => …}` or
  an object property inside a function, belong to the function around them.
- **Resolution** asks the type checker what each call runs: the resolved signature's declaration first, then the
  callee's symbol through aliases. That covers imported functions, methods on typed objects, functions handed out by
  hooks (`const { add } = useCart(); add()`), JSX elements (`<Button />` is a call to `Button`) and `new Class()`.
- **Code loaded on demand:** `const { fn } = require("./x")` (also cast with `as`), `const m = require("./x"); m.fn()`,
  `require("./x").fn()` and `await import("./x")` are resolved through the target module's exports.
- **Dispatch tables:** `HANDLERS[key](…)` links to every function in the table (the type checker alone would pick one).
- **Imports:** `import type` and type-only specifiers don't count; a `require()` inside a function isn't a load-time
  import.
- **Entry points:** default exports, and exports of files nothing imports (routes and screens a framework loads by
  file name), are never reported as unused.
- **Loops** as in Python, plus array callbacks (`map`, `forEach`, `filter`, `reduce`…), which run once per element. A
  callback that isn't an array callback (`onPress`, `setTimeout`, `.then`) stops the search: its body runs later, not
  per iteration. **Bounded** loops iterate array or object literals, `const`s holding them (also imported, and
  through `Object.keys/values/entries`, `.map`, destructuring and `PARTS[key].list`), enums, `.slice(0, N)`, or
  `for (…; i < N; …)` with N ≤ 50.
- **I/O calls:** expo-sqlite and similar (`getAllAsync`, `runAsync`…), `fetch`, file-system calls, `axios`,
  `AsyncStorage`, Prisma/Supabase-style clients.
- **Array searches** (`find`, `filter`, `includes`, `indexOf`…) count only when the receiver's type is an array and
  it isn't a list written out in the code.

The helper prints the same graph JSON the Python analyzer produces. Paths are compared after resolving them, because
TypeScript reports `/` and Node on Windows uses `\`.

## Layers

A layer (a zone on the floor) is, in order of precedence:

1. a `[layers]` glob in `factory.toml`;
2. otherwise the first folder below the folders every source file shares, skipping `src/` and `lib/`; test folders
   become `tests`;
3. if one inferred layer holds 70% or more of the code and its files spread over three or more subfolders, that layer
   is split by its next folder level (so `pip/_internal/…` becomes `cli`, `commands`, `network`…);
4. for a flat project (one folder), layers are levels of import depth: level 0 imports nothing else in the project,
   each level builds on those below, and import loops share a level.

Layers are ordered left to right by how much they depend on others: a layer that imports more than it's imported
goes left. `tests` always goes first; import-depth levels go highest first.

## Checks

### Import loops

Tarjan's strongly-connected-components algorithm (iterative, so deep graphs can't overflow the stack) on the
load-time import graph. Each file in a component of two or more gets a `high` flag naming the loop.

### Dead code

A function is unused when no `call` or `ref` edge reaches it and it isn't an entry point: top-level code, decorated
functions, `__all__` names, `main`, dunders, tests, methods frameworks call by name (React lifecycle methods, web
components, Angular, Django/DRF views), default exports, and TypeScript exports of files nothing imports. Methods are
reported only at info level, and not at all when their name is used as `obj.name` anywhere, because dynamic dispatch
is the commonest source of false positives. A function reached only from test files is `test_only`.

### Duplicates and near-duplicates

- **Exact duplicates:** functions of at least 6 lines (and 15 syntax nodes) with the same structure hash.
- **Near-duplicates:** each function's tokens are cut into 4-token shingles. A 64-permutation MinHash signature, split
  into 16 bands of 4 rows (locality-sensitive hashing), finds candidate pairs without comparing every pair. Candidates
  are then confirmed with the exact Jaccard similarity of their shingle sets. A pair qualifies at 0.75 or more, if both
  have at least 40 tokens and their sizes are within 60% of each other; exact duplicates and a function paired with one
  nested inside it are skipped, and so are buckets of more than 200 functions (boilerplate everyone shares). Pairs are
  grouped into clusters with union–find. Clusters at 0.85 or more are `warn`, the rest `info`.

The parameters were tuned on real code: with 5-token shingles at 0.80, a copy with one added line in seven fell
below the threshold; at 0.70, unrelated components that merely share JSX structure started to match.

### Efficiency

1. **Who reaches I/O:** a reverse breadth-first search from every function that does I/O itself, along call edges,
   marks every function that eventually does I/O, and remembers the next hop and the I/O call reached.
2. **Calls in loops:** each `loop_io` site, and each `loop_call` site whose target reaches I/O, becomes an
   `io_in_loop` finding per (function, callee). Severity follows cost: network calls and reads are `warn` (the N+1
   pattern), writes and file operations `info`. If every site is bounded, or the file is a migration, it's `info` with
   a note that it can't grow with the data.
3. **Awaits in loops** are reported only where no call-in-loop finding already explains the same line, and never in
   bounded loops: serialising a few writes on one connection is often required, and suggesting `Promise.all` would
   be wrong advice.
4. **Searches in loops** are reported at `info`, never in bounded loops.

Test files are excluded: a setup loop in a test isn't a production problem.

### Size, hubs and saved queries

`large_file` (over 400 lines), `long_function` (over 60), `hub` (called from 12 or more files) are context rather
than defects. Saved SQL queries run against the in-memory SQLite form of the graph; each row returned is a flag.

## Silencing, baselines and fingerprints

- **Silencing** happens after all checks. A `codefactory: ignore <kinds> — reason` comment on the flagged line, the
  function's line, or the line above either; `ignore-file` anywhere in a file; or a `[[silence]]` glob in
  `factory.toml`. Silenced flags move to `Graph.silenced` with their reason rather than disappearing.
- **Issue identity** for baselines is `kind | file::qualname` (or the file for file-level issues), counted. It doesn't
  include line numbers, so editing code above an issue doesn't make it "new".
- **SARIF fingerprints** are a hash of the same identity plus the occurrence index, so GitHub tracks an alert across
  edits instead of closing and reopening it.

## The review

`checks.py` adds what the graph doesn't cover:

- **Source-text patterns:** credentials (provider key formats, private keys, `key = "<long random string>"`), SQL
  assembled with f-strings, `%`, `+`, `.format` or template literals (interpolations of constants are allowed),
  `eval`/`exec`/`pickle`/unsafe YAML, shell strings, TLS verification off, raw HTML, plain HTTP, swallowed errors,
  module-level `let` and `global`, `fetch` without an abort signal, `requests` without a timeout, external hosts.
  Each honours `codefactory: ignore` comments; test files are only checked for credentials.
- **Repository facts:** CI configuration and what it runs, lockfiles, floating or unpinned dependencies, runtime
  version pins, README, licence, committed `.env` files (checked against `git ls-files`), detected frameworks.
- **Test reach:** a breadth-first search over call and ref edges from every function in a test file.

`review.py` turns these and the graph's flags into findings with severity, evidence (the first six instances),
impact, a fix and an effort (S/M/L from the number of instances and files).

**Health grade.** Start at 100 and subtract 30 per Critical finding, 10 per High, 3 per Medium (at most 24 in total)
and 1 per Low (at most 6), so a pile of small issues can't outweigh one serious one. 85 or more is *Strong*, 65 or
more *Adequate*, 40 or more *Fragile*, below that *At risk*. The number itself isn't printed: it's a rubric, not a
measurement.

**Evidence pack** (`--for-ai`). Functions of 8 to 160 lines outside scripts are scored on what makes code dangerous:
deleting a database or files (+6) or rows (+2), swallowed errors (+2, plus 1 each, up to +6), I/O (+1), no test
reaching it (+2), transactions or concurrency (+1), and branching (+1 per 4 branches, up to +4). Comments are
stripped before matching. The six highest-scoring functions with a score of 7 or more are included with their code.

## The plan

`plan.py` groups issues into tasks and scores them:

| Task | Groups | Base score |
|---|---|---|
| Break an import loop | one per strongly connected component | 90 |
| Remove a forbidden import | one per violation | 80 |
| Batch the queries / writes in a function | all of a function's calls in loops | 70 (reads, network) / 25 (writes) |
| Merge copies | one per cluster | 60 (identical) / 45 (similar) |
| Remove unused functions | all of them | 35 |
| Run awaits together | one per function | 18 |
| Replace searches in loops | one per file | 14 |
| Decide on test-only functions | all of them | 12 |
| Split a long function | one per function | 8 |

Scores grow with lines saved, the number of copies and callers, and repeated sites; tasks entirely in tests weigh
0.3, entirely in scripts 0.5. For a merge, the copy to keep is the one in the layer furthest right (the one the
others' callers can import), then the most-called; when one copy is plain JavaScript and the other TypeScript, the
task says so.

Each task's prompt is plain text with fixed sections (task, why, where, steps, constraints, done when), so it works
with any agent, and it lists the tests that exercise the code: test files among the functions that depend on it, and
test files importing it.

## The viewer

`codefactory view` writes one self-contained HTML file: the graph as JSON, the CSS and JavaScript inlined, no
libraries and no network. Data is escaped so source text can't end the script block, and every value inserted into
the page goes through an escape function.

- **Layout:** zones are halls of one shared height, each as wide as its machines need, sized so the floor has roughly
  the screen's proportions; machines are packed in rows inside each hall, largest first. Belts are routed
  orthogonally between halls; backward and same-hall belts go over the top.
- **Semantic zoom:** below a scale of 0.26 the floor is drawn as halls with summary cards and one conveyor per pair of
  halls; above 0.46, as machines and belts; in between, one fades into the other. Text on cards is drawn in screen
  space so it stays readable at any zoom.
- **Lenses** tint machines by a metric (lines in copied functions, weighted loop problems, lines of code) with a
  square-root scale, and add overlays: arcs between files holding copies, red belts for loops calling into I/O.
- **Large floors:** belts are drawn faint until something is in focus; test files can be hidden; the moving dots on
  belts are drawn only at machine level and are off under `prefers-reduced-motion`.

## Caching

`.codefactory/graph.json` holds the last analysis and a fingerprint: codefactory's version and the size and
modification time of its own source files, plus the path, size and modification time of every analyzable file and
of `factory.toml`, `tsconfig.json`, `jsconfig.json` and `pyproject.toml`. Any change re-analyzes. The folder contains
its own `.gitignore`, so it never shows up in `git status`. Upgrading codefactory invalidates the cache automatically.

## Working with AI agents

The economics are the point. An agent that understands a repository by reading it spends tens of thousands of tokens
before doing anything, and still misses things outside what it read. codefactory reverses that:

- `brief` gives the agent the shape of the repository in about 3,000 tokens;
- `context` gives everything about one function (callers, impact, tests) in a few hundred;
- `plan` and `prompt` give it a scoped task with a definition of done;
- `check` gives it a cheap, objective test that it made nothing worse.

The skill file (`codefactory skill`) tells Claude Code which command answers which question, and, as importantly,
which findings are only hints (`unused`, `test_only`, "no test reaches it") and must be verified before acting.

Instructions that lag the tool are worse than none, so the skill is versioned: it carries a
`<!-- codefactory skill X.Y.Z -->` stamp after its front matter, and every command checks it (one small file read)
and rewrites a stale copy before running. The optional session hook closes the other gap, an outdated tool: it
upgrades at most once a day so a session start costs nothing on most days, uses a local checkout when one is
present (cloud sessions with the repository attached), and always exits 0, because a helper must never stop a
session from starting.

## Testing

- **Fixtures with planted problems:** `tests/fixtures/shop` (Python: an import loop, copies, near-copies, an N+1,
  dead code) and `tests/fixtures/tsapp` (TypeScript: path aliases, hooks, JSX, typed methods, lazy `require`,
  dispatch tables, bounded loops, a React-style error boundary, an import loop, copies). Tests assert both that
  problems are found and that the look-alikes of problems aren't.
- **Regression tests from real use:** every false positive found on a real codebase got a test before it was fixed,
  such as inline `onPress` callbacks inside `.map`, loops over constant tables, lazy `require()`, React lifecycle
  methods, imports inside functions, and same-shaped functions with different SQL.
- **End to end:** the CLI is tested as a user runs it, including error messages, the baseline ratchet, SARIF output
  and cache invalidation; SARIF output was validated against the OASIS 2.1.0 schema.
- **CI:** Linux and Windows, Python 3.11 and 3.13, with Node and TypeScript installed so the TypeScript tests run;
  ruff lint and format checks; and codefactory runs `check` on its own source.

## Decisions and trade-offs

- **Static, not dynamic.** Nothing runs, so it's safe on any repository and needs no environment. The price is that
  calls resolved only at runtime are missed; the design compensates by preferring false negatives over false
  positives for anything that suggests deleting code, and by making every finding easy to verify and silence.
- **The project's own TypeScript.** Bundling a TypeScript version would be simpler, but it would resolve modules
  differently from the project and drift from its language version. Using the project's own compiler and
  `tsconfig.json` makes the graph match what the project's build sees.
- **No Python dependencies.** Installing the tool can never conflict with a project's dependencies, and it runs
  anywhere Python 3.11 does. Node is needed only for TypeScript.
- **One graph, many outputs.** Checks never read source text except for the review's line patterns, so they're
  language-independent and fast to test.
- **Heuristics are calibrated on real code** and documented here with their thresholds, so their behaviour can be
  predicted and argued with.
- **Severity reflects cost.** A loop that can't grow, a write inside a transaction or an unused method is real but
  minor; reserving `warn` and `high` for things worth fixing keeps the list worth reading.

## Known limitations

- Calls through reflection, `getattr`, dependency injection, or untyped objects aren't resolved, so belts can be
  missing and "unused" or "no test reaches it" can be wrong. Both are labelled as hints.
- `while` loops are always treated as unbounded.
- Exact duplicates ignore local variable names, so two short functions with the same shape and the same literals but
  different meaning can match; the 6-line and 15-node minimums keep this rare.
- The review's security checks are patterns, not data-flow analysis: they find likely problems, and can't prove a
  value is or isn't attacker-controlled.
- Only Python and TypeScript/JavaScript are analyzed; other languages in a repository are listed in the review's
  limits.
- A whole-repository TypeScript analysis takes tens of seconds on large projects, because the type checker builds the
  full program; the cache makes repeat runs instant.

## Extending codefactory

**A new language.** Write `analyzers/<language>.py` exposing `analyze_<language>(root: Path, ignore: list[str]) ->
Graph` that fills `files`, `functions`, `edges` and, where it can, `sites` and `Function.io`/`tokens`; register it in
`analyzers/__init__.py`. Everything else (layers, checks, review, plan, viewer, SARIF) works unchanged. Add a fixture
with planted problems and a test file.

**A new check on the graph.** Write a function taking the `Graph` (and the `Config` if it needs thresholds) and
returning `Flag`s; call it from `run_flags` in `flags.py`; add a rule to `sarif.RULES`, a label to the viewer's
`KIND` map, and, if it should become work, a task in `plan.py`. Many checks can instead be a saved SQL query in
`factory.toml`, with no code at all.

**A new review check.** Add a pattern to `checks.PATTERNS` (line-level) or a fact to `scan_repo` (repository-level),
then a finding in `review.py` and a rule in `sarif.RULES`.

## Roadmap

- **More languages** through tree-sitter: Go, Rust, Java, C#, Swift.
- **Graph diffs:** compare two commits and report what a change added (new loops, rule breaks, copies, files that grew).
- **Safe automatic fixes** (`--fix`): merge exact duplicates and delete unused functions, always showing the diff first.
- **Richer architecture rules:** allow-lists ("only `services/` may import `db/`"), limits, and must-go-through rules.
- **Cohesion:** flag files whose functions never call each other and serve separate callers, and suggest a split.
- **Layout:** order machines to minimise belt crossings, and save named views ("the checkout flow").
- **Live traffic:** load OpenTelemetry traces so real calls move along the belts and slow paths pile up visibly.
