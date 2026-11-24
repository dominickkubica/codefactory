# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); before 1.0, minor versions may
change command-line output.

## 0.10.0 · 2026-11-24

### Added
- **`codefactory accept`:** marks a finding as intended, with the reason, by writing a `[[silence]]` rule to
  `factory.toml`. It takes either a kind and a place (`accept sql_built src/db/x.ts --why "…"`) or a plan task, which
  covers every finding behind it. The review's own checks now honour these rules too.
- **Measured coverage:** when the repository has a coverage report (lcov, Istanbul `coverage-final.json`,
  coverage.py `coverage.json`), "no test reaches it" comes from what actually ran, and the review names the report.
  The call-graph estimate it replaces matched Jest's report for 97.6% of functions on a 500-file app.

### Changed
- **Ordinary commands never change the repository.** They used to rewrite an outdated
  `.claude/skills/codefactory/SKILL.md`, which left clean checkouts and CI runs dirty. Now they print a note, and the
  session hook, `codefactory skill` and `codefactory update` refresh it.
- **Array searches inside loops** are reviewed only in functions that load data from storage or the network, where
  the lists can grow. A search over a handful of UI items or a fixed table isn't worth a line in a review. On a React
  Native app this went from 53 to 2.

## 0.9.4 · 2026-11-24

### Fixed (clean-slate runs on a React Native app and a FastAPI app)
- **Transactions opened by the caller count:** a function every call of which happens inside a transaction (`with
  db.session(): insert_items(…)`, `transaction(db, () => insertItems(…))`) has its writes treated as batched. On the
  React Native app, "writes inside loops" went from 4 to 1, and the one left is real.
- **Calling the transaction helper once per batch** (`for (…) await transaction(db, …)`) is the batching, not a
  write in a loop.

## 0.9.3 · 2026-11-24

### Fixed (a second pass over the same FastAPI + React app)
- **Calls in loops are classified by what they do**, and the review reports each kind separately:
  - "Writes inside loops" no longer includes file operations, program runs, or loops over fixed lists and
    migrations (which said "fine as is").
  - File copies, moves and deletes (`shutil.copy2`, `rename`, `unlink`…) count as file operations, not database
    writes.
  - `subprocess.run()` per item counts as a program run.
  - `time.sleep()` in a loop is pacing on purpose and isn't reported.
- **Reads hidden behind `execute`:** an f-string starting with `SELECT` marks a read. When the SQL can't be seen, a
  function on the way named like a read (`read_*`, `get_*`, `load_*`…) makes it one, so these are no longer filed as
  writes.
- **A function named `migrate*` counts as a migration**, wherever it lives.
- **`getattr(obj, "name")` and `hasattr` with a literal name use that name**, so a method only reached that way isn't
  reported as unused.

## 0.9.2 · 2026-11-24

What a review of a 55,000-line FastAPI + React app showed could be better.

### Changed
- **Writes inside a transaction aren't reported**: loops in `with db.session():`, `with transaction.atomic():`,
  `with conn:` (Python) or in a callback given to `transaction(…)` / `withTransactionAsync(…)` (TypeScript) are
  batched already. On a React Native app this took "writes inside loops" from 28 to 7.
- **Copy sizes count code, not docstrings**: three functions with long docstrings and a 3-line shared body were
  "~29 lines" of copies; now ~12.
- **Copies kept apart on purpose** (same file, different names, each used or public) get "share one body between
  them" advice instead of "replace it with an import of the other".
- **Long functions are ranked by decision points**, not length alone, and the count is shown: a 750-line table of
  options no longer outranks a 90-line parser full of conditions.
- **Batch suggestions use the code's naming style**: `get_order_batch(ids)` and a dict in Python, `getOrderMany(ids)`
  and a Map in TypeScript.
- **Top-level files of a package split into zones** are placed by how they're used: imported by the zones
  ("pkg shared": config, logging) or importing them ("pkg app": the CLI). One mixed zone used to look like a layer
  against the dependency order.
- **Hidden folders** (`.claude`, `.github`…) are tooling, not product code, and aren't analyzed.
- **Data stores from Python manifests**: dependencies in `pyproject.toml` and `requirements.txt` are read, and DuckDB,
  Parquet, SQLAlchemy, MySQL, Elasticsearch and S3 are recognised.

### Added
- **Snapshot tests** of every finding on the three fixture apps (`tests/golden/`): any change in what codefactory
  reports fails CI until it's reviewed (`CODEFACTORY_UPDATE_GOLDEN=1`).

## 0.9.1 · 2026-11-24

### Fixed (found reviewing a 55,000-line FastAPI + React app)
- **Python imports inside a function now apply to that function only.** Two functions importing different
  `summarize`s both linked to the last one, so the other looked unused and the loops calling it were missed.
- "Network calls without a timeout" looks for `fetch()` only in JavaScript/TypeScript, where it's the web's fetch; in
  Python a variable named `fetch` is anything.

## 0.9.0 · 2026-11-24

Big codebases and many languages.

### Added
- **Every other language through tree-sitter** (optional: `pip install "codefactory[languages]"`): Go, Java, Kotlin,
  Swift, Rust, C/C++, C#, Ruby, PHP, Scala, Dart, Lua, Elixir and more get the map, copies, calls and I/O in loops,
  sizes and unused-code hints. Calls are matched by name, and the review says so. Without TypeScript installed,
  TypeScript/JavaScript falls back to it instead of being skipped. The review's text checks (credentials, empty
  catches, SQL built from strings, plain HTTP) now read these languages too.
- **Parallel, incremental analysis:** files are parsed on every core (`CODEFACTORY_JOBS`) and cached one by one, so a
  repeat run re-reads only what changed. On 1.7 million lines of Python: 287 s to 48 s for a first run, 21 s after
  changing a file, 5 s when nothing changed; memory 3.2 GB to 1.2 GB.
- `--lang other` limits the analysis to the tree-sitter languages.

### Changed
- Near-duplicate signatures use one-permutation MinHash (64 times cheaper), are cached, and pre-screen candidates.
  The same pairs as before on a React Native app, and 0.2% more on 1.7 million lines.
- Copies between per-platform versions of a file (`x_linux.go` / `x_darwin.go`) aren't duplicates.
- Test files are recognised in more languages (`x_test.go`, `x_spec.rb`, `FooTest.java`).

### Fixed
- The review re-checked every function for each copy (quadratic): 31% of a review's time on large codebases.
- Silencing comments were re-read for every finding in a file.
- Minified JavaScript (`*.min.js`) is skipped, and function ids are unique whatever an analyzer produces.

## 0.8.1 · 2026-11-24

### Fixed (review false positives found on a real React Native app)
- **Swallowed errors:** an empty catch isn't reported when a comment says why, when it's best-effort cleanup of a
  leftover (cancelling a notification, deleting a stored item, file or cache; never the user's records), or when the
  failure becomes a fallback value (`const x = await load().catch(() => null)`). The review's limits section counts
  them. On that app: 16 reported before, 5 after, all 5 real.
- **SQL built from strings:** names that come from a fixed list or are checked against one in the lines above
  (`for (const t of Object.keys(TABLES))`, `known.has(t)`, `.filter((c) => allowed.has(c))`) and numeric expressions
  (`version + 1`, `Math.floor(v)`) are safe. Only the template literal itself is read, and `{name}` counts as
  interpolation only in Python strings.
- **Module-level state** in a UI app (React, React Native, Expo, Vue, Svelte) is reported only when exported mutable;
  per-app singletons are normal there.
- **Copied logic** in the review lists only identical or ≥85% similar groups with no test among them; lower scores are
  usually deliberate variants.
- **CI not on push** isn't reported when the workflow explains in a comment why it runs on pull requests only.
- `http://*` (an origin wildcard) isn't a plain-HTTP URL.
- A source file containing a lone surrogate character (e.g. `"\ud83d"` in a string) no longer stops the analysis.
- The skill refresh rewrites `SKILL.md` only when its instructions changed, not for a new version number alone, so
  upgrades don't leave a one-line diff in every repository.

## 0.8.0 · 2026-11-24

Staying current in Claude Code.

### Added
- **The skill keeps itself current.** `SKILL.md` records the version that wrote it; any codefactory command run in a
  repository with an older skill rewrites it, so Claude never follows instructions for commands that changed.
- `codefactory update`: upgrades codefactory from GitHub (or `--source`) and refreshes the repository's skill.
- `codefactory skill --hook`: adds a Claude Code session-start hook (`.claude/hooks/codefactory.sh`, registered in
  `.claude/settings.json` alongside existing settings) that installs codefactory if missing, upgrades it at most once
  a day, and refreshes the skill. It never blocks or fails a session.

## 0.7.0 · 2026-11-24

Hardening and documentation for a first wider release.

### Added
- **Dispatch tables** are followed in both languages: `COMMANDS[name][0](args)` and `HANDLERS[key]()` link to every
  function in the table, so command and handler tables no longer look unused or untested.
- **Friendlier errors:** problems a user can fix (an invalid `factory.toml`, a bad layer rule, a missing folder,
  TypeScript not installed) end with a one-line message; unexpected errors say how to get the full traceback.
  New global `--debug` flag (or `CODEFACTORY_DEBUG=1`).
- `codefactory --help` shows examples.
- Documentation: a rewritten README with screenshots, a [usage guide](docs/USAGE.md), a [design document](docs/DESIGN.md),
  and a contributor guide.
- Lint and format checks (ruff) in CI.

### Changed
- **Import loops count only imports that run at load time.** Imports inside functions and under `TYPE_CHECKING`
  (often placed there to break a loop), and `require()` inside functions, no longer create loops. On pip's source
  this removed a false 67-file loop.
- **Zones:** when one inferred zone holds most of the code (`pkg/_internal/…`), it's split by the next folder level.
- A search in a list written out in the code (`["a", "b"].includes(x)`) is no longer reported as O(n²).
- The viewer zooms to a traced function's reach (or centres on the function when its reach is too spread out), and
  the side panel opens at the top after each selection.
- One shared definition of "test file" and "script" across all checks.

### Fixed
- Two dead helpers and a duplicated function in codefactory itself, found by running its own review.

## 0.6.1 · 2026-11-24

### Fixed (false positives found using it on a real React Native app)
- Calls in loops over a list fixed in the code (literals, constants, `Object.entries(CONST)`, destructured constant
  pieces, `range(N)`, `.slice(0, N)`) and in migrations are info, not warn; searches and awaits in them aren't reported.
- Methods frameworks call by name (React lifecycle, web components, Angular, Django/DRF) are never unused.
- Lazy `require()` / `import()` is followed, including the `as`-cast destructuring form.

## 0.6.0 · 2026-11-23

### Added
- `codefactory sarif`: SARIF 2.1.0 for GitHub code scanning and VS Code, with rules, security severities, related
  locations, stable fingerprints, suppressions and baseline state.
- `--github` on `flags` and `check`: GitHub Actions annotations on pull requests, without code scanning.

## 0.5.0 · 2026-11-23

### Added
- `codefactory review`: a technical review report (summary, health grade, system map, findings by severity, what's
  working, gaps, questions, limits) with security, reliability, testing and delivery checks.
- `--for-ai`: an evidence pack with the riskiest functions' code, for an AI to finish the judgement calls.

## 0.4.0 · 2026-11-23

### Added
- `codefactory plan` and `prompt`: ranked tasks with steps, tests and a ready-to-paste prompt each; **Copy fix
  prompt** in the viewer.
- Silencing by comment (`codefactory: ignore <kind> — why`) or `[[silence]]` in `factory.toml`.
- `codefactory baseline` and `check`: fail CI only on new issues.

### Fixed
- Same-shaped functions with different SQL or messages are no longer reported as duplicates.

## 0.3.0 · 2026-11-23

### Added
- Calls in loops (N+1), near-duplicates (MinHash), searches and awaits in loops.
- Lenses in the viewer: duplication, efficiency, size.
- `brief`, `context`, `--json`, the Claude Code skill installer, and the analysis cache.

## 0.2.0 · 2026-11-23

### Added
- The TypeScript/JavaScript analyzer, using the project's own TypeScript compiler.
- The readable zoom-out: halls with summary cards and one conveyor per pair of halls.

## 0.1.0 · 2026-11-23

First version: the Python analyzer, issue flags (import loops, layer rules, duplicates, unused code, hubs, sizes),
the factory-floor viewer, SQL export and queries, `trace` and `path`.
