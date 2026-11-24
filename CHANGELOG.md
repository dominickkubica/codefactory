# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); before 1.0, minor versions may
change command-line output.

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
