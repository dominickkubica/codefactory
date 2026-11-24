---
name: codefactory
description: Map this codebase's structure (layers, who calls what) and find copied code, database/network calls inside loops (N+1), dead code, import loops, and security, reliability and delivery problems. Use before restructuring, deduplicating or optimizing; when asked to review the codebase; before changing or deleting a function or file (to see callers, impact and which tests to run); and when debugging how one part reaches another.
---

# codefactory

`codefactory` statically analyzes this repo (Python, TypeScript/JavaScript) into a call graph and lists issues with
`file:line`. The first run takes a few seconds to ~30 s; later runs reuse `.codefactory/graph.json` until a source
file changes. Run it from the repo root. If the command isn't found, use `python -m codefactory`; if it isn't
installed at all, `pip install git+https://github.com/dominickkubica/codefactory`. If a command below is missing or
an option is rejected, run `codefactory update` (this file refreshes itself to match the installed version).

## When to use which command

| Situation | Command |
|---|---|
| Starting a restructure, cleanup or performance pass | `codefactory brief` (layers, most-used code, issues grouped by what to do, copied-code groups with lines saved) |
| Asked to review the codebase (architecture, security, reliability, quality) | `codefactory review --for-ai`, then confirm or reject each finding from its cited lines and judge the risky code it includes; read other files only when a finding needs it |
| Deciding what to work on | `codefactory plan` (ranked tasks with steps and tests); `codefactory prompt <id or rank>` prints one task as a full brief to follow |
| About to change, move, rename or delete a function or file | `codefactory context <name or path>` (callers, what it calls, how many functions/files depend on it, tests that exercise it) |
| Debugging: what does X eventually do? | `codefactory trace <function>` |
| Debugging: how does A end up calling B? | `codefactory path <A> <B>` |
| A list to work through | `codefactory flags --kind similar --kind duplicate`, `--kind io_in_loop`, `--min warn`; add `--json` to parse |
| Any other question | `codefactory query "SELECT … FROM function_stats …"` (tables files, functions, edges, flags; views function_stats(fan_in, fan_out, caller_files), file_deps) |
| Showing the human | `codefactory view -o <file>.html` (an interactive factory-floor map; lenses for duplication, efficiency, size) |

## Working rules

1. **Check impact before editing.** Run `context` on what you'll change. If it has many callers or a large impact,
   keep its signature, or update every caller it lists.
2. **Copied code (`duplicate`, `similar`).** Merge into one function in the lowest layer that all copies' callers can
   import (usually `lib`/`utils`), then point each copy's callers at it. `brief` lists groups by lines saved.
3. **Calls in loops (`io_in_loop`).** `warn` = reads or network: replace the per-item call with one batched query
   (`WHERE id IN (…)`, a JOIN) or one request. `info` = writes/files: batch only if many items; keep them in one
   transaction.
4. **`unused` and `test_only` are hints, not proof.** Frameworks call some code by name (routes, handlers, exports
   loaded by convention). Search for the name (including strings) before deleting.
5. **Static analysis misses dynamic calls** (getattr, callbacks stored in variables, untyped `obj.method()`). Treat
   "no callers" as "no callers found".
6. **After changing, verify.** Run `codefactory check` if the repo has a `codefactory-baseline.json` (it fails on
   issues your change introduced), otherwise re-run `codefactory flags --min warn` and compare with before. Run the
   tests `context` (or the task) listed, plus the project's test command.
7. **An issue that's intended** (a bounded loop, a deliberate copy, code a framework calls by name): don't contort the
   code. Add a comment on the line above the function or the flagged line, saying why:
   `// codefactory: ignore io_in_loop — one query per table, there are 7` (or `# …` in Python). It moves to
   `codefactory flags --silenced` with its reason.
8. **Don't update the baseline yourself** (`codefactory baseline`) unless the user asks: it's the line that new
   issues are measured against.

## Interpreting severities

- `high`: import loops, layer violations (from `factory.toml`). Fix.
- `warn`: copies, N+1 loops, dead code. Worth fixing while working nearby.
- `info`: long functions, hubs, searches/awaits in loops, writes in loops. Context for decisions.
