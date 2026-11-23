# codefactory

See a codebase as a top-down factory floor, then use it to find what's wrong: dead code, copy-pasted functions,
import loops, layer violations, oversized files and hubs everything depends on.

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

Needs Python 3.11+. No dependencies.

```bash
pip install git+https://github.com/<you>/codefactory      # or, from a clone: pip install -e .

codefactory view path/to/repo        # writes factory.html and opens it in your browser
codefactory flags path/to/repo       # issues in the terminal
codefactory analyze path/to/repo -o repo.graph.json      # the raw graph, for other tools
codefactory flags path/to/repo --fail-on high            # exit 1 on any high-severity issue (CI)
```

`python -m codefactory …` works the same without installing. The HTML page is self-contained: no server, no
network, so it can be emailed or attached to a PR.

**In the viewer:** drag to pan, scroll to zoom, `f` to fit. Hover a machine to see only its belts; click it for its
functions (lines, callers, callees), issues and neighbours. **Calls / Imports** switches what the belts show. The
Issues tab filters by kind; clicking an issue flies to its machine.

## What it flags

| Issue | Severity | Meaning |
|---|---|---|
| Import loop | high | Files that import each other in a circle (Tarjan's algorithm on the import graph) |
| Layer violation | high | An import your `factory.toml` forbids, e.g. `ui -> db` |
| Duplicate | warn | Functions with the same structure, even with renamed variables (≥ 6 lines, not one-liners) |
| Unused | warn / info | Functions nothing calls or references. Methods are only "info", and skipped when their name is used as `obj.name` anywhere |
| Hub | info | A function called from 12+ files: change it carefully |
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

Analysis is static (nothing is run), so the graph is a good approximation, not the truth:

- **Resolved:** plain calls, imported names (absolute and relative, through package re-exports), `module.func()`,
  `self.method()`, `cls.method()`, `ClassName()` (to `__init__`), and functions passed by name (callbacks).
- **Not resolved:** calls through variables, `getattr`, dependency injection, or most `obj.method()` where `obj`'s type
  isn't known. Those methods are protected from false "unused" reports, but their belts don't show.
- Decorated functions, `__all__` names, `main`, dunders and tests are treated as entry points and never "unused".

Speed is about 15 ms per file (a 1,000-file repo maps in ~15 s).

## Layout

```
codefactory/
  analyzers/python.py   Python → graph (stdlib ast). Add a language by adding a module and registering it
  graph.py              The language-neutral graph (files, functions, edges, flags)
  layers.py             Zones and their order
  flags.py              Issue detectors (read only the graph, so they work for every language)
  config.py             factory.toml
  viewer/               The factory page (canvas, no libraries), inlined into one HTML file
  cli.py                analyze / flags / view
tests/                  unittest; fixtures/shop is a small app with planted problems
```

## Roadmap

- **TypeScript / JavaScript analyzer** (TypeScript compiler API), then more languages via tree-sitter.
- **Live traffic:** load OpenTelemetry traces or a small Python profiler so real calls move along the belts and slow or
  repeated calls (N+1) pile up visibly.
- **Agent view:** a Claude Code hook that logs which files each AI session reads and edits, shown as workers walking
  the floor.
- Function-level drill-down (a machine opens into its own little line of functions).
- Near-duplicate detection (similar, not identical, structure).
