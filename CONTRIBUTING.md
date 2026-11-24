# Contributing

Thanks for helping. This page covers setting up, the standards a change has to meet, and where things live. The
[design document](docs/DESIGN.md) explains how codefactory works and how to add a language or a check.

## Setting up

```bash
git clone https://github.com/dominickkubica/codefactory
cd codefactory
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
npm install -g typescript                          # so the TypeScript tests run
pip install ruff
```

## Before every change is merged

```bash
python -m unittest discover -s tests -t .   # all tests pass (TypeScript tests skip without Node + typescript)
ruff check codefactory tests                 # no lint findings
ruff format --check codefactory tests        # formatted
codefactory check .                          # codefactory finds nothing serious in itself
```

CI runs the same on Linux and Windows with Python 3.11 and 3.13.

## Standards

- **No new runtime dependencies.** codefactory installs anywhere Python 3.11 does; keep it that way.
- **Every check has tests both ways:** a fixture where it should fire, and a look-alike where it shouldn't.
- **A false positive gets a regression test before its fix.** Most of codefactory's accuracy came from fixing what it
  got wrong on real codebases.
- **Prefer missing a problem to inventing one** for anything that suggests deleting or rewriting code, and label
  findings that are hints as hints.
- **Every finding points at a `file:line`** and says what to do about it, in plain words.
- **User-facing errors are one line** that says what went wrong and how to fix it; no tracebacks unless `--debug`.
- **Document thresholds** you add or change in `docs/DESIGN.md`, with why that value.
- Code style: ruff's defaults with a 130-character line; type hints on public functions; docstrings that say what
  and why, not how.

## Where things live

| Path | What |
|---|---|
| `codefactory/analyzers/` | One analyzer per language, producing the graph |
| `codefactory/flags.py`, `similar.py`, `efficiency.py` | Checks on the graph |
| `codefactory/checks.py`, `review.py` | Source-text and repository checks; the review |
| `codefactory/plan.py`, `brief.py`, `sarif.py`, `trace.py`, `sqlgraph.py` | Outputs |
| `codefactory/viewer/` | The HTML map: `template.html`, `factory.css`, `factory.js` |
| `tests/fixtures/shop`, `tests/fixtures/tsapp` | Small Python and TypeScript apps with planted problems |
| `docs/` | Usage guide, design document, screenshots |

## Releasing

1. Update `version` in `pyproject.toml` and `__version__` in `codefactory/__init__.py`.
2. Add a section to `CHANGELOG.md`.
3. Merge to `main` with CI green. `pip install --upgrade git+…` picks up the new version.
