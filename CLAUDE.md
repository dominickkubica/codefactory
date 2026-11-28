# codefactory

Static analysis for codebases, measured for precision on a labeled corpus of public repositories. Python 3.11+, no
runtime dependencies beyond the standard library and the optional language pack.

Read `CONTRIBUTING.md` before changing anything: its **Cardinal rules** section is binding for every change, and
**Standards** covers style. The short version:

- `python tools/gate.py` before anything reaches `main` (golden diff, right findings kept, CI); add `--corpus` for a
  graph check (loops, unused/untested code). Work in progress goes to a branch.
- A rule states a fact about a language or protocol, never one repository's habit, and ships with at least a test pair.
- Fixes come from the labeled rounds; held-out rounds are frozen and measured before/after (`tools/heldout.py`).
- Labels are blind and never changed after the score is seen.
- Nothing under `codefactory/` changes while a corpus run is going.
- Slow is a bug: a timeout or a run over its budget (`tools/speed.py`) is fixed before other work.
- Ask before a version bump (it publishes to PyPI). No secret-shaped strings in tests: split them (`"sk_" + "live_"`).

Where things are: `CONTRIBUTING.md` ("Where things live"); how precision is measured: `docs/ACCURACY.md`.
