"""Leaving test code out of the results: `--no-tests`, or `tests = false` in factory.toml.

Tests are analyzed as always (they're how codefactory knows what's tested), then removed from what's shown: their
files, functions and edges leave the map, and findings in them (or copies whose only other copies are tests) leave
the findings and the plan. What they reach is kept in the graph as `tests`, so the review's coverage still counts
them and doesn't say the repository has no tests.
"""

from __future__ import annotations

from .paths import is_test

COPIES = ("duplicate", "similar")


def without_tests(graph: dict) -> dict:
    test_files = [f["id"] for f in graph["files"] if is_test(f["id"])]
    if not test_files:
        return graph
    from .brief import View
    from .checks import test_reach

    reached = sorted(test_reach(View(graph)))
    test_fns = {f["id"] for f in graph["functions"] if is_test(f["file"])}
    hidden = set(test_files) | test_fns

    def kept(flag: dict) -> bool:
        if flag["target"] in hidden or is_test(flag["target"].split("::")[0]):
            return False
        if flag["kind"] in COPIES:  # a copy of test code only: nothing to merge in the product
            return any(r not in hidden for r in flag.get("related", []))
        return True

    return {
        **graph,
        "files": [f for f in graph["files"] if f["id"] not in hidden],
        "functions": [f for f in graph["functions"] if f["id"] not in test_fns],
        "edges": [e for e in graph["edges"] if e["src"] not in hidden and e["dst"] not in hidden],
        "sites": [s for s in graph.get("sites", []) if s.get("fn") not in test_fns],
        "flags": [f for f in graph["flags"] if kept(f)],
        "tests": {"files": test_files, "reached": [r for r in reached if r not in test_fns]},
    }
