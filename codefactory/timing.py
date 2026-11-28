"""Where a run's time goes, phase by phase.

`with phase("review.scan_sources"): …` adds the time spent to that phase; `report()` returns them all, slowest first.
`CODEFACTORY_TIMINGS=1` prints them when a command ends, and `tools/corpus.py` and `tools/speed.py` keep them per
repository, so a slow phase is seen when it appears instead of after it has cost hours (CONTRIBUTING.md, rule 11).
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

TIMES: dict[str, float] = {}


@contextmanager
def phase(name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        TIMES[name] = TIMES.get(name, 0.0) + time.perf_counter() - start


def reset() -> None:
    TIMES.clear()


def report() -> dict[str, float]:
    """Seconds per phase, slowest first (phases nest: `build` includes `build.typescript`)."""
    return {k: round(v, 2) for k, v in sorted(TIMES.items(), key=lambda kv: -kv[1])}


def print_if_asked() -> None:
    if os.environ.get("CODEFACTORY_TIMINGS") and TIMES:
        width = max(map(len, TIMES))
        print("codefactory timings:", file=sys.stderr)
        for name, seconds in report().items():
            print(f"  {name:{width}}  {seconds:7.2f} s", file=sys.stderr)
