"""Accuracy benchmark: run every line-level check, the efficiency checks and data flow over a labeled corpus
(tests/fixtures/bench, ground truth in its expect.txt) and report precision and recall per check.

    python -m tests.bench            print the table
    python -m tests.bench --write    also rewrite the table in docs/ACCURACY.md

A finding matches a label when the file, the line and the check agree. Anything reported and not labeled expected is
a false positive. tests/test_bench.py fails on any new false alarm or miss, or below the floors in tests/fixtures/bench/floors.json.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CORPUS = Path(__file__).parent / "fixtures" / "bench"
GRAPH_KINDS = ("io_in_loop", "quadratic_scan", "sequential_await", "taint")
SKIP = {"swallowed_ok", "hosts", "error_boundary", "module_state"}  # bookkeeping, or not about correctness


def labels() -> tuple[set[tuple[str, int, str]], set[tuple[str, int, str]]]:
    """(expected, look-alikes) as (file, line, kind)."""
    expected, traps = set(), set()
    for raw in (CORPUS / "expect.txt").read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        file, kind, text = (p.strip() for p in raw.split(" | ", 2))
        lines = (CORPUS / file).read_text(encoding="utf-8").splitlines()
        at = [i for i, ln in enumerate(lines, 1) if text in ln]
        if len(at) != 1:
            raise ValueError(f"expect.txt: {text!r} is on {len(at)} lines of {file}, not one")
        (traps if kind.startswith("~") else expected).add((file, at[0], kind.lstrip("~")))
    return expected, traps


def findings() -> set[tuple[str, int, str]]:
    from codefactory.apple import scan as apple_scan
    from codefactory.audit import scan_config
    from codefactory.checks import _scan
    from codefactory.cli import build
    from codefactory.privacy import scan as privacy_scan

    files = sorted(
        p.relative_to(CORPUS).as_posix()
        for p in CORPUS.rglob("*")
        if p.is_file() and ".codefactory" not in p.parts and p.name != "expect.txt" and p.suffix != ".json"
    )
    out: set[tuple[str, int, str]] = set()
    for scan in (_scan(CORPUS, files), privacy_scan(CORPUS, files), apple_scan(CORPUS, files), scan_config(CORPUS)):
        for key, check in scan.items():
            if key not in SKIP:
                out |= {(e.file, e.line, key) for e in check.hits}
    g = build(CORPUS, cache=False)
    fn_file = {f.id: f.file for f in g.functions}
    for flag in g.flags:
        if flag.kind in GRAPH_KINDS and not flag.detail.endswith(":fixed"):  # a fixed list is correctly not a problem
            out.add((fn_file.get(flag.target, flag.target.split("::")[0]), flag.line, flag.kind))
    return out


def score(part: str | None = None, got: set | None = None) -> dict[str, dict]:
    """Per check, for the whole corpus or one part: "tuning" (checks were fixed against it) or "holdout" (written
    after those fixes and measured without tuning)."""
    expected, traps = labels()
    got = findings() if got is None else got
    if part:
        keep = (lambda f: f.startswith("holdout/")) if part == "holdout" else (lambda f: not f.startswith("holdout/"))
        expected, traps, got = ({x for x in s if keep(x[0])} for s in (expected, traps, got))
    kinds = sorted({k for *_, k in expected | traps | got})
    rows = {}
    for k in kinds:
        e = {x for x in expected if x[2] == k}
        g = {x for x in got if x[2] == k}
        tp, fp, fn = len(e & g), len(g - e), len(e - g)
        rows[k] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "traps": sum(1 for x in traps if x[2] == k),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "missed": sorted(f"{f}:{ln}" for f, ln, _ in e - g),
            "wrong": sorted(f"{f}:{ln}" for f, ln, _ in g - e),
        }
    return rows


def _pct(x: float | None) -> str:
    return "–" if x is None else f"{x:.0%}"


def table(rows: dict[str, dict]) -> str:
    tp = sum(r["tp"] for r in rows.values())
    fp = sum(r["fp"] for r in rows.values())
    fn = sum(r["fn"] for r in rows.values())
    out = [
        "| Check | Found | Missed | False alarms | Look-alikes | Precision | Recall |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for k, r in rows.items():
        out.append(f"| `{k}` | {r['tp']} | {r['fn']} | {r['fp']} | {r['traps']} | {_pct(r['precision'])} | {_pct(r['recall'])} |")
    out.append(
        f"| **All** | **{tp}** | **{fn}** | **{fp}** | **{sum(r['traps'] for r in rows.values())}** | "
        f"**{_pct(tp / (tp + fp) if tp + fp else None)}** | **{_pct(tp / (tp + fn) if tp + fn else None)}** |"
    )
    return "\n".join(out)


def main(argv: list[str]) -> int:
    got = findings()
    parts = {p: score(p, got) for p in ("tuning", "holdout")}
    for name, rows in parts.items():
        print(f"\n{name}\n" + table(rows))
        for k, r in rows.items():
            for where in r["missed"]:
                print(f"  missed  {k:22} {where}")
            for where in r["wrong"]:
                print(f"  wrong   {k:22} {where}")
    rows = score(None, got)
    if "--write" in argv:
        doc = Path(__file__).parent.parent / "docs" / "ACCURACY.md"
        text = doc.read_text(encoding="utf-8")
        for name, part in parts.items():
            text = re.sub(
                rf"(<!-- bench:{name}:start -->\n).*?(<!-- bench:{name}:end -->)",
                lambda m, part=part: m.group(1) + table(part) + "\n" + m.group(2),
                text,
                flags=re.S,
            )
        doc.write_text(text, encoding="utf-8")
    if "--json" in argv:
        print(json.dumps({k: {x: r[x] for x in ("tp", "fp", "fn")} for k, r in rows.items()}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
