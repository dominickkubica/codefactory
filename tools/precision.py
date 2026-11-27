"""Precision on real code, per check: how often a reported location is right, measured on the corpus.

    python tools/precision.py sample [--per-check 25] [--per-repo 3]   add unlabeled samples to the labels file
    python tools/precision.py batch OUT.md [--checks a,b] [--limit 60]  unlabeled samples with code around each, to label
    python tools/precision.py merge FILE.json ...                       take labels written by a reviewer
    python tools/precision.py score                                     precision per check against the current exports
    python tools/precision.py report                                    score, and rewrite the table in docs/ACCURACY.md

The unit is one location of one finding (`file:line` plus the check), read from the corpus exports that
`tools/corpus.py run` writes. `sample` picks up to --per-check locations per check, at most --per-repo from any one
repository so no project dominates, spread over severities and kept stable between runs (a hash, not a random
draw). Each sample goes into `tools/corpus/labels.json` with `label: null`; a person (or a reviewer working to the
rubric in docs/ACCURACY.md) sets it to `true` (the claim is right: the thing it describes is there and is worth the
look the finding asks for), `false` (the claim is wrong about this code) or `unsure`, with a one-line `why`.

`score` reads the labels against the exports as they are now. A labeled location that's still reported counts
toward precision; one that's gone is reported separately: a false one that disappeared is a fix, a true one that
disappeared is lost recall. Precision is shown with a 95% Wilson interval, which is honest about small samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from corpus import CACHE, HERE, repos  # noqa: E402

LABELS = HERE / "labels.json"
ACCURACY = ROOT / "docs" / "ACCURACY.md"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# claims that are true by construction (a count, a missing file, a version string): nothing to measure
MECHANICAL = re.compile(
    r"^(?:Very long function|Runtime version not pinned|No README|README doesn't say|No lockfile|No automated tests|"
    r"No continuous integration|CI doesn't run on pushes|Container base image not pinned|Third-party CI actions not "
    r"pinned|Unpinned Python requirements|Dependencies on moving targets|Dependencies against the layer order)"
)
AT = re.compile(r"`([^`\s]+?):(\d+)`")


def check_of(title: str) -> str:
    """The check a finding comes from: its title without the counts ("Import loops (N)")."""
    t = re.sub(r"(?<![\w-])\d+(?!\w)", "N", title)  # counts, not MD5 / SHA-1 / RC4
    t = re.sub(r"\b(function|group|place|error|flow)s\b", r"\1", t)
    return re.sub(r"\(N\+N\)", "(N)", t)


def where(location: str) -> tuple[str, int] | None:
    m = AT.search(location)
    return (m.group(1), int(m.group(2))) if m else None


def key(repo: str, check: str, location: str) -> str:
    at = where(location)
    spots = AT.findall(location)
    if len(spots) > 1:  # a group (copies): the same group whichever member is listed first
        spot = min(f"{f}:{n}" for f, n in spots)
    elif at:
        spot = f"{at[0]}:{at[1]}"
    elif " → " in location:  # a loop: its first file (the chain shown after it may change as the check improves)
        spot = location.split(" → ")[0].strip()
    else:
        spot = re.sub(r"\d+", "N", location)[:200]
    return f"{repo}|{check}|{spot}"


def exports() -> dict[str, dict]:
    """repo -> export, for the corpus repositories that have one."""
    out = {}
    for repo in repos():
        path = CACHE / "exports" / f"{repo.replace('/', '__')}.json"
        if path.exists():
            out[repo] = json.loads(path.read_text(encoding="utf-8"))
    return out


def reported() -> dict[str, dict]:
    """Every location reported now: key -> {repo, check, severity, location}."""
    out = {}
    for repo, doc in exports().items():
        for f in doc["findings"]:
            check = check_of(f["title"])
            if MECHANICAL.match(check):
                continue
            for loc in f["locations"]:
                if loc.startswith("…and "):
                    continue
                out.setdefault(key(repo, check, loc), {"repo": repo, "check": check, "severity": f["severity"], "location": loc})
    return out


def load() -> dict:
    return json.loads(LABELS.read_text(encoding="utf-8")) if LABELS.exists() else {}


def save(labels: dict) -> None:
    LABELS.write_text(json.dumps(dict(sorted(labels.items())), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _stable(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sample(args) -> int:
    labels, now = load(), reported()
    by_check: dict[str, list[str]] = defaultdict(list)
    for k, hit in now.items():
        by_check[hit["check"]].append(k)
    added = 0
    for check, keys in sorted(by_check.items()):
        have = [k for k in keys if k in labels]
        want = args.per_check - len(have)
        if want <= 0:
            continue
        per_repo: dict[str, int] = defaultdict(int)
        for k in have:
            per_repo[now[k]["repo"]] += 1
        # the more serious first, then a stable shuffle; at most --per-repo from one repository
        order = sorted((k for k in keys if k not in labels),
                       key=lambda k: (SEVERITIES.index(now[k]["severity"]) > 2, _stable(k)))  # fmt: skip
        for k in order:
            if want <= 0:
                break
            hit = now[k]
            if per_repo[hit["repo"]] >= args.per_repo:
                continue
            per_repo[hit["repo"]] += 1
            labels[k] = {**hit, "label": None, "why": ""}
            want -= 1
            added += 1
    save(labels)
    todo = sum(1 for v in labels.values() if v["label"] is None)
    print(f"{added} added; {len(labels)} samples, {todo} to label, over {len({v['check'] for v in labels.values()})} checks")
    return 0


def _code(repo: str, file: str, line: int, around: int) -> str:
    path = CACHE / repo.replace("/", "__") / file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(file not readable)"
    lo, hi = max(0, line - 1 - around), min(len(lines), line + around)
    return "\n".join(f"{'>' if i + 1 == line else ' '}{i + 1:5} {lines[i][:200]}" for i in range(lo, hi))


def batch(args) -> int:
    labels = load()
    wanted = set(args.checks.split("|")) if args.checks else None
    todo = [(k, v) for k, v in sorted(labels.items(), key=lambda kv: (kv[1]["check"], kv[0]))
            if v["label"] is None and (wanted is None or v["check"] in wanted)][: args.limit]  # fmt: skip
    out = []
    for k, v in todo:
        out.append(f"### {k}\n\nCheck: {v['check']} ({v['severity']})  \nRepository checkout: "
                   f"`{CACHE / v['repo'].replace('/', '__')}`  \nReported: {v['location']}\n")  # fmt: skip
        at = where(v["location"])
        if at:
            out.append("```\n" + _code(v["repo"], at[0], at[1], args.around) + "\n```\n")
    Path(args.out).write_text("\n".join(out), encoding="utf-8")
    print(f"{len(todo)} samples written to {args.out}")
    return 0


def merge(args) -> int:
    """Take labels from JSON files ({key: {label, why}}), e.g. written by reviewers working through `batch` output."""
    labels = load()
    # keys as `batch` wrote them, before a change to how keys are made: map them through the stored location
    old = {f"{v['repo']}|{v['check']}|{re.sub(r'[0-9]+', 'N', v['location'])[:200]}": k for k, v in labels.items()}
    taken = unknown = 0
    for path in args.files:
        for k, v in json.loads(Path(path).read_text(encoding="utf-8")).items():
            k = k if k in labels else old.get(k, k)
            if k not in labels:
                unknown += 1
                continue
            if v.get("label") in ("true", "false", "unsure"):
                labels[k]["label"], labels[k]["why"] = v["label"], v.get("why", "")
                taken += 1
    save(labels)
    print(f"{taken} labels taken, {unknown} keys not in the labels file")
    return 0


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - r) / d, (c + r) / d


def score(_args=None, quiet: bool = False) -> list[dict]:
    labels, now = load(), reported()
    total = defaultdict(int)
    for hit in now.values():
        total[hit["check"]] += 1
    rows: dict[str, dict] = {}
    for k, v in labels.items():
        r = rows.setdefault(v["check"], {"check": v["check"], "true": 0, "false": 0, "unsure": 0, "todo": 0,
                                         "fixed": 0, "lost": 0, "reported": total.get(v["check"], 0)})  # fmt: skip
        if v["label"] is None:
            r["todo"] += k in now
        elif k not in now:
            r["fixed" if v["label"] == "false" else "lost" if v["label"] == "true" else "unsure"] += v["label"] != "unsure"
        else:
            r[v["label"]] += 1
    out = []
    for r in rows.values():
        n = r["true"] + r["false"]
        r["n"] = n
        r["precision"] = r["true"] / n if n else None
        r["low"], r["high"] = wilson(r["true"], n)
        out.append(r)
    out.sort(key=lambda r: (r["precision"] is None, r["precision"] if r["precision"] is not None else 0, -r["n"]))
    if not quiet:
        print(f"{'check':62} {'prec':>5} {'95% interval':>13} {'n':>4} {'fixed':>5} {'lost':>4} {'todo':>4}")
        for r in out:
            p = "  –  " if r["precision"] is None else f"{r['precision']:5.0%}"
            ci = "" if not r["n"] else f"{r['low']:.0%}–{r['high']:.0%}"
            print(f"{r['check'][:62]:62} {p} {ci:>13} {r['n']:4} {r['fixed']:5} {r['lost']:4} {r['todo']:4}")
        k = sum(r["true"] for r in out)
        n = sum(r["n"] for r in out)
        if n:
            print(f"\nall labeled and still reported: {k}/{n} = {k / n:.0%}")
    return out


def report(args) -> int:
    """Rewrite the table in docs/ACCURACY.md: per check, precision when first labeled (every sample was reported then)
    and now (the labeled locations the current code still reports), with what changed in between."""
    rows = score(quiet=True)
    labels = load()
    first: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for v in labels.values():
        if v["label"] in ("true", "false"):
            first[v["check"]][v["label"] == "true"] += 1
    k, n = sum(r["true"] for r in rows), sum(r["n"] for r in rows)
    k0, n0 = sum(c[1] for c in first.values()), sum(c[0] + c[1] for c in first.values())
    fixed, lost = sum(r["fixed"] for r in rows), sum(r["lost"] for r in rows)
    table = [
        f"{n0} locations labeled across {len({v['repo'] for v in labels.values()})} repositories. **First measurement: "
        f"{k0} right ({k0 / n0:.0%}). Now: {k} of the {n} still reported are right ({k / n:.0%})**: the fixes removed "
        f"{fixed} wrong ones and lost {lost} right ones.",
        "",
        "| Check | First measured | Now | 95% interval (now) | Still reported | Wrong removed | Right lost |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for r in sorted(rows, key=lambda r: (-(r["precision"] or 0), -r["n"], r["check"])):
        f_false, f_true = first[r["check"]]
        if f_false + f_true == 0:
            continue
        was = f"{f_true / (f_false + f_true):.0%}"
        now = f"{r['precision']:.0%}" if r["n"] else "–"
        ci = f"{r['low']:.0%}–{r['high']:.0%}" if r["n"] else ""
        table.append(f"| {r['check']} | {was} | {now} | {ci} | {r['n']} | {r['fixed']} | {r['lost']} |")
    text = ACCURACY.read_text(encoding="utf-8")
    start, end = "<!-- precision:start -->", "<!-- precision:end -->"
    if start not in text:
        print(f"{ACCURACY} has no {start} marker")
        return 1
    head, rest = text.split(start, 1)
    ACCURACY.write_text(head + start + "\n" + "\n".join(table) + "\n" + end + rest.split(end, 1)[1], encoding="utf-8")
    print(f"docs/ACCURACY.md: first {k0}/{n0} = {k0 / n0:.0%}; now {k}/{n} = {k / n:.0%}; {fixed} wrong removed, {lost} right lost")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--per-check", type=int, default=25)
    s.add_argument("--per-repo", type=int, default=3)
    b = sub.add_parser("batch")
    b.add_argument("out")
    b.add_argument("--checks", default=None, help="check names separated by |")
    b.add_argument("--limit", type=int, default=60)
    b.add_argument("--around", type=int, default=12)
    m = sub.add_parser("merge")
    m.add_argument("files", nargs="+")
    sub.add_parser("score")
    sub.add_parser("report")
    args = p.parse_args(argv)
    return {"sample": sample, "batch": batch, "merge": merge, "score": lambda a: (score(a), 0)[1], "report": report}[args.cmd](
        args
    )


if __name__ == "__main__":
    raise SystemExit(main())
