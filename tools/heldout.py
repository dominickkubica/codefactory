"""Held-out before/after: does a round of fixes carry to repositories nobody tuned against?

    python tools/heldout.py run --round 8 --as base --ref v0.23.0    analyze the round's repositories with the code at
                                                                     a git ref (a temporary worktree)
    python tools/heldout.py run --round 8 --as after                 ... with the working tree
    python tools/heldout.py sample --round 8 [--per-check 12]        add unlabeled locations, drawn from both versions
    python tools/heldout.py score --round 8                          precision before and after, per check and overall

A round's repositories are the block in `tools/corpus/repos.txt` under `# Round N`. They are drawn before the round's
fixes start and not read while making them; the fixes come from the earlier rounds' labels. Both versions analyze the
same commits. The sample is drawn from the union of what either version reports, without saying which, so whoever
labels it can't favor one; each version's precision is then read from the labeled locations it reports. Overall
precision weights each check by how many locations that version reports, which is what a reader of the report sees.
Labels go into `tools/corpus/labels.json` with the round number, like every other round.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from corpus import CACHE, HERE, checkout, export_with, share_memory  # noqa: E402
from precision import MECHANICAL, VULNERABLE_BY_DESIGN, check_of, key, load, save, stable, wilson  # noqa: E402

LIMIT = 900


def round_repos(n: int) -> list[str]:
    out, inside = [], False
    for line in (HERE / "repos.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            inside = line.lower().startswith(f"# round {n}:") or (inside and not line.lower().startswith("# round "))
            continue
        name = line.split("#", 1)[0].strip()
        if inside and name:
            out.append(name)
    return out


def folder(n: int, version: str) -> Path:
    return CACHE / "heldout" / f"round{n}" / version


def run(args) -> int:
    names = round_repos(args.round)
    if args.only:  # (one run again: a timeout caused by a busy machine, not by the code)
        names = [n for n in names if n in args.only.split(",")]
    code, tmp = ROOT, None
    if args.ref:
        tmp = CACHE / "heldout" / f"code-{args.as_}"
        if tmp.exists():
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(tmp)], capture_output=True)
            shutil.rmtree(tmp, ignore_errors=True)
        subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(tmp), args.ref], check=True)
        code = tmp
    out = folder(args.round, args.as_)
    out.mkdir(parents=True, exist_ok=True)

    def one(repo: str) -> str:
        path = checkout(repo)
        dest = out / f"{repo.replace('/', '__')}.json"
        prof = out / f"{repo.replace('/', '__')}.profile.json"
        try:
            done = export_with(code, path, dest, prof, timeout=LIMIT)
        except subprocess.TimeoutExpired:
            return f"{repo}: timeout"
        return f"{repo}: {'ok' if done.returncode == 0 else 'crash ' + done.stderr[-200:]}"

    jobs = args.jobs or os.cpu_count() or 2
    share_memory(jobs)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for line in pool.map(one, names):
            print(line, flush=True)
    if tmp:
        subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(tmp)], capture_output=True)
    return 0


def finished(n: int, version: str) -> set[str]:
    folder_ = folder(n, version)
    return {p.name for p in folder_.glob("*.json") if not p.name.endswith(".profile.json")} if folder_.exists() else set()


def reported(n: int, version: str) -> dict[str, dict]:
    """key -> {repo, check, severity, location, counted} for everything this version reported on the round, on the
    repositories both versions finished: one that timed out before a fix and finishes after it would otherwise add
    locations to one side only."""
    out = {}
    both = finished(n, "base") & finished(n, "after")
    for path in sorted(folder(n, version).glob("*.json")):
        if path.name not in both:
            continue
        repo = path.stem.replace("__", "/", 1)
        doc = json.loads(path.read_text(encoding="utf-8"))
        for tier in ("findings", "hints"):
            for f in doc.get(tier, []):
                check = check_of(f["title"])
                if MECHANICAL.match(check):
                    continue
                for loc in f["locations"]:
                    if not loc.startswith("…and "):
                        row = {
                            "repo": repo,
                            "check": check,
                            "severity": f["severity"],
                            "location": loc,
                            "counted": tier == "findings",
                        }
                        out.setdefault(key(repo, check, loc), row)
    return out


def sample(args) -> int:
    labels = load()
    base, after = reported(args.round, "base"), reported(args.round, "after")
    union = {**after, **base}
    by_check: dict[str, list[str]] = defaultdict(list)
    for k, v in union.items():
        if v["repo"] not in VULNERABLE_BY_DESIGN:
            by_check[v["check"]].append(k)
    added = 0
    for check, keys in sorted(by_check.items()):
        have = [k for k in keys if k in labels]
        want = args.per_check - len(have)
        per_repo: dict[str, int] = defaultdict(int)
        for k in have:
            per_repo[union[k]["repo"]] += 1
        for k in sorted((k for k in keys if k not in labels), key=stable):
            if want <= 0:
                break
            if per_repo[union[k]["repo"]] >= args.per_repo:
                continue
            per_repo[union[k]["repo"]] += 1
            v = union[k]
            labels[k] = {"repo": v["repo"], "check": check, "severity": v["severity"], "location": v["location"],
                         "label": None, "why": "", "round": args.round}  # fmt: skip
            want -= 1
            added += 1
    save(labels)
    print(f"{added} added to round {args.round}; `precision.py batch OUT.md --round {args.round}` writes them for labeling")
    return 0


def score(args) -> int:
    labels = {k: v for k, v in load().items() if v.get("round") == args.round and v["label"] in ("true", "false")}
    versions = {"base": reported(args.round, "base"), "after": reported(args.round, "after")}
    rows: dict[str, dict] = defaultdict(lambda: {"base": [0, 0, 0], "after": [0, 0, 0], "counted": {}})
    for version, now in versions.items():
        for k, v in now.items():
            r = rows[v["check"]]
            r[version][2] += 1  # locations reported
            r["counted"][version] = v["counted"]
            if k in labels:
                r[version][0] += labels[k]["label"] == "true"
                r[version][1] += 1
    print(f"{'check':58} {'base':>14} {'after':>14}")
    total = {"base": [0.0, 0, 0, 0], "after": [0.0, 0, 0, 0]}  # weighted right, reported, labeled right, labeled
    for check, r in sorted(rows.items(), key=lambda kv: -kv[1]["base"][2]):
        cells = []
        for version in ("base", "after"):
            right, n, reported_n = r[version]
            counted = r["counted"].get(version)
            mark = "" if counted else "h"
            cells.append(f"{right}/{n} of {reported_n}{mark}".rjust(14) if reported_n else "–".rjust(14))
            if counted and n:
                total[version][0] += reported_n * right / n
                total[version][1] += reported_n
                total[version][2] += right
                total[version][3] += n
        print(f"{check[:58]:58} {cells[0]} {cells[1]}")
    print("\n(right/labeled of reported; h = shown as a hint, not counted)")
    for version in ("base", "after"):
        w, n, k, m = total[version]
        lo, hi = wilson(k, m) if m else (0, 0)
        print(f"{version:5}: counted precision {k}/{m} = {k / max(m, 1):.0%} as sampled ({lo:.0%}–{hi:.0%}), "
              f"{w / max(n, 1):.0%} weighted by locations reported ({n:.0f} counted locations)")  # fmt: skip
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--round", type=int, required=True)
    r.add_argument("--as", dest="as_", choices=("base", "after"), required=True)
    r.add_argument("--ref")
    r.add_argument("--jobs", type=int)
    r.add_argument("--only", help="owner/repo,...: just these of the round")
    s = sub.add_parser("sample")
    s.add_argument("--round", type=int, required=True)
    s.add_argument("--per-check", type=int, default=12)
    s.add_argument("--per-repo", type=int, default=3)
    sc = sub.add_parser("score")
    sc.add_argument("--round", type=int, required=True)
    args = p.parse_args(argv)
    return {"run": run, "sample": sample, "score": score}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
