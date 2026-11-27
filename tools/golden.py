"""Golden snapshots: every finding on a few pinned repositories, so each change shows what it added and removed.

    python tools/golden.py diff [--only a,b]          re-analyze the pinned repositories, list what changed (exit 1 on
                                                    a removal without a reason)
    python tools/golden.py accept --why "..."       record the reason for the current removals and take the new
                                                    results as the snapshot
    python tools/golden.py pin NAME PATH            add a local repository (pinned at its current commit)

The corpus labels say whether a location is right, but only for the locations someone labeled. A change can remove
findings nobody sampled, on code nobody looked at, and the precision check can't see that. These snapshots hold
everything reported (findings and hints) on a fixed set of repositories at fixed commits, so a change's whole effect
is a diff: what appeared, what disappeared, what moved between finding and hint or changed severity. A removal is
lost recall until someone says why it's right to lose it; `accept` writes that reason next to the key in
`tools/golden/reasons.jsonl`, the way a labeled location's fate is checked by `precision.py check`.

Public corpus repositories are listed in CORPUS below and their snapshots are committed. Local (private) repositories
go in `tools/golden/local.txt` (`name path commit`, gitignored), with snapshots under `tools/golden/local/` (also
gitignored), so nothing from a private codebase lands in this repository. Each is analyzed from `git archive` of its
pinned commit, so later commits there don't move the snapshot.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from corpus import CACHE, EXPORT, checkout  # noqa: E402
from precision import MECHANICAL, check_of, key  # noqa: E402

HERE = ROOT / "tools" / "golden"
LOCAL = HERE / "local.txt"
REASONS = HERE / "reasons.jsonl"
WORK = Path(os.environ.get("CODEFACTORY_GOLDEN", Path.home() / ".cache" / "codefactory-golden"))
# a spread of languages and kinds, each analyzed in under a minute: Python + TypeScript, Go + Vue, Ruby (Rails), Rust,
# Python + Vue, Next.js, a Python library
CORPUS = ["fastapi/full-stack-fastapi-template", "filebrowser/filebrowser", "maybe-finance/maybe",
          "dani-garcia/vaultwarden", "mealie-recipes/mealie", "shadcn-ui/taxonomy", "celery/celery"]  # fmt: skip


def golden() -> dict[str, dict]:
    """name -> {path, commit, snapshot}: the corpus ones at the commit already cloned, then the local ones."""
    out = {}
    for repo in CORPUS:
        path = CACHE / repo.replace("/", "__")
        out[repo] = {"path": path, "commit": None, "snapshot": HERE / f"{repo.replace('/', '__')}.json"}
    if LOCAL.exists():
        for line in LOCAL.read_text(encoding="utf-8").splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) == 3:
                name, path, commit = parts
                out[name] = {"path": Path(path), "commit": commit, "snapshot": HERE / "local" / f"{name}.json"}
    return out


def tree(name: str, spec: dict) -> Path:
    """The code to analyze: a corpus clone as is (shallow, never updated), or a local repository's pinned commit."""
    if spec["commit"] is None:
        return checkout(name)
    dest = WORK / name / spec["commit"]
    if not dest.exists():
        data = subprocess.run(["git", "-C", str(spec["path"]), "archive", spec["commit"]], capture_output=True, check=True).stdout
        dest.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            tar.extractall(dest, filter="data")
    return dest


def locations(doc: dict) -> dict[str, dict]:
    """key -> {check, severity, tier, location} for everything reported, findings and hints."""
    out = {}
    for tier in ("findings", "hints"):
        for f in doc.get(tier, []):
            check = check_of(f["title"])
            if MECHANICAL.match(check):
                continue
            for loc in f["locations"]:
                if not loc.startswith("…and "):
                    out.setdefault(
                        key("", check, loc)[1:], {"check": check, "severity": f["severity"], "tier": tier, "location": loc}
                    )
    return out


def analyze(name: str, spec: dict) -> dict[str, dict]:
    path = tree(name, spec)
    WORK.mkdir(parents=True, exist_ok=True)
    out, prof = WORK / f"{name.replace('/', '__')}.export.json", WORK / f"{name.replace('/', '__')}.profile.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    done = subprocess.run([sys.executable, "-c", EXPORT, str(path), str(out), str(prof)], capture_output=True, text=True, env=env)
    if done.returncode != 0:
        raise RuntimeError(f"{name}: {(done.stderr or done.stdout)[-400:]}")
    return locations(json.loads(out.read_text(encoding="utf-8")))


def reasons() -> dict[str, str]:
    out = {}
    if REASONS.exists():
        for line in REASONS.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                out[f"{r['repo']}|{r['key']}"] = r["why"]
    return out


def compare(name: str, spec: dict, now: dict) -> dict[str, list]:
    before = json.loads(spec["snapshot"].read_text(encoding="utf-8"))["locations"] if spec["snapshot"].exists() else None
    if before is None:
        return {"new snapshot": sorted(now)}
    moved = [k for k in now if k in before and (now[k]["tier"], now[k]["severity"]) != (before[k]["tier"], before[k]["severity"])]
    return {"added": [k for k in now if k not in before], "removed": [k for k in before if k not in now], "moved": moved,
            "_before": before}  # fmt: skip


def run_all(only: list[str] | None) -> dict[str, tuple[dict, dict]]:
    specs = {n: s for n, s in golden().items() if not only or n in only}
    # one at a time on small machines: the TypeScript analyzer's heap is shared out between parallel jobs
    jobs = max(1, min(len(specs), (os.cpu_count() or 2) // 2))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = dict(zip(specs, pool.map(lambda n: analyze(n, specs[n]), specs), strict=True))
    return {n: (specs[n], results[n]) for n in specs}


def diff(args) -> int:
    why, unexplained = reasons(), 0
    for name, (spec, now) in run_all(args.only.split(",") if args.only else None).items():
        d = compare(name, spec, now)
        before = d.pop("_before", {})
        if "new snapshot" in d:
            print(f"\n{name}: no snapshot yet ({len(now)} locations); `accept` takes one")
            continue
        if not any(d.values()):
            print(f"{name}: unchanged ({len(now)} locations)")
            continue
        print(f"\n{name}: +{len(d['added'])} -{len(d['removed'])} ~{len(d['moved'])}")
        for k in d["removed"]:
            reason = why.get(f"{name}|{k}")
            unexplained += reason is None
            v = before[k]
            print(f"  - {v['tier'][:4]} {v['severity'][:4]} {v['check'][:38]:38} {v['location'][:80]}"
                  + (f"  [{reason}]" if reason else "  ** no reason **"))  # fmt: skip
        for k in d["added"]:
            v = now[k]
            print(f"  + {v['tier'][:4]} {v['severity'][:4]} {v['check'][:38]:38} {v['location'][:80]}")
        for k in d["moved"]:
            a, b = before[k], now[k]
            was, nw = f"{a['tier'][:4]}/{a['severity'][:4]}", f"{b['tier'][:4]}/{b['severity'][:4]}"
            print(f"  ~ {was} -> {nw} {b['check'][:30]:30} {b['location'][:70]}")
    if unexplained:
        print(f'\n{unexplained} removed without a reason: if each is right to lose, `golden.py accept --why "..."`')
    return 1 if unexplained else 0


def accept(args) -> int:
    today = datetime.date.today().isoformat()
    with REASONS.open("a", encoding="utf-8") as log:
        for name, (spec, now) in run_all(args.only.split(",") if args.only else None).items():
            d = compare(name, spec, now)
            for k in d.get("removed", []):
                log.write(json.dumps({"repo": name, "key": k, "why": args.why, "date": today}, ensure_ascii=False) + "\n")
            spec["snapshot"].parent.mkdir(parents=True, exist_ok=True)
            doc = {"repo": name, "commit": spec["commit"] or _head(spec["path"]), "locations": dict(sorted(now.items()))}
            spec["snapshot"].write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"{name}: snapshot of {len(now)} locations ({len(d.get('removed', []))} removals recorded)")
    return 0


def _head(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def pin(args) -> int:
    commit = _head(Path(args.path))
    if not commit:
        print(f"{args.path}: not a git repository")
        return 1
    lines = [
        ln for ln in (LOCAL.read_text(encoding="utf-8").splitlines() if LOCAL.exists() else []) if ln.split()[:1] != [args.name]
    ]
    LOCAL.write_text("\n".join([*lines, f"{args.name} {Path(args.path).resolve()} {commit}"]) + "\n", encoding="utf-8")
    print(f"{args.name}: pinned at {commit[:10]}; `golden.py accept --only {args.name} --why pinned` takes its snapshot")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff")
    d.add_argument("--only")
    a = sub.add_parser("accept")
    a.add_argument("--why", required=True)
    a.add_argument("--only")
    pn = sub.add_parser("pin")
    pn.add_argument("name")
    pn.add_argument("path")
    args = p.parse_args(argv)
    return {"diff": diff, "accept": accept, "pin": pin}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
