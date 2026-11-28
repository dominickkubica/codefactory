"""Speed budgets: how long a cold run takes on a fixed set of repositories, phase by phase, and a check that fails when
one gets slower.

    python tools/speed.py check [--set quick|full]     run each repository cold, one at a time; fail on a regression
    python tools/speed.py baseline [--set quick|full]  record the current times as the baseline (on an idle machine)

A repository fails the check when its run is more than 30% (and 3 s) slower than the baseline, when any phase over 2 s
is more than 50% (and 2 s) slower, or when it passes the absolute ceiling (CEILING, whatever the baseline says). The
baseline lives in `tools/speed/baseline.json`; local repositories (gymlift, options-scanner) are timed when present,
with their timings kept in the gitignored `tools/speed/local.json`. Runs are cold (no analysis cache) and sequential,
so a number means the same thing every time; a busy machine makes every run slower, so the check reports the load
average it ran under.

This exists because timeouts were noted and passed over for weeks (CONTRIBUTING.md, rule 11): a run that times out
reports nothing at all, and a slow phase hides until it costs hours.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from corpus import checkout, kill_group, share_memory  # noqa: E402

HERE = ROOT / "tools" / "speed"
BASELINE = HERE / "baseline.json"
LOCAL_BASELINE = HERE / "local.json"
CEILING = 120.0  # seconds: no repository may take longer, cold, on one core's worth of jobs
# (quick: under a minute in all, run by tools/gate.py; full: the slow cases too, run before a release and after a
# speed change)
QUICK = ["shadcn-ui/taxonomy", "fastapi/full-stack-fastapi-template", "filebrowser/filebrowser", "maybe-finance/maybe"]
FULL = QUICK + ["mealie-recipes/mealie", "excalidraw/excalidraw", "dani-garcia/vaultwarden", "django/django",
                "invoiceninja/invoiceninja", "teableio/teable"]  # fmt: skip
# one cold analysis: no cache read or written, timings and peak memory out
RUN = """
import json, resource, sys, time
from pathlib import Path
from codefactory.cli import load_graph
from codefactory.export import audit
from codefactory.timing import report
start = time.perf_counter()
doc, review = audit(load_graph(Path(sys.argv[1]), cache=False), Path(sys.argv[1]).resolve())
seconds = time.perf_counter() - start
peak = max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
print(json.dumps({"seconds": round(seconds, 1), "phases": report(), "peak_mb": peak // 1024}))
"""


def local_repos() -> dict[str, Path]:
    """The local repositories pinned for golden snapshots (tools/golden/local.txt), when this machine has them."""
    out = {}
    pinned = ROOT / "tools" / "golden" / "local.txt"
    if pinned.exists():
        for line in pinned.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 3 and Path(parts[1]).is_dir():
                out[parts[0]] = Path(parts[1])
    return out


def time_one(path: Path) -> dict:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    with tempfile.TemporaryDirectory() as empty:  # (from an empty folder: `python -c` imports from where it runs)
        # (its own process group: a timeout ends the Node analyzer and the worker pool too, not just Python)
        proc = subprocess.Popen([sys.executable, "-c", RUN, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, cwd=empty, start_new_session=os.name != "nt")  # fmt: skip
        try:
            stdout, stderr = proc.communicate(timeout=CEILING * 3)
        except subprocess.TimeoutExpired:
            kill_group(proc)
            return {"seconds": CEILING * 3, "phases": {}, "peak_mb": 0, "error": "timeout"}
        done = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    if done.returncode != 0:
        return {"seconds": 0, "phases": {}, "peak_mb": 0, "error": done.stderr[-300:]}
    return json.loads(done.stdout.strip().splitlines()[-1])


def measure(names: list[str]) -> dict[str, dict]:
    share_memory(1)
    out = {}
    targets = {n: checkout(n) for n in names} | local_repos()
    for name, path in targets.items():
        out[name] = time_one(path)
        r = out[name]
        top = ", ".join(f"{k} {v:.1f}" for k, v in list(r["phases"].items())[:3] if k != "build")
        error = f"  ** {r['error'][:60]}" if "error" in r else ""
        print(f"{name:40} {r['seconds']:6.1f} s  {r['peak_mb']:5} MB  {top}{error}", flush=True)
    return out


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def check(args) -> int:
    names = QUICK if args.set == "quick" else FULL
    base = load(BASELINE) | load(LOCAL_BASELINE)
    print(f"load average {os.getloadavg()[0]:.1f} on {os.cpu_count()} cores")
    now = measure(names)
    failed = []
    for name, r in now.items():
        why = []
        if "error" in r:
            why.append(r["error"][:80])
        if r["seconds"] > CEILING:
            why.append(f"{r['seconds']:.0f} s, over the {CEILING:.0f} s ceiling")
        b = base.get(name)
        if b and r["seconds"] > max(b["seconds"] * 1.3, b["seconds"] + 3):
            why.append(f"{r['seconds']:.1f} s against {b['seconds']:.1f} s")
        for phase_name, s in r["phases"].items():
            was = (b or {}).get("phases", {}).get(phase_name)
            if was is not None and was > 2 and s > max(was * 1.5, was + 2):
                why.append(f"{phase_name} {s:.1f} s against {was:.1f} s")
        if why:
            failed.append(f"{name}: {'; '.join(why)}")
    busy = os.getloadavg()[0]
    strict = busy < (os.cpu_count() or 1) * 0.75  # (a busy machine slows every run: then over-budget is a warning)
    for line in failed:
        print(("FAIL  " if strict else "WARN  ") + line)
    if failed and not strict:
        print(f"      (load average {busy:.1f}: re-run on an idle machine before reading these as regressions)")
    print("ok    speed: every repository within budget" if not failed else f"{len(failed)} over budget")
    return 1 if failed and strict else 0


def baseline(args) -> int:
    names = QUICK if args.set == "quick" else FULL
    print(f"load average {os.getloadavg()[0]:.1f} on {os.cpu_count()} cores (record on an idle machine)")
    now = measure(names)
    local = {n: now.pop(n) for n in list(now) if n in local_repos()}
    HERE.mkdir(exist_ok=True)
    for path, data in ((BASELINE, now), (LOCAL_BASELINE, local)):
        merged = load(path) | data
        path.write_text(json.dumps(dict(sorted(merged.items())), indent=1) + "\n", encoding="utf-8")
    print(f"baseline: {len(now)} corpus and {len(local)} local repositories recorded")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("check", "baseline"):
        s = sub.add_parser(name)
        s.add_argument("--set", choices=("quick", "full"), default="quick")
    args = p.parse_args(argv)
    return {"check": check, "baseline": baseline}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
