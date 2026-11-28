"""The public-repository corpus: every repository codefactory has been checked against, and what became of it.

    python tools/corpus.py run [--jobs N] [--only owner/repo,...] [--new]   clone (shallow) and analyze (jobs: one per core)
    python tools/corpus.py report                                          rewrite docs/CORPUS.md

`tools/corpus/repos.txt` lists the repositories (owner/repo, one per line, `#` comments). Each run clones into
~/.cache/codefactory-corpus (or CODEFACTORY_CORPUS), runs `codefactory export --json` with a time limit in a separate
process, and records the outcome in `tools/corpus/results.json`: the commit, seconds, the profile, findings by
severity, the Critical and High titles, and the run's `codefactory:` notes (a fallback, files left out: otherwise
unseen). `tools/corpus/triage.json` holds what a person decided about each one:
`clean` (every Critical and High finding checked and real, or none), `fixed` (false positives found and fixed, with
a regression test), or `open` (something still to fix, with a note). A repository is accounted for once it ran
without a crash or timeout and has a triage status.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tools" / "corpus"
CACHE = Path(os.environ.get("CODEFACTORY_CORPUS", Path.home() / ".cache" / "codefactory-corpus"))
LIMIT = 900  # seconds per repository: past this, a run is killed and reports nothing
SLOW = 120  # seconds: a repository slower than this is listed at the end of every run, to be looked at
# `codefactory export PATH --json -o OUT`, also writing what `codefactory profile PATH --json` prints
EXPORT = """
import json, sys
from pathlib import Path
from codefactory.cli import load_graph
from codefactory.export import audit
path, out, prof = map(Path, sys.argv[1:4])
doc, review = audit(load_graph(path), path.resolve())
out.write_text(json.dumps(doc, indent=1) + "\\n", encoding="utf-8")
from codefactory.timing import report
prof.write_text(json.dumps({**review.profile.to_dict(), "timings": report()}, indent=1), encoding="utf-8")
"""


def export_with(code: Path, repo_path: Path, out: Path, prof: Path, timeout: float | None = LIMIT) -> subprocess.CompletedProcess:
    """`EXPORT` with the codefactory at `code` (a worktree of some commit, or this checkout), and only that one: run
    from an empty folder, since `python -c` puts the current folder first on the path, ahead of PYTHONPATH (heldout.py
    ran the working tree, not the commit asked for, until this), and checked before anything is analyzed."""
    import tempfile

    check = (f"import codefactory, pathlib; assert pathlib.Path(codefactory.__file__).resolve().is_relative_to("
             f"{str(Path(code).resolve())!r}), codefactory.__file__\n")  # fmt: skip
    env = {**os.environ, "PYTHONPATH": str(code)}
    with tempfile.TemporaryDirectory() as empty:
        # its own process group, so a timeout ends the TypeScript analyzer's Node processes too: killing only Python
        # left them running for half an hour, holding a core and gigabytes each (invoiceninja, round 9)
        proc = subprocess.Popen([sys.executable, "-c", check + EXPORT, str(repo_path), str(out), str(prof)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=empty,
                                start_new_session=os.name != "nt")  # fmt: skip
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            raise
        return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def _kill_group(proc: subprocess.Popen) -> None:
    import signal

    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
    proc.communicate()


def repos() -> list[str]:
    out = []
    for line in (HERE / "repos.txt").read_text(encoding="utf-8").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            out.append(name)
    return list(dict.fromkeys(out))


def load(name: str) -> dict:
    path = HERE / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save(name: str, data: dict) -> None:
    (HERE / name).write_text(json.dumps(dict(sorted(data.items())), indent=1) + "\n", encoding="utf-8")


def checkout(repo: str) -> Path:
    path = CACHE / repo.replace("/", "__")
    if (path / ".git").exists():
        return path
    shutil.rmtree(path, ignore_errors=True)
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"https://github.com/{repo}.git", str(path)],
        check=True,
        capture_output=True,
        timeout=600,
    )
    return path


def analyze(repo: str) -> dict:
    started = time.time()
    try:
        path = checkout(repo)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return {"status": "clone failed", "error": str(e)[-300:]}
    out = CACHE / "exports" / f"{repo.replace('/', '__')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    prof = out.with_suffix(".profile.json")
    prof.unlink(missing_ok=True)
    try:  # the export and its structured profile from one analysis (a second `codefactory profile` re-analyzed
        # whenever the result couldn't be cached, as when the TypeScript analyzer falls back: n8n, twice)
        done = export_with(ROOT, path, out, prof)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "seconds": LIMIT}
    seconds = round(time.time() - started, 1)
    if done.returncode != 0 or not out.exists():
        return {"status": "crash", "seconds": seconds, "error": (done.stderr or done.stdout)[-600:]}
    data = json.loads(out.read_text(encoding="utf-8"))
    try:
        profile = json.loads(prof.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        profile = {}
    counts: dict[str, int] = {}
    for f in data["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "status": "ok",
        "seconds": seconds,
        "commit": data.get("commit", "")[:12],
        "kind": profile.get("kind", ""),
        "deployment": profile.get("deployment", ""),
        "counts": counts,
        "serious": [f"{f['severity']}: {f['title']}" for f in data["findings"] if f["severity"] in ("Critical", "High")],
        **({"notes": found} if (found := notes(done.stderr)) else {}),  # (only when there are some, as older entries)
        # the slowest phases, so a slow repository says where its time went (rule 11)
        **({"phases": dict(list(timings.items())[:6])} if (timings := profile.get("timings")) else {}),
    }


def notes(stderr: str) -> list[str]:
    """The run's own notes on stderr (a fallback analyzer, files not analyzed), each once and short."""
    out: list[str] = []
    for line in (stderr or "").splitlines():
        line = line.strip()[:240]
        if line.startswith("codefactory:") and line not in out:
            out.append(line)
    return out[:8]


def share_memory(jobs: int) -> None:
    """Each parallel job's TypeScript analyzer gets its share of memory: half of it each, at 4 jobs, ran the box out
    (and heldout.py, which didn't share it, had runs killed for lack of memory)."""
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)
        os.environ.setdefault("CODEFACTORY_TS_HEAP_MB", str(max(2048, int(total * 0.8) // max(1, jobs))))
    except (AttributeError, ValueError, OSError):
        pass


def run(args) -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    results = load("results.json")
    wanted = args.only.split(",") if args.only else repos()
    if args.new:
        wanted = [r for r in wanted if r not in results]
    print(f"{len(wanted)} repositories, {args.jobs} at a time", flush=True)
    share_memory(args.jobs)

    def one(repo: str) -> tuple[str, dict]:
        try:
            result = analyze(repo)
        except Exception as e:  # a bug in this script mustn't lose the rest of the run
            result = {"status": "crash", "error": f"corpus.py: {type(e).__name__}: {e}"}
        flag = "" if result["status"] == "ok" else f"  ** {result['status']} **"
        serious = len(result.get("serious", []))
        print(f"{repo:45} {result.get('kind', ''):18} {result.get('seconds', '')!s:>6}s  serious {serious}{flag}", flush=True)
        return repo, result

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for repo, result in pool.map(one, wanted):
            results[repo] = result
            save("results.json", results)  # after each, so an interrupted run keeps what it did
    bad = [r for r in wanted if results[r]["status"] != "ok"]
    print(f"done: {len(wanted) - len(bad)} ok, {len(bad)} not ({', '.join(bad) or 'none'})")
    slow = sorted((r for r in wanted if results[r].get("seconds", 0) > SLOW), key=lambda r: -results[r]["seconds"])
    if slow or any(results[r]["status"] == "timeout" for r in wanted):  # (rule 11: loud, every time, until fixed)
        print(f"\n** over {SLOW:.0f} s or timed out: investigate before anything else (CONTRIBUTING.md, rule 11) **")
        for r in slow + [r for r in wanted if results[r]["status"] == "timeout"]:
            phases = ", ".join(f"{k} {v:.0f}" for k, v in results[r].get("phases", {}).items() if k != "build")
            print(f"  {r:45} {results[r].get('seconds', LIMIT):6.0f} s  {results[r]['status']:8} {phases}")
    return 1 if bad else 0


def report(args) -> int:
    results, triage = load("results.json"), load("triage.json")
    names = repos()
    accounted = [r for r in names if results.get(r, {}).get("status") == "ok" and r in triage]
    lines = [
        "# Corpus",
        "",
        "Every public repository codefactory has been checked against: analyzed without a crash or timeout, its Critical",
        "and High findings looked at, and false positives fixed with a regression test. Generated by",
        "`python tools/corpus.py report` from `tools/corpus/results.json` and `tools/corpus/triage.json`.",
        "",
        f"**{len(accounted)} of {len(names)} accounted for.**",
        "",
        "| Repository | Profile | Critical / High / Medium / Low | Seconds | Status |",
        "|---|---|---|---|---|",
    ]
    for repo in sorted(names, key=str.lower):
        r = results.get(repo, {})
        t = triage.get(repo, {})
        if r.get("status") != "ok":
            row = [repo, "", "", "", r.get("status", "not run")]
        else:
            c = r.get("counts", {})
            sev = " / ".join(str(c.get(s, 0)) for s in ("Critical", "High", "Medium", "Low"))
            status = t.get("status", "to triage") + (f": {t['note']}" if t.get("note") else "")
            row = [f"[{repo}](https://github.com/{repo})", r.get("kind") or "unknown", sev, str(r.get("seconds", "")), status]
        lines.append("| " + " | ".join(row) + " |")
    (ROOT / "docs" / "CORPUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"docs/CORPUS.md: {len(accounted)} of {len(names)} accounted for")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--jobs", type=int, default=os.cpu_count() or 4)  # (more jobs than cores: big repositories time out)
    r.add_argument("--only", default=None)
    r.add_argument("--new", action="store_true", help="only repositories with no result yet")
    sub.add_parser("report")
    args = p.parse_args(argv)
    return run(args) if args.cmd == "run" else report(args)


if __name__ == "__main__":
    raise SystemExit(main())
