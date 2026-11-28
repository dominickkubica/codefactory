"""The gate a change to codefactory passes before it's pushed: `python tools/gate.py [--against REF]`.

1. Golden diff (`tools/golden.py diff`): every finding on the pinned repositories; a removal fails until
   `golden.py accept --why "..."` records why it's right to lose.
2. Right findings kept: every location labeled right in `tools/corpus/labels.json` for a source-text check that the
   code at REF (default `origin/main`) reports, the working tree must still report. Both versions scan the same files
   of the corpus checkouts, so nothing else (a stale export, a run interrupted halfway) can move the result.
3. `tools/check.py`: lint, format, the tests on every Python and configuration CI runs, `codefactory check .`.

It stops at the first step that fails. Graph checks (loops, unused and untested code, import loops) need whole-repository
analysis: `--corpus owner/repo,...` (or `--corpus "labeled:PREFIX|PREFIX"`, every repository with labels for checks starting so)
adds a step that analyzes each with both versions, into separate folders, and holds every labeled-right location of
any check to the same rule. Nothing is read from earlier exports, so a run interrupted halfway can't skew it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from corpus import CACHE, EXPORT, checkout  # noqa: E402
from golden import locations  # noqa: E402
from precision import AT, key, load  # noqa: E402

# labeled checks that come from scan_sources / scan_config, by the key their hits are kept under
SOURCE_CHECKS = {
    "N error silently swallowed": "swallowed",
    "Shell commands built at runtime": "shell",
    "SQL assembled from strings": "sql_built",
    "TLS certificate checks turned off": "tls_off",
    "Raw HTML injected into pages": "raw_html",
    "Network calls without a timeout": "fetch_no_timeout",
    "Dynamic code execution (eval / exec / pickle / unsafe YAML)": "eval",
    "Credentials committed in source": "secret",
    "MD5 / SHA-1 used for security": "weak_hash",
    "Any website may call this API (CORS *)": "cors_any",
    "Tokens or passwords in unencrypted storage": "sensitive_storage",
    "Container runs as root": "docker_root",
}
# run with a given codefactory on sys.path: which of the given locations it reports (key -> bool)
PROBE = """
import json, re, sys, codefactory
assert codefactory.__file__.startswith(sys.argv[3]), (codefactory.__file__, sys.argv[3])  # the version meant
from pathlib import Path
from codefactory.audit import scan_config
from codefactory.checks import scan_sources
spots, cache = json.load(open(sys.argv[1])), Path(sys.argv[2])
by_repo, out = {}, {}
for key, (repo, kind, file, line) in spots.items():
    by_repo.setdefault(repo, []).append((key, kind, file, line))
for repo, items in by_repo.items():
    root = cache / repo.replace("/", "__")
    config = scan_config(root) if any(k == "docker_root" for _, k, _, _ in items) else None
    source = scan_sources(root, sorted({f for _, k, f, _ in items if k != "docker_root"}))
    for key, kind, file, line in items:
        found = config if kind == "docker_root" else source
        out[key] = any(e.file == file and e.line == line for e in found[kind].hits)
print(json.dumps(out))
"""


def step(name: str, command: list[str]) -> bool:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = (done.stdout + done.stderr).strip().splitlines()[-4:]
    print(f"{'ok  ' if done.returncode == 0 else 'FAIL'}  {name}")
    if done.returncode != 0:
        print("\n".join("      " + t for t in tail))
    return done.returncode == 0


def right_kept(ref: str) -> bool:
    """Step 2: no location labeled right, reported by REF, goes missing in the working tree."""
    spots = {}
    for k, v in load().items():
        kind = SOURCE_CHECKS.get(v["check"])
        checkout = CACHE / v["repo"].replace("/", "__")
        if v["label"] == "true" and kind and (m := AT.search(v["location"])) and checkout.exists():
            spots[k] = (v["repo"], kind, m.group(1), int(m.group(2)))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spots.json"
        path.write_text(json.dumps(spots), encoding="utf-8")
        old = Path(tmp) / "old"
        subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(old), ref], check=True)
        try:
            found = {}
            for name, code in (("ref", old), ("tree", ROOT)):
                env = {**os.environ, "PYTHONPATH": str(code)}
                # (from a neutral folder: `python -c` puts the current one first on the path, ahead of PYTHONPATH)
                done = subprocess.run([sys.executable, "-c", PROBE, str(path), str(CACHE), str(code)], capture_output=True,
                                      text=True, env=env, check=True, cwd=tmp)  # fmt: skip
                found[name] = json.loads(done.stdout)
        finally:
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(old)], capture_output=True)
    lost = [k for k in spots if found["ref"][k] and not found["tree"][k]]
    print(f"{'ok  ' if not lost else 'FAIL'}  right findings kept: {len(spots)} labeled right, {len(lost)} lost against {ref}")
    labels = load()
    for k in lost:
        print(f"      {labels[k]['check'][:32]:32} {labels[k]['location'][:90]}")
    return not lost


def _labeled_repos(prefix: str) -> list[str]:
    """Repositories with right or wrong labels for checks starting with `prefix`, minus any held-out round still
    waiting for its after-run: the fixes being gated must not be tuned on it (CONTRIBUTING.md, rule 4)."""
    waiting = {r for n in _waiting_rounds() for r in __import__("heldout").round_repos(n)}
    return sorted({v["repo"] for v in load().values() if v["check"].startswith(prefix) and v["label"] in ("true", "false")}
                  - waiting)  # fmt: skip


def _waiting_rounds() -> set[int]:
    """Held-out rounds frozen (a base run exists) but not yet measured (no after run)."""
    import heldout

    def done(n: int, version: str) -> set[str]:
        folder = heldout.folder(n, version)
        return {p.name for p in folder.glob("*.json") if not p.name.endswith(".profile.json")} if folder.exists() else set()

    # (measured only once the after-run covers every repository the base has: an interrupted one leaves a few)
    return {n for n in range(1, 100) if done(n, "base") and not done(n, "base") <= done(n, "after")}


def corpus_kept(ref: str, repos: list[str], jobs: int) -> bool:
    """Whole-repository analysis with both versions: no labeled-right location the ref reports may go missing."""
    from concurrent.futures import ThreadPoolExecutor

    with tempfile.TemporaryDirectory() as tmp:
        old = Path(tmp) / "old"
        subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(old), ref], check=True)
        try:

            def export(job: tuple[str, Path, str]) -> tuple[str, str, dict | None]:
                version, code, repo = job
                out = Path(tmp) / version / f"{repo.replace('/', '__')}.json"
                out.parent.mkdir(exist_ok=True)
                env = {**os.environ, "PYTHONPATH": str(code)}
                done = subprocess.run([sys.executable, "-c", EXPORT, str(checkout(repo)), str(out), str(out) + ".profile"],
                                      capture_output=True, text=True, env=env, cwd=tmp, timeout=1800)  # fmt: skip
                ok = done.returncode == 0 and out.exists()
                return version, repo, locations(json.loads(out.read_text(encoding="utf-8"))) if ok else None

            jobs_list = [(v, c, r) for r in repos for v, c in (("ref", old), ("tree", ROOT))]
            found: dict[tuple[str, str], dict | None] = {}
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                for version, repo, locs in pool.map(export, jobs_list):
                    found[(version, repo)] = locs
        finally:
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(old)], capture_output=True)
    labels, lost, failed, n = load(), [], [], 0
    wanted = set(repos)
    for v in labels.values():
        if v["label"] != "true" or v["repo"] not in wanted:
            continue
        ref_locs, tree_locs = found[("ref", v["repo"])], found[("tree", v["repo"])]
        if ref_locs is None or tree_locs is None:
            failed.append(v["repo"])
            continue
        spot = key("", v["check"], v["location"])[1:]
        if spot in ref_locs:
            n += 1
            if spot not in tree_locs:
                lost.append(v)
    failed = sorted(set(failed) | {r for (_, r), locs in found.items() if locs is None})
    note = f"; analysis failed: {', '.join(failed)}" if failed else ""
    mark = "ok  " if not lost and not failed else "FAIL"
    print(f"{mark}  corpus: {len(repos)} repositories, {n} labeled-right locations the ref reports, {len(lost)} lost{note}")
    for v in lost:
        print(f"      {v['repo'][:22]:22} {v['check'][:30]:30} {v['location'][:80]}")
    return not lost and not failed


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--against", default="origin/main", help="the git ref whose right findings must be kept")
    p.add_argument("--skip-ci", action="store_true", help="stop before tools/check.py (for a quick loop while working)")
    p.add_argument("--corpus", help="owner/repo,... or labeled:CHECK-PREFIX: also gate whole-repository analysis on them")
    p.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2), help="analyses at a time (--corpus)")
    args = p.parse_args(argv)
    if not re.fullmatch(r"[\w./^~-]+", args.against):
        print(f"--against: not a git ref: {args.against}")
        return 2
    ok = step("golden diff", [sys.executable, "tools/golden.py", "diff"]) and right_kept(args.against)
    if ok and args.corpus:
        spec = args.corpus
        if spec.startswith("labeled:"):
            repos = sorted({r for prefix in spec[8:].split("|") for r in _labeled_repos(prefix)})
        else:
            repos = spec.split(",")
        ok = corpus_kept(args.against, repos, args.jobs)
    if ok and not args.skip_ci:
        ok = step("tools/check.py", [sys.executable, "tools/check.py"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
