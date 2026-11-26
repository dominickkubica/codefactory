"""Run what CI runs, locally, before pushing: `python tools/check.py`.

CI tests on two Pythons (3.11 and 3.13), each without the optional language pack and with it, plus lint with the
pinned ruff and `codefactory check .`. Most failed pushes were a configuration nobody ran locally: a test that passed
with the language pack installed and failed without it, or on the older Python. This runs every configuration this
machine has a Python for, in parallel, in throwaway environments kept under ~/.cache/codefactory-ci (built once, then
reused), and prints one line per configuration.

What it can't run is another operating system: CI also tests on Windows. Paths, file times and shell tools differ
there; CONTRIBUTING.md lists what has broken before.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path(os.environ.get("CODEFACTORY_CI_CACHE", Path.home() / ".cache" / "codefactory-ci"))
PYTHONS = ("3.11", "3.13")
WINDOWS = os.name == "nt"


def find_python(version: str) -> list[str] | None:
    """The interpreter for a version: `python3.11` on Linux and macOS, `py -3.11` on Windows."""
    if WINDOWS and shutil.which("py"):
        probe = subprocess.run(["py", f"-{version}", "-c", "pass"], capture_output=True)
        return ["py", f"-{version}"] if probe.returncode == 0 else None
    found = shutil.which(f"python{version}")
    return [found] if found else None


def venv(name: str, python: list[str], requirements: str | None) -> Path:
    """A virtual environment with exactly these pinned requirements (or none), rebuilt when they change."""
    path = CACHE / name
    exe = path / ("Scripts/python.exe" if WINDOWS else "bin/python")
    stamp = path / ".requirements"
    wanted = (ROOT / requirements).read_text(encoding="utf-8") if requirements else ""
    if exe.exists() and stamp.exists() and stamp.read_text(encoding="utf-8") == wanted:
        return exe
    shutil.rmtree(path, ignore_errors=True)
    subprocess.run([*python, "-m", "venv", str(path)], check=True, capture_output=True)
    if requirements:
        subprocess.run(
            [str(exe), "-m", "pip", "install", "-q", "--require-hashes", "--no-deps", "-r", str(ROOT / requirements)],
            check=True,
            capture_output=True,
        )
    stamp.write_text(wanted, encoding="utf-8")
    return exe


def run(label: str, command: list[str]) -> tuple[str, bool, str, float]:
    started = time.time()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = "\n".join((done.stdout + done.stderr).strip().splitlines()[-25:])
    return label, done.returncode == 0, tail, time.time() - started


def main() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    jobs: list[tuple[str, list[str]]] = []
    lint = venv("lint", find_python("3.13") or [sys.executable], ".github/ci-requirements.txt")
    jobs.append(("lint (pinned ruff)", [str(lint), "-m", "ruff", "check", "codefactory", "tests"]))
    jobs.append(("format (pinned ruff)", [str(lint), "-m", "ruff", "format", "--check", "codefactory", "tests"]))
    missing = []
    for version in PYTHONS:
        python = find_python(version)
        if python is None:
            missing.append(version)
            continue
        bare = venv(f"py{version}-bare", python, None)
        pack = venv(f"py{version}-languages", python, "action-requirements.txt")
        tests = ["-m", "unittest", "discover", "-s", "tests", "-t", "."]
        jobs.append((f"tests, Python {version}, no language pack", [str(bare), *tests]))
        jobs.append((f"tests, Python {version}, language pack", [str(pack), *tests]))
    newest = find_python("3.13") or [sys.executable]
    jobs.append(("codefactory check .", [str(venv("py3.13-bare", newest, None)), "-m", "codefactory", "check", "."]))

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = list(pool.map(lambda job: run(*job), jobs))
    failed = [r for r in results if not r[1]]
    for label, ok, _, seconds in results:
        print(f"{'ok  ' if ok else 'FAIL'}  {label}  ({seconds:.0f}s)")
    for version in missing:
        print(f"skip  Python {version} isn't installed here; CI still runs it")
    print("not run here: Windows (CI runs it; see CONTRIBUTING.md for what breaks there)")
    for label, _, tail, _ in failed:
        print(f"\n--- {label} ---\n{tail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
