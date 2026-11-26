"""What a change adds and removes: findings on the working tree compared with a base commit (a pull request's target).

The base is extracted once per commit into `.codefactory/diff/<sha>/` and analyzed with the same per-file caches as
anything else, so comparing again after a push re-reads only what changed. Findings are matched by identity, not line:
kind + file + function for graph findings (as in the baseline), kind + file + the flagged line's text for source
checks, so code moving down a file doesn't look new.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .baseline import issue_key

SEV_RANK = {"high": 0, "warn": 1, "info": 2}


@dataclass
class Item:
    key: str
    kind: str
    severity: str  # high | warn | info
    file: str
    line: int
    function: str
    message: str


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def default_base(root: Path) -> str:
    for ref in ("origin/HEAD", "origin/main", "origin/master", "main", "master"):
        try:
            git(root, "rev-parse", "--verify", "-q", ref)
            return ref
        except RuntimeError:
            continue
    raise RuntimeError("no base branch found: pass --base (a branch, tag or commit)")


def merge_base(root: Path, ref: str) -> str:
    try:
        return git(root, "merge-base", ref, "HEAD")
    except RuntimeError:
        return git(root, "rev-parse", ref)  # unrelated or shallow history: compare with the ref itself


def _keep(name: str) -> bool:
    return name.lstrip("./").split("/")[0] != ".codefactory"  # a cache, never part of the code (and could be planted)


def _base_member(member: tarfile.TarInfo, dest: str) -> tarfile.TarInfo | None:
    """tarfile's data filter, leaving out what it refuses (a link out of the folder) instead of failing the diff."""
    if not _keep(member.name):
        return None
    try:
        return tarfile.data_filter(member, dest)
    except tarfile.FilterError:
        return None


def extract(root: Path, sha: str, into: Path) -> Path:
    """The tree at `sha`, extracted once (git archive) into `into/<sha>`: the cache folder, or a temporary one."""
    target = into / sha[:12]
    try:  # only our own marker, naming this commit: anything else is re-extracted
        if (target / ".complete").read_text(encoding="utf-8") == sha and not target.is_symlink():
            return target
    except OSError:
        pass
    if target.is_symlink():
        target.unlink()
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "base.tar"
        # the analyzed folder only, with paths relative to it (a subfolder of a monorepo is compared with itself)
        prefix = git(root, "rev-parse", "--show-prefix").rstrip("/")
        top = git(root, "rev-parse", "--show-toplevel")  # run there: from a subfolder, `sha:path` is read relative to it
        git(Path(top), "archive", "--format=tar", "-o", str(archive), f"{sha}:{prefix}" if prefix else sha)
        with tarfile.open(archive) as tar:
            try:  # the data filter refuses absolute paths, links out of the folder and special files
                tar.extractall(target, filter=_base_member)
            except TypeError:  # Python 3.11 before 3.11.4 has no filters: leave out every link instead
                safe = [m for m in tar.getmembers() if _keep(m.name) and (m.isfile() or m.isdir())]
                tar.extractall(target, members=safe)  # noqa: S202
    (target / ".complete").write_text(sha, encoding="utf-8")
    # older bases: keep three at most (real folders only: a link is removed, never followed)
    olds = sorted((p for p in into.iterdir() if p != target), key=lambda p: p.lstat().st_mtime)
    for old in olds[:-2]:
        if old.is_symlink() or not old.is_dir():
            old.unlink(missing_ok=True)
        else:
            shutil.rmtree(old, ignore_errors=True)
    return target


def changed_files(root: Path, sha: str) -> set[str]:
    out = git(root, "diff", "--name-only", "--relative", sha)  # committed and uncommitted changes, this folder only
    untracked = git(root, "ls-files", "--others", "--exclude-standard")
    return {p for p in (out + "\n" + untracked).splitlines() if p}


def items(root: Path, graph: dict) -> list[Item]:
    """Every finding: graph flags and the review's source and repository checks (git history aside: it's the same
    history on both sides)."""
    from .audit import scan_config
    from .checks import scan_sources, source_files
    from .sarif import RULES

    fns = {f["id"]: f for f in graph["functions"]}
    out = []
    for f in graph["flags"]:
        fn = fns.get(f["target"])
        out.append(Item(issue_key(graph, f, fns), f["kind"], f["severity"], fn["file"] if fn else f["target"],
                        f.get("line") or (fn["line"] if fn else 0), fn["qualname"] if fn and fn["kind"] != "module" else "",
                        f["message"]))  # fmt: skip
    from .privacy import scan as privacy_scan

    sources = source_files(root, graph)  # parsed or not: line checks need no parser
    checks = scan_sources(root, sources)
    checks.update(scan_config(root))
    checks.update(privacy_scan(root, sources))
    from .apple import scan as apple_scan

    checks.update(apple_scan(root, sources))
    from .config import load_config
    from .infra import scan as infra_scan

    checks.update(infra_scan(root, set(load_config(root).ignore)))
    for kind, check in checks.items():
        if kind not in RULES:
            continue
        for e in check.hits:
            text = " ".join(e.text.split())
            out.append(Item(f"{kind}|{e.file}|{text}", kind, RULES[kind][3], e.file, e.line, "", f"{RULES[kind][1]}: {e.text}"))
    return out


def compare(base: list[Item], head: list[Item]) -> tuple[list[Item], list[Item]]:
    """(new on head, gone from base), matching by key and counting repeats."""
    left = Counter(i.key for i in base)
    new = []
    for i in head:
        if left[i.key] > 0:
            left[i.key] -= 1
        else:
            new.append(i)
    remaining = Counter(i.key for i in head)
    gone = []
    for i in base:
        if remaining[i.key] > 0:
            remaining[i.key] -= 1
        else:
            gone.append(i)
    return new, gone


def run(root: Path, base_ref: str, load) -> dict:
    """load(path) -> graph. Returns base sha, changed files, new and fixed findings."""
    root = root.resolve()
    sha = merge_base(root, base_ref)
    from .paths import cache_dir

    cache = cache_dir(root)
    if cache and (cache / "diff").is_symlink():
        (cache / "diff").unlink()  # never extract (or clean up) through a link
    with tempfile.TemporaryDirectory() as tmp:  # no trusted cache folder: the base lives only for this run
        base_dir = extract(root, sha, cache / "diff" if cache else Path(tmp))
        head_items = items(root, load(root))
        base_items = items(base_dir, load(base_dir))
    new, gone = compare(base_items, head_items)
    changed = changed_files(root, sha)
    order = lambda i: (SEV_RANK.get(i.severity, 3), i.file, i.line)  # noqa: E731
    return {"base": sha, "changed": sorted(changed), "new": sorted(new, key=order), "fixed": sorted(gone, key=order)}


def markdown(result: dict, limit: int = 30, owners=None) -> str:
    """A pull-request comment (with each finding's owners, when the repository has a CODEOWNERS file)."""
    new, fixed, changed = result["new"], result["fixed"], set(result["changed"])
    counts = Counter(i.severity for i in new)
    head = (
        f"**codefactory:** {len(new)} new finding{'s' if len(new) != 1 else ''}"
        + (f" ({', '.join(f'{counts[s]} {s}' for s in ('high', 'warn', 'info') if counts[s])})" if new else "")
        + (
            f" in the {result['added']:,} lines this patch adds ({len(changed)} files; line checks only, graph checks "
            "need the repository)."
            if result.get("patch")
            else f", {len(fixed)} fixed, compared with `{result['base'][:10]}`."
        )
    )
    lines = [head, ""]
    if new:
        lines += ["| | Finding | Where |", "|---|---|---|"]
        for i in new[:limit]:
            where = f"`{i.file}:{i.line}`" + (f" {i.function}" if i.function else "")
            if owners and (who := owners.of(i.file)):
                where += " · " + " ".join(who)
            note = (
                ""
                if i.file in changed or result.get("patch")
                else " (a file this change didn't touch: a consequence, such as a caller removed)"
            )
            lines.append(f"| {i.severity} | {i.message.replace('|', '/')} | {where}{note} |")
        if len(new) > limit:
            lines.append(f"| | … {len(new) - limit} more | |")
        lines += ["", "Intended? Mark it with `codefactory: ignore <kind> — why` or `codefactory accept`."]
    if fixed:
        lines += ["", f"<details><summary>{len(fixed)} fixed</summary>", ""]
        lines += [f"- {i.kind}: `{i.file}`" + (f" {i.function}" if i.function else "") for i in fixed[:limit]]
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"
