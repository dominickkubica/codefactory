# codefactory: ignore-file secret, eval, shell — the patterns themselves
"""Security checks on what surrounds the code: CI workflows, Dockerfiles, mobile app configuration, and secrets that
were committed once and deleted later (still in git history, so still leaked).

Each returns Evidence (file, line, text) under a check key, like checks.scan_sources, so the review, SARIF and
`codefactory accept` treat them the same way.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .checks import PATTERNS, Check, Evidence
from .suppress import MARK

# GitHub Actions
PR_TARGET = re.compile(r"^\s*pull_request_target\s*:?", re.M)
HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/")
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"[\w.\[\]*]*\.(?:title|body|head_ref|label|message|name|email|ref)|head_ref)\s*\}\}"
)
USES = re.compile(r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)", re.M)
FIRST_PARTY = ("actions/", "github/")
# Dockerfiles
FROM = re.compile(r"^\s*FROM\s+(\S+)", re.I | re.M)
USER = re.compile(r"^\s*USER\s+(\S+)", re.I | re.M)
ENV_SECRET = re.compile(r"^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY)\w*[= ]\s*\S+", re.I | re.M)
# Mobile
ATS = re.compile(r"NSAllowsArbitraryLoads[\"']?\s*(?::\s*true|</key>\s*<true\s*/>)", re.I)
CLEARTEXT = re.compile(r"usesCleartextTraffic\s*[=:]\s*[\"']?true", re.I)

KEYS = ("gha_pr_target", "gha_injection", "gha_unpinned", "docker_root", "docker_secret", "docker_latest",
        "mobile_cleartext", "history_secret")  # fmt: skip


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _excerpt(text: str) -> str:
    t = text.strip()
    return t if len(t) <= 140 else t[:137] + "…"


def workflows(root: Path, out: dict[str, Check]) -> None:
    for path in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        if m := PR_TARGET.search(text):
            # runs with the repository's secrets and write access, on code from a fork: dangerous only if it checks
            # that code out (or builds it); otherwise it's the safe way to label or comment on a PR
            danger = HEAD_CHECKOUT.search(text)
            out["gha_pr_target"].hits.append(
                Evidence(rel, _line(text, m.start()), "pull_request_target" + (" + checks out the PR's code" if danger else ""))
            )
            out["gha_pr_target"].data[rel] = "checkout" if danger else "trigger"
        for i, ln in enumerate(lines, 1):
            if UNTRUSTED.search(ln) and not ln.strip().startswith(("#", "if:", "name:")):
                out["gha_injection"].hits.append(Evidence(rel, i, _excerpt(ln)))
        for m in USES.finditer(text):
            action, ref = m.group(1), m.group(2)
            if not action.startswith(FIRST_PARTY) and not re.fullmatch(r"[0-9a-f]{40}", ref):
                out["gha_unpinned"].hits.append(Evidence(rel, _line(text, m.start()), f"{action}@{ref}"))


def dockerfiles(root: Path, files: list[Path], out: dict[str, Check]) -> None:
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        froms = list(FROM.finditer(text))
        if not froms:
            continue
        users = [u.group(1) for u in USER.finditer(text)]
        if not users or users[-1] in ("root", "0", "0:0"):
            out["docker_root"].hits.append(Evidence(rel, _line(text, froms[-1].start()), f"no USER after {froms[-1].group(1)}"))
        for m in froms:
            image = m.group(1)
            if image.lower() == "scratch" or image.startswith("$") or "@sha256:" in image:
                continue
            tag = image.split("/")[-1].partition(":")[2]
            if not tag or tag == "latest":
                out["docker_latest"].hits.append(Evidence(rel, _line(text, m.start()), f"FROM {image}"))
        for m in ENV_SECRET.finditer(text):
            if not re.search(r"\$\{?\w+|changeme|example|<", m.group(0), re.I):
                out["docker_secret"].hits.append(Evidence(rel, _line(text, m.start()), _excerpt(m.group(0))))


def mobile(root: Path, out: dict[str, Check]) -> None:
    names = ("app.json", "app.config.json", "Info.plist", "AndroidManifest.xml")
    found = (p for name in names for p in root.rglob(name) if not ({"node_modules", ".git", ".codefactory"} & set(p.parts)))
    for path in sorted(found):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in (ATS, CLEARTEXT):
            if m := pat.search(text):
                out["mobile_cleartext"].hits.append(Evidence(rel, _line(text, m.start()), _excerpt(m.group(0))))


def history(root: Path, current: set[str], out: dict[str, Check], max_lines: int = 400_000, timeout: int = 60) -> str:
    """Secrets added in any commit (and branch) that aren't in the current files: deleted, but still leaked. Returns a
    note on how much history was read ("" when everything was)."""
    if not (root / ".git").exists():
        return "not a git repository: history not checked"
    try:
        proc = subprocess.Popen(
            ["git", "-C", str(root), "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0", "--format=@@commit %h %as"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
        )  # fmt: skip
    except OSError:
        return "git isn't available: history not checked"
    commit, file, seen, read, note = "", "", set(), 0, ""
    pats = PATTERNS["secret"]
    try:
        for raw in proc.stdout:
            read += 1
            if read > max_lines:
                note = f"history read up to {max_lines:,} changed lines (the most recent commits)"
                break
            if raw.startswith("@@commit "):
                commit = raw[9:].strip()
            elif raw.startswith("+++ "):
                file = raw[6:].strip() if raw.startswith("+++ b/") else ""
            elif raw.startswith("+") and not raw.startswith("+++") and file:
                line = raw[1:]
                if len(line) < 2000 and any(p.search(line) for p in pats):
                    value = next(m.group(0) for p in pats if (m := p.search(line)))
                    if re.search(r"(?i)example|placeholder|dummy|xxxx|your[_-]|changeme|<", line) or MARK.search(line):
                        continue  # (a `codefactory: ignore` comment on it said it isn't real)
                    if value in current or (file, value) in seen:
                        continue  # still in the code: the current-files check reports it
                    seen.add((file, value))
                    out["history_secret"].hits.append(Evidence(file, 0, f"commit {commit}: {_excerpt(line)}"))
    finally:
        proc.kill()
        proc.stdout.close()
        proc.wait(timeout=timeout)
    if (root / ".git" / "shallow").exists():
        note = (note + "; " if note else "") + "shallow clone: only part of the history was available"
    return note


def current_secrets(secret_check: Check) -> set[str]:
    """The secret values in today's files (history only reports the ones that are gone)."""
    return {m.group(0) for e in secret_check.hits for p in PATTERNS["secret"] if (m := p.search(e.text))}


def find_dockerfiles(root: Path) -> list[Path]:
    skip = {"node_modules", ".git", ".venv", "venv", ".codefactory"}
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and re.fullmatch(r"(?i)dockerfile(\..+)?|.+\.dockerfile", p.name) and not (skip & set(p.parts))
    )  # fmt: skip


def scan_config(root: Path) -> dict[str, Check]:
    """Everything here but git history (which is the same on both sides of a diff)."""
    out = {k: Check(k) for k in KEYS}
    workflows(root, out)
    dockerfiles(root, find_dockerfiles(root), out)
    mobile(root, out)
    return out


def scan(root: Path, current_secrets: set[str]) -> tuple[dict[str, Check], str]:
    out = scan_config(root)
    note = history(root, current_secrets, out)
    return out, note
