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

from .checks import ANY, PATTERNS, PLACEHOLDER, VENDOR_SECRETS, Check, Evidence, redact
from .paths import drop_ignored, is_dev_setup, is_test, is_vendored, links_outside, walk
from .suppress import MARK

# GitHub Actions
PR_TARGET = re.compile(r"^(?!\s*#).*\bpull_request_target\b", re.M)  # also `on: pull_request_target`, `on: [push, …]`
# checking out the PR's code: a checkout's `ref:` set to the head, or a command that fetches it. The head sha used
# elsewhere (an env var for looking up artifacts) is just a string.
HEAD_CHECKOUT = re.compile(
    r"^\s*ref:\s*\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)|gh pr checkout|"
    r"git (?:fetch|checkout)[^\n]*(?:refs/pull/|pull_request\.head|head_ref)",
    re.M,
)
SCRIPT_KEY = re.compile(r"^(\s*)(?:-\s+)?(run|script):\s*(.*)$")
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"[\w.\[\]*]*\.(?:title|body|head_ref|label|message|name|email|ref)|head_ref)\s*\}\}"
)
USES = re.compile(r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)", re.M)
FIRST_PARTY = ("actions/", "github/")
VENDORED = re.compile(r"(?:^|/)(?:\.yarn|vendor|node_modules|dist|build|third_party|bower_components)/|\.min\.(?:js|css)$")
# Dockerfiles
FROM = re.compile(r"^[ \t]*FROM\s+(\S+)", re.I | re.M)  # [ \t], not \s: \s would start on a blank line above
USER = re.compile(r"^[ \t]*USER\s+(\S+)", re.I | re.M)
ENV_SECRET = re.compile(
    r"^[ \t]*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY)\w*[= ]\s*\S+", re.I | re.M
)
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
        if links_outside(root, rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        line_of = _line(text, m.start()) if (m := PR_TARGET.search(text)) else 0
        if m and "zizmor: ignore[dangerous-triggers]" in lines[line_of - 1]:
            m = None  # the authors ran zizmor (a workflow security linter) and decided this trigger is safe
        if m:
            # runs with the repository's secrets and write access, on code from a fork: dangerous only if it checks
            # that code out (or builds it); otherwise it's the safe way to label or comment on a PR
            danger = HEAD_CHECKOUT.search(text)
            out["gha_pr_target"].hits.append(
                Evidence(rel, _line(text, m.start()), "pull_request_target" + (" + checks out the PR's code" if danger else ""))
            )
            out["gha_pr_target"].data[rel] = "checkout" if danger else "trigger"
        for i in _script_lines(lines):  # only text a shell (run:) or github-script (script:) executes
            if UNTRUSTED.search(lines[i - 1]) and not lines[i - 1].strip().startswith("#"):
                out["gha_injection"].hits.append(Evidence(rel, i, _excerpt(lines[i - 1])))
        for m in USES.finditer(text):
            action, ref = m.group(1), m.group(2)
            if not action.startswith(FIRST_PARTY) and not re.fullmatch(r"[0-9a-f]{40}", ref):
                out["gha_unpinned"].hits.append(Evidence(rel, _line(text, m.start()), f"{action}@{ref}"))


def _script_lines(lines: list[str]) -> list[int]:
    """1-based numbers of the lines inside `run:` and `script:` values (inline or block)."""
    out, block_indent = [], None
    for i, ln in enumerate(lines, 1):
        if block_indent is not None:
            if not ln.strip() or len(ln) - len(ln.lstrip()) > block_indent:
                out.append(i)
                continue
            block_indent = None
        m = SCRIPT_KEY.match(ln)
        if m:
            if m.group(3).strip() in ("|", ">", "|-", ">-", "|+", ">+", ""):
                block_indent = ln.find(m.group(2))  # the block is everything indented past the key itself
            else:
                out.append(i)
    return out


DROP_ROOT = re.compile(r"\b(?:su-exec|gosu|setpriv|runuser|s6-setuidgid|chpst\s+-u|setuidgid)\b")


# official images whose program doesn't run as root. The database images start as root and their entrypoint switches
# to the database's own user, but only to run the database: a Dockerfile that replaces the ENTRYPOINT or CMD runs its
# own program as root. These others set a non-root USER in the image itself, which a CMD doesn't undo.
DB_ENTRYPOINT_DROPS = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?"
    r"(?:postgres|postgis/postgis|mysql|mariadb|mongo|redis|rabbitmq|couchdb)(?::\S+)?(?:\s|$)",
    re.I,
)
USER_IN_IMAGE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?"
    r"(?:bitnami/[\w.-]+|grafana/grafana[\w-]*|jenkins/jenkins|sonarqube|(?:docker\.elastic\.co/elasticsearch/)?elasticsearch|"
    r"opensearchproject/opensearch|quay\.io/keycloak/keycloak|keycloak/keycloak)(?::\S+)?(?:\s|$)",
    re.I,
)


def _base_drops_root(final: str, text: str) -> bool:
    """The final stage builds on an official image whose program runs as its own user, and doesn't swap the
    program out from under a database image's entrypoint."""
    stage = text[text.rfind(final) :]
    if USER_IN_IMAGE.match(final.strip()):
        return True
    return DB_ENTRYPOINT_DROPS.match(final.strip()) is not None and not re.search(r"^\s*(?:ENTRYPOINT|CMD)\b", stage, re.M | re.I)


def _drops_root(root: Path, dockerfile: Path, text: str) -> bool:
    """Starts as root only to switch user before the program runs: `su-exec`/`gosu` in the Dockerfile or in the
    entrypoint script it copies in (syncthing's docker-entrypoint.sh)."""
    # (in the Dockerfile itself, a use, not the line installing it: gitea installs su-exec and still runs s6 as root)
    if any(
        DROP_ROOT.search(ln)
        and not ln.lstrip().startswith("#")
        and not re.search(r"\b(?:apk|apt-get|apt|yum|dnf)\b|^\s*\\?\s*[\w.-]+\s*\\\s*$", ln)
        for ln in text.splitlines()
    ):
        return True
    for script in set(re.findall(r"[\w./-]+\.sh\b", text)):
        parts = script.strip("/").split("/")
        # (`/src/script/docker-entrypoint.sh` is a build stage's path: try each tail of it in the repository)
        for base, tail in ((b, "/".join(parts[i:])) for b in (dockerfile.parent, root) for i in range(len(parts))):
            p = (base / tail).resolve()
            if p.is_file() and p.is_relative_to(root.resolve()):
                try:
                    if DROP_ROOT.search(p.read_text(encoding="utf-8", errors="replace")[:200_000]):
                        return True
                except OSError:
                    pass
    return False


def _cleartext_local_only(manifest: Path, text: str) -> bool:
    """The manifest's network security config permits cleartext only to local hosts (10.0.2.2, localhost): it
    overrides usesCleartextTraffic. A base-config permitting it (immich) still counts."""
    m = re.search(r'networkSecurityConfig\s*=\s*"@xml/(\w+)"', text)
    if not m:
        return False
    for base in (manifest.parent, manifest.parent.parent):
        for cfg in base.rglob(f"xml/{m.group(1)}.xml"):
            try:
                xml = cfg.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r'<base-config[^>]*cleartextTrafficPermitted\s*=\s*"true"', xml):
                return False
            blocks = re.findall(
                r'<domain-config[^>]*cleartextTrafficPermitted\s*=\s*"true"[^>]*>(.*?)</domain-config>', xml, re.S
            )
            hosts = [h.strip() for b in blocks for h in re.findall(r"<domain[^>]*>([^<]+)</domain>", b)]
            return all(h in ("10.0.2.2", "localhost", "127.0.0.1", "10.0.3.2") for h in hosts)
    return False


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
        final = text[froms[-1].start() :].split("\n", 1)[0]  # the whole line: `FROM node:22 AS dev`
        tests_image = re.search(r"^\s*COPY\s+[^\n]*\b(?:tests?|phpunit[\w.]*|pytest[\w.]*|jest\.config\w*)\b", text, re.M | re.I)
        dev = is_dev_setup(rel) or tests_image or re.search(r"\bAS\s+(?:dev|develop\w*|test\w*|ci)\s*$", final, re.I)  # (a final
        # stage named `build` still ships: cal.com's API image)
        nonroot = re.search(r"nonroot|distroless|chainguard|rootless|unprivileged", final, re.I)
        # a base image other Dockerfiles build on (`Dockerfile.base`, `images/n8n-base/`): the shipped one sets USER
        base = re.search(r"(?:^|/)Dockerfile\.base$|(?:^|/)base\.Dockerfile$|(?:^|[/_-])base/Dockerfile(?:\.[\w-]+)?$", rel, re.I)
        exempt = dev or nonroot or base or is_vendored(rel) or _base_drops_root(final, text) or _drops_root(root, path, text)
        if (not users or users[-1] in ("root", "0", "0:0")) and not exempt:
            out["docker_root"].hits.append(Evidence(rel, _line(text, froms[-1].start()), f"no USER after {froms[-1].group(1)}"))
        for m in froms:
            image = m.group(1)
            if image.lower() == "scratch" or image.startswith("$") or "@sha256:" in image:
                continue
            tag = image.split("/")[-1].partition(":")[2]
            if not tag or tag == "latest":
                out["docker_latest"].hits.append(Evidence(rel, _line(text, m.start()), f"FROM {image}"))
        for m in ENV_SECRET.finditer(text):
            # (a build argument's stand-in, `ARG NEXTAUTH_SECRET=secret`, is replaced at build time)
            if not re.search(
                r"\$\{?\w+|changeme|example|<|=\s*['\"]?(?:secret|password|changeit|dummy)['\"]?\s*$", m.group(0), re.I
            ):
                out["docker_secret"].hits.append(Evidence(rel, _line(text, m.start()), redact(_excerpt(m.group(0)))))


def mobile(root: Path, out: dict[str, Check]) -> None:
    names = ("app.json", "app.config.json", "Info.plist", "AndroidManifest.xml")
    found = (root / rel for rel in walk(root, names=names))
    for path in sorted(found):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in (ATS, CLEARTEXT):
            if pat is CLEARTEXT and _cleartext_local_only(path, text):
                continue  # the network security config allows it only to the emulator's host (eShop: 10.0.2.2)
            if m := pat.search(text):
                out["mobile_cleartext"].hits.append(Evidence(rel, _line(text, m.start()), _excerpt(m.group(0))))


def _now(root: Path, file: str, texts: dict[str, str]) -> str:
    """The file's current text ("" if it's gone): a key still there isn't a deleted one, even when a
    `codefactory: ignore` comment keeps the current-files check quiet about it."""
    if file not in texts:
        try:
            texts[file] = (root / file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            texts[file] = ""
    return texts[file]


def history(root: Path, current: set[str], out: dict[str, Check], max_lines: int = 400_000, timeout: int = 60) -> str:
    """Secrets added in any commit (and branch) that aren't in the current files: deleted, but still leaked. Returns a
    note on how much history was read ("" when everything was)."""
    inside = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    if inside.stdout.strip() != "true":  # (a monorepo's subfolder has no .git of its own, but is in a repository)
        return "not a git repository: history not checked"
    try:
        proc = subprocess.Popen(
            ["git", "-C", str(root), "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0", "--format=@@commit %h %as",
             "--relative", "--", "."],  # this folder only, paths relative to it (a monorepo package)
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
        )  # fmt: skip
    except OSError:
        return "git isn't available: history not checked"
    commit, file, seen, read, note = "", "", set(), 0, ""
    texts: dict[str, str] = {}
    pats = PATTERNS["secret"]
    import threading

    watchdog = threading.Timer(timeout, proc.kill)  # git stalled or slow: stop it, and say what was read
    watchdog.daemon = True
    watchdog.start()
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
                if len(line) > 500 or VENDORED.search(file):
                    continue  # minified or vendored code (a bundled yarn release, dist/, vendor/): not anyone's key
                if not ANY["secret"].search(line):
                    continue  # one search rules out almost every line
                use = VENDOR_SECRETS if is_test(file) else pats  # test fixtures: only real credential formats
                if any(p.search(line) for p in use):
                    value = next(m.group(0) for p in use if (m := p.search(line)))
                    if re.search(PLACEHOLDER, line) or MARK.search(line):
                        continue  # (a `codefactory: ignore` comment on it said it isn't real)
                    if value in current or (file, value) in seen or value in _now(root, file, texts):
                        continue  # still in the code: the current-files check reports it (or it was marked as intended)
                    seen.add((file, value))
                    out["history_secret"].hits.append(Evidence(file, 0, f"commit {commit}: {redact(_excerpt(line))}"))
    finally:
        timed_out = not watchdog.is_alive() and proc.poll() not in (0, None) and read <= max_lines
        watchdog.cancel()
        proc.kill()
        proc.stdout.close()
        proc.wait(timeout=timeout)
    if timed_out and not note:
        note = f"history read for {timeout} s, then stopped ({read:,} changed lines, the most recent commits)"
    shallow = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True)
    if shallow.stdout.strip() == "true":
        note = (note + "; " if note else "") + "shallow clone: only part of the history was available"
    return note


def current_secrets(secret_check: Check, root: Path | None = None) -> set[str]:
    """The secret values in today's files (history only reports the ones that are gone). Reported text is redacted,
    so the values are read again from each reported line."""
    lines = []
    for e in secret_check.hits:
        try:
            lines.append((root / e.file).read_text(encoding="utf-8", errors="replace").splitlines()[e.line - 1])
        except (OSError, IndexError, TypeError):
            lines.append(e.text)
    return {m.group(0) for line in lines for p in PATTERNS["secret"] if (m := p.search(line))}


def find_dockerfiles(root: Path) -> list[Path]:
    return sorted(
        root / rel for rel in walk(root) if re.fullmatch(r"(?i)dockerfile(\..+)?|.+\.dockerfile", rel.rsplit("/", 1)[-1])
    )


def scan_config(root: Path) -> dict[str, Check]:
    """Everything here but git history (which is the same on both sides of a diff)."""
    out = {k: Check(k) for k in KEYS}
    workflows(root, out)
    dockerfiles(root, find_dockerfiles(root), out)
    mobile(root, out)
    return drop_ignored(out, root)


def scan(root: Path, current_secrets: set[str]) -> tuple[dict[str, Check], str]:
    out = scan_config(root)
    note = history(root, current_secrets, out)
    return drop_ignored(out, root), note
