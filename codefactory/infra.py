"""Files that aren't application code but decide how it's built, shipped and served: shell scripts and Makefiles,
docker-compose and Kubernetes YAML, Pkl and other configuration, HTML pages, and patch files.

- Credentials written into any of them (the source-code secret patterns, applied to config files too).
- Shell (scripts, and Makefile recipes, which are shell): piping a download into a shell, `rm -rf` on a variable that
  can be empty, `eval` of a variable, and scripts that carry on after a failing command (no `set -e`).
- docker-compose: privileged containers, the host's network, databases published on every interface, passwords
  written into `environment:`.
- Kubernetes: privileged or root containers, the host's network or filesystem, Secrets committed with their values.
- HTML: scripts, styles and frames loaded over plain HTTP, third-party scripts without integrity hashes, forms that
  post over plain HTTP.
- Pkl and other configuration: plain-HTTP URLs to packages and services.

Line checks with the exact line, like the source checks; the same `codefactory: ignore` comments silence them.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .checks import PATTERNS, PLACEHOLDER, VENDOR_SECRETS, Check, Evidence
from .paths import is_test
from .suppress import MARK

SKIP = {"node_modules", ".git", ".codefactory", ".venv", "venv", "dist", "build", "vendor", "Pods", ".expo", "coverage",
        "__pycache__", "site-packages", "target", ".next", ".nuxt"}  # fmt: skip
CONFIG_EXT = (".yml", ".yaml", ".pkl", ".toml", ".ini", ".cfg", ".conf", ".properties", ".tf", ".tfvars", ".hcl")
HTML_EXT = (".html", ".htm")
SHELL_EXT = (".sh", ".bash", ".zsh")
PATCH_EXT = (".diff", ".patch")
MAKEFILES = ("Makefile", "makefile", "GNUmakefile")
MAX_BYTES = 1_000_000

KEYS = ("config_secret", "shell_pipe", "shell_rm_var", "shell_eval", "compose_privileged",
        "compose_exposed", "compose_secret", "k8s_privileged", "k8s_host", "k8s_secret", "html_mixed",
        "html_no_sri", "config_http")  # fmt: skip

# ---- shell
PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|#\n]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:ba|z|da)?sh\b")
# `rm -rf "$DIR/"`, a Make variable `$(BUILD)/` or a recipe's `$$OUT/`: empty, it's `rm -rf /`
RM_VAR = re.compile(
    r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+[\"']?\$\$?(?:\{(\w+)\}|\((\w+)\)|(\w+))[\"']?/"
)
SHELL_EVAL = re.compile(r"^\s*eval\s+[\"']?\$(?!\()")  # not `eval "$(ssh-agent -s)"`: a trusted command's output
# credentials without quotes, as config files write them: `PASSWORD = s3cr3t…`, `password: hunter2…`, `api.key=…`
UNQUOTED_SECRET = re.compile(
    r"^\s*(?:export\s+)?[\w.-]*(?:password|passwd|secret|token|api[_.-]?key|private[_.-]?key)[\w.-]*\s*(?::|\??=|:=)\s*"
    r"(?=[^\s'\"]*\d)([^\s'\"$#{(%][^\s#]{7,})\s*$",
    re.I,
)
# (no "missing set -e" check: whether scripts should use it is a debated choice, and most handle errors on purpose)
HARNESS = re.compile(r"(?:^|/)(?:examples?|samples?|demos?|e2e|playwright|cypress|fixtures|testdata)/", re.I)
# ---- compose / kubernetes
DB_PORTS = {"5432": "PostgreSQL", "3306": "MySQL", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch",
            "5672": "RabbitMQ", "11211": "Memcached", "1433": "SQL Server", "9042": "Cassandra"}  # fmt: skip
PORT = re.compile(r"^\s*-\s*[\"']?(?:(\d+\.\d+\.\d+\.\d+|\[?::1?\]?):)?(\d+):(\d+)[\"']?\s*$")
ENV_SECRET = re.compile(
    r"^\s*-?\s*[\"']?(\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*)[\"']?\s*[:=]\s*(.+)$", re.I
)
# ---- html
TAG_SRC = re.compile(r"<(script|link|iframe|img|form)\b[^>]*?\b(?:src|href|action)\s*=\s*[\"'](http://[^\"']+)[\"'][^>]*>", re.I)
CDN_SCRIPT = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"'](?:https:)?//(?!(?:localhost|127\.0\.0\.1))([^/\"']+)[^\"']*[\"'][^>]*>", re.I
)
LOCAL_HOST = re.compile(
    r"http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|[^/\"']*\.local\b|example\.)"
)
HTTP_URL = re.compile(
    r"""["'`(\s]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.|"""
    r"""json-schema\.org|[\w.-]*\.(?:local|svc|internal)(?=[/:"'`\s]|$))[a-z0-9][^"'`\s)]*""",
    re.I,
)


def files(root: Path, ignore: set[str] | None = None) -> list[str]:
    skip = SKIP | set(ignore or ())
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not (d.startswith(".") and d != ".github"))
        for name in sorted(filenames):
            if name.endswith(CONFIG_EXT + HTML_EXT + SHELL_EXT + PATCH_EXT) or name in MAKEFILES or name.endswith(".mk"):
                out.append(Path(dirpath, name).relative_to(root).as_posix())
    return out


def _read(root: Path, rel: str) -> list[str]:
    try:
        path = root / rel
        if path.stat().st_size > MAX_BYTES:
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _quiet(lines: list[str], i: int, key: str) -> bool:
    """A `codefactory: ignore` on this line or the one above, naming this kind (or none)."""
    for ln in (lines[i - 1], lines[i - 2] if i > 1 else ""):
        m = MARK.search(ln)
        if m and (not m.group(2).strip() or key in m.group(2) or not re.match(r"\s*[a-z_]", m.group(2))):
            return True
    return False


def _hit(out: dict, key: str, rel: str, lines: list[str], i: int, text: str | None = None) -> None:
    if not _quiet(lines, i, key):
        out[key].hits.append(Evidence(rel, i, (text or lines[i - 1].strip())[:140]))


def _secrets(rel: str, lines: list[str], out: dict, unquoted: bool = True) -> None:
    pats = VENDOR_SECRETS if is_test(rel) else PATTERNS["secret"]
    patch = rel.endswith(PATCH_EXT)
    for i, ln in enumerate(lines, 1):
        if len(ln) > 2000 or (patch and not ln.startswith("+")):
            continue
        body = ln[1:] if patch else ln
        if re.search(PLACEHOLDER, body) or re.search(r"\$\{\{|\$\{|\{\{|\$\(", body):
            continue
        if any(p.search(body) for p in pats) or (unquoted and not is_test(rel) and UNQUOTED_SECRET.match(body)):
            _hit(out, "config_secret", rel, lines, i, f"{body.split('=')[0].split(':')[0].strip()[:60]} = ********")


def shell(rel: str, lines: list[str], out: dict, makefile: bool = False) -> None:
    """Shell scripts, and the recipes of a Makefile (each recipe line runs in a shell)."""
    text = "\n".join(lines)
    # `set -u` (or `#!/bin/sh -eu`): an unset variable stops the script before `rm -rf "$X/"` can run
    guarded = re.search(r"^\s*set\s+-[a-zA-Z]*u|set -o nounset|^#!\S+\s+-[a-zA-Z]*u", text, re.M)
    for i, ln in enumerate(lines, 1):
        code = ln.split(" #", 1)[0] if not makefile else ln
        if makefile and not ln.startswith("\t"):
            continue
        if re.match(r"\s*#", code):
            continue
        if PIPE_TO_SHELL.search(re.sub(r"'[^']*'|\"[^\"]*\"", "''", code)):  # not inside a message: echo 'curl … | sh'
            _hit(out, "shell_pipe", rel, lines, i)
        m = RM_VAR.search(code)
        name = m and (m.group(1) or m.group(2) or m.group(3))
        if m and not guarded and not re.search(rf"\$\{{{name}:[?]", code):
            _hit(out, "shell_rm_var", rel, lines, i)
        if SHELL_EVAL.search(code):
            _hit(out, "shell_eval", rel, lines, i)


def compose(rel: str, lines: list[str], out: dict) -> None:
    in_ports = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if re.match(r"privileged:\s*true\b", s):
            _hit(out, "compose_privileged", rel, lines, i)
        if re.match(r"network_mode:\s*[\"']?host\b", s):
            _hit(out, "compose_privileged", rel, lines, i)
        if re.match(r"ports:\s*$", s):
            in_ports = True
            continue
        if in_ports:
            m = PORT.match(ln)
            if m:
                host_ip, inside = m.group(1), m.group(3)
                if inside in DB_PORTS and not (host_ip or "").startswith(("127.", "[::1]", "::1")):
                    _hit(out, "compose_exposed", rel, lines, i, f"{s}  ({DB_PORTS[inside]} on every interface)")
            elif s and not s.startswith("#"):
                in_ports = False
        m = ENV_SECRET.match(ln)
        if m:
            value = m.group(2).strip().strip("'\"")
            if (len(value) >= 6 and not m.group(1).upper().endswith("_FILE") and not value.startswith("/")
                    and not re.search(PLACEHOLDER + r"|^\$|changethis|^secret$|^password$", value, re.I)):  # fmt: skip
                _hit(out, "compose_secret", rel, lines, i, f"{m.group(1)}: {'*' * 8}")


def kubernetes(rel: str, lines: list[str], out: dict) -> None:
    text = "\n".join(lines)
    starts = [0] + [m.end() for m in re.finditer(r"^---[ \t]*\n", text, re.M)]
    for begin, end in zip(starts, [*starts[1:], len(text)], strict=True):  # each YAML document
        doc = text[begin:end]
        if re.search(r"^kind:\s*Secret\s*$", doc, re.M) and re.search(r"^(?:data|stringData):\s*\n\s+\w+:\s*\S", doc, re.M):
            name = re.search(r"^\s+name:\s*(\S+)", doc, re.M)  # point at the Secret's name: that's what to look up
            at = begin + (name.start(1) if name else doc.find("kind:"))
            label = f"Secret {name.group(1)}" if name else "a Secret"
            _hit(out, "k8s_secret", rel, lines, text.count("\n", 0, at) + 1, f"{label} with its values in the repository")
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if re.match(r"(?:privileged|allowPrivilegeEscalation):\s*true\b", s) or re.match(r"runAsUser:\s*0\b", s):
            _hit(out, "k8s_privileged", rel, lines, i)
        if re.match(r"(?:hostNetwork|hostPID|hostIPC):\s*true\b", s) or re.match(r"hostPath:\s*$", s):
            _hit(out, "k8s_host", rel, lines, i)


def html(rel: str, lines: list[str], out: dict) -> None:
    for i, ln in enumerate(lines, 1):
        for m in TAG_SRC.finditer(ln):
            if not LOCAL_HOST.match(m.group(2)):
                _hit(out, "html_mixed", rel, lines, i)
        for m in CDN_SCRIPT.finditer(ln):
            if "integrity=" not in m.group(0).lower():
                _hit(out, "html_no_sri", rel, lines, i, f"<script src=…{m.group(1)}…> without integrity=")


def config_http(rel: str, lines: list[str], out: dict) -> None:
    for i, ln in enumerate(lines, 1):
        if re.match(r"\s*(?:#|//|;)", ln):
            continue
        if HTTP_URL.search(ln) and re.search(r"url|uri|endpoint|host|server|registry|repo|source|amends|import|"
                                             r"package|mirror|proxy|base|api|href", ln, re.I):  # fmt: skip
            _hit(out, "config_http", rel, lines, i)


def scan(root: Path, ignore: set[str] | None = None) -> dict[str, Check]:
    out = {k: Check(k) for k in KEYS}
    for rel in files(root, ignore):
        lines = _read(root, rel)
        if not lines:
            continue
        name = rel.rsplit("/", 1)[-1]
        test = is_test(rel)
        head = "\n".join(lines[:400])
        compose_file = name.endswith((".yml", ".yaml")) and (
            re.search(r"^services:\s*$", head, re.M) or re.search(r"^kind:\s*Secret\s*$", head, re.M)
        )  # compose passwords and Kubernetes Secrets have their own findings
        if not name.endswith(SHELL_EXT):  # scripts are source: the source check covers their credentials
            _secrets(rel, lines, out, unquoted=not compose_file)  # compose passwords have their own finding
        if test or rel.startswith(".github/workflows/") or HARNESS.search(rel):
            continue  # tests, demos and e2e harnesses may do anything; workflows have their own checks (audit.py)
        if name.endswith(SHELL_EXT):
            shell(rel, lines, out)
        elif name in MAKEFILES or name.endswith(".mk"):
            shell(rel, lines, out, makefile=True)
        elif name.endswith((".yml", ".yaml")):
            text = "\n".join(lines[:400])
            if re.search(r"^services:\s*$", text, re.M):
                compose(rel, lines, out)
            if re.search(r"^apiVersion:\s*\S", text, re.M) and re.search(r"^kind:\s*\S", text, re.M):
                kubernetes(rel, lines, out)
        elif name.endswith(HTML_EXT):
            html(rel, lines, out)
        if name.endswith((".pkl", ".toml", ".ini", ".cfg", ".conf", ".properties", ".tf", ".hcl")):
            config_http(rel, lines, out)
    from .paths import drop_ignored

    return drop_ignored(out, root)
