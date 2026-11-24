"""Keeps Claude Code's codefactory current in a repository.

- The skill (.claude/skills/codefactory/SKILL.md) teaches Claude when and how to use each command. It carries the
  version that wrote it; any codefactory run in that repository rewrites it when it's older, so Claude never works
  from instructions for commands that changed.
- The session-start hook (.claude/hooks/codefactory.sh, registered in .claude/settings.json) installs codefactory if
  it's missing and upgrades it at most once a day, then refreshes the skill. It never blocks or fails a session.
- `codefactory update` upgrades the installed tool on demand.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from . import __version__

SOURCE = "codefactory[languages] @ git+https://github.com/dominickkubica/codefactory"
STAMP = re.compile(r"<!-- codefactory skill (\S+) -->")
HOOK_NAME = "codefactory.sh"
HOOK_COMMAND = f'"$CLAUDE_PROJECT_DIR"/.claude/hooks/{HOOK_NAME}'


def skill_path(repo: Path) -> Path:
    return repo / ".claude" / "skills" / "codefactory" / "SKILL.md"


def skill_text() -> str:
    text = (files("codefactory") / "skill_template" / "SKILL.md").read_text(encoding="utf-8")
    # the stamp goes right after the front matter, which must stay first for Claude Code to read the skill
    head, sep, body = text.partition("\n---\n")
    return f"{head}{sep}<!-- codefactory skill {__version__} -->\n{body}" if sep else text


def install_skill(repo: Path) -> Path:
    if not repo.is_dir():
        raise ValueError(f"{repo} is not a folder")
    target = skill_path(repo)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(skill_text(), encoding="utf-8")
    return target


def refresh_skill(repo: Path) -> bool:
    """Rewrites the repository's skill if an older codefactory wrote it. True if it did. Never raises."""
    try:
        target = skill_path(repo)
        if not target.is_file():
            return False
        text = target.read_text(encoding="utf-8")
        current = STAMP.search(text)
        if current and current.group(1) == __version__:
            return False
        if current and STAMP.sub("", text) == STAMP.sub("", skill_text()):
            return False  # same instructions: don't leave a version-only diff in the repository
        target.write_text(skill_text(), encoding="utf-8")
        return True
    except OSError:
        return False


HOOK_SCRIPT = """#!/bin/bash
# codefactory for Claude Code (installed by `codefactory skill --hook`).
# At each session start: install codefactory if it's missing, upgrade it at most once a day, and refresh this
# repository's codefactory skill. Any failure is ignored: this never blocks or breaks a session.
set -u
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

SOURCE="__SOURCE__"
PY=""
for c in python3 python py; do # the first that really runs (Windows has a python3 stub that doesn't)
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || exit 0
STAMP="${HOME:-/tmp}/.cache/codefactory/last-update"
mkdir -p "$(dirname "$STAMP")" 2>/dev/null

install() { # $1: what to install
  if command -v timeout >/dev/null 2>&1; then timeout 180 "$PY" -m pip install --quiet --upgrade "$1" >/dev/null 2>&1
  else "$PY" -m pip install --quiet --upgrade "$1" >/dev/null 2>&1; fi
}

if [ -f ../codefactory/pyproject.toml ]; then
  # a checkout of codefactory next to this repository (a cloud session with both attached): use it as is
  "$PY" -c "import codefactory" 2>/dev/null || install -e "../codefactory[languages]"
elif ! "$PY" -c "import codefactory" 2>/dev/null || [ -z "$(find "$STAMP" -mmin -1440 2>/dev/null)" ]; then
  install "$SOURCE" && touch "$STAMP"
fi

if "$PY" -c "import codefactory" 2>/dev/null; then
  "$PY" -m codefactory skill . >/dev/null 2>&1
  V="$("$PY" -c 'import codefactory; print(codefactory.__version__)')"
  echo "codefactory $V is installed: see .claude/skills/codefactory/SKILL.md"
fi
exit 0
"""


def install_hook(repo: Path) -> tuple[Path, Path]:
    """Writes the hook script and registers it as a SessionStart hook, keeping everything else in settings.json."""
    hook = repo / ".claude" / "hooks" / HOOK_NAME
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK_SCRIPT.replace("__SOURCE__", SOURCE), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    settings_file = repo / ".claude" / "settings.json"
    try:
        settings = json.loads(settings_file.read_text(encoding="utf-8")) if settings_file.is_file() else {}
    except ValueError as e:
        raise ValueError(f"{settings_file} isn't valid JSON ({e}); fix it, then run this again") from None
    groups = settings.setdefault("hooks", {}).setdefault("SessionStart", [])
    registered = any(h.get("command") == HOOK_COMMAND for g in groups for h in g.get("hooks", []))
    if not registered:
        groups.append({"hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 240}]})
    settings_file.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return hook, settings_file


def update(source: str = SOURCE) -> tuple[str, str]:
    """Upgrades codefactory with this Python's pip. Returns (old version, new version)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", source], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pip couldn't upgrade codefactory:\n{proc.stderr.strip()[-1500:]}")
    new = subprocess.run(
        [sys.executable, "-c", "import codefactory; print(codefactory.__version__)"], capture_output=True, text=True
    ).stdout.strip()
    return __version__, new or "?"
