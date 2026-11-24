"""Installs the Claude Code skill that teaches an agent working in a repo when and how to use codefactory."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def install_skill(repo: Path) -> Path:
    if not repo.is_dir():
        raise SystemExit(f"codefactory: {repo} is not a folder")
    target = repo / ".claude" / "skills" / "codefactory" / "SKILL.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text((files("codefactory") / "skill_template" / "SKILL.md").read_text(encoding="utf-8"), encoding="utf-8")
    return target
