"""Renders a graph into one self-contained HTML file (no server, no network) that opens in any browser."""

from __future__ import annotations

import html
import json
from importlib.resources import files

_HERE = files(__package__)


def render_html(graph: dict) -> str:
    template = (_HERE / "template.html").read_text(encoding="utf-8")
    css = (_HERE / "factory.css").read_text(encoding="utf-8")
    js = (_HERE / "factory.js").read_text(encoding="utf-8")
    # "</" can't appear inside a <script> block: escape it so code text in the data can't end the script early.
    data = json.dumps(graph, separators=(",", ":")).replace("</", "<\\/")
    title = html.escape(graph.get("root", "").replace("\\", "/").rstrip("/").split("/")[-1] or "codebase")
    return template.replace("__TITLE__", title).replace("/*CSS*/", css).replace("/*JS*/", js).replace("__DATA__", data)
