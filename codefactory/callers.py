"""A value that is fixed at every caller: a parameter put into SQL, HTML or a shell command is only as risky as what
the callers pass. When every call site in the repository passes a literal (or an escaped value, or a parameter that
is itself fixed at every caller of its own function), nothing from outside reaches the line.

The call-site index is built once per scan, and only when a hit needs it: one pass over the files of a language for
all the function names asked about so far."""

from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from .intent import NUMERIC, interp_safe, safe_names
from .paths import is_test

LANG = {".py": "py", ".go": "go", ".php": "php", ".rb": "rb",
        **{e: "js" for e in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")}}  # fmt: skip
HEADER = {
    "py": [r"^\s*(?:async\s+)?def\s+(\w+)\s*\("],
    "go": [r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*(?:\[[^\]]*\])?\("],
    "php": [r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)\s*\("],
    "rb": [r"^\s*def\s+(?:self\.)?(\w+[?!]?)(?=\s*\(|\s+\w|\s*$)"],
    "js": [
        r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([\w$]+)\s*\(",
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:function\s*\*?\s*[\w$]*\s*)?\(",
        r"^\s*(?:(?:public|private|protected|static|async|override)\s+)*([\w$]+)\s*\("
        r"(?=[^()'\"`]*\)\s*(?::[^={]+)?\{\s*$)",  # a class's method: `name(a, b) {`
    ],
}
NOT_NAMES = {"if", "for", "while", "switch", "catch", "function", "return", "elif", "with", "super"}
DEF_BEFORE = re.compile(r"(?:\bdef|\bfunction\s*\*?|\bfunc(?:\s*\([^)]*\))?|\bfn)\s*&?$")
STR = r"""(?:[rbuRBU]{0,2}'(?:[^'\\\n]|\\.)*'|[rbuRBU]{0,2}"(?:[^"\\\n]|\\.)*"|`[^`]*`)"""
LITERALS = re.compile(rf"{STR}(?:\s*(?:\+|\.)?\s*{STR})*")
TERNARY = re.compile(rf"[^?]+\?\s*{STR}\s*:\s*{STR}|{STR}\s+if\s+.+\s+else\s+{STR}", re.S)
ESCAPING = re.compile(r"(?:[\w$]+\.)*(?:esc|escape\w*|escape_?html|html_?escape|htmlspecialchars|htmlentities|"
                      r"quote_ident\w*|quote\w*|sanitize\w*|encodeURIComponent)\s*\(", re.I)  # fmt: skip
IDENT = re.compile(r"\$?[A-Za-z_$][\w$]*")
MAX_DEFS, MAX_SITES, DEPTH = 3, 100, 3  # a name defined all over (render, run) or called everywhere: not judged


def args_of(s: str) -> list[str] | None:
    """The arguments of a call whose text starts just after `(`, split at top-level commas; None if unreadable."""
    out, cur, depth, i = [], [], 0, 0
    while i < len(s) and i < 4000:
        c = s[i]
        if c in "'\"`":
            q = s[i : i + 3] if s[i : i + 3] in ('"""', "'''") else c
            j = i + len(q)
            while j < len(s) and s[j : j + len(q)] != q:
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i : j + len(q)])
            i = j + len(q)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                if c != ")":
                    return None
                last = "".join(cur).strip()
                return [*out, last] if last or out else out
            depth -= 1
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    return None


def _whole_call(arg: str, m: re.Match) -> bool:
    rest = arg[m.end() :]
    if args_of(rest) is None:
        return False
    depth = 0
    for k, c in enumerate(rest):  # the call must be all of the argument: `esc(a) + b` isn't escaped
        depth += c in "([{"
        depth -= c in ")]}"
        if depth < 0:
            return not rest[k + 1 :].strip()
    return False


def literal(arg: str, lang: str) -> bool:
    a = " ".join(arg.split())
    if NUMERIC.match(a) or re.fullmatch(r"-?\d[\d_.]*[a-zA-Z]?|None|nil|null|true|false|True|False", a):
        return True
    if not (LITERALS.fullmatch(a) or TERNARY.fullmatch(a)):
        return False
    if lang == "rb" and "#{" in a or lang == "php" and re.search(r'"[^"]*\$', a):
        return False  # interpolated in a double-quoted string
    subs = re.findall(r"\$\{([^}]+)\}", a) if lang == "js" else []
    return all(fixed_expr(s, lang) for s in subs)  # a template literal whose values are all escaped or numbers


def fixed_expr(e: str, lang: str) -> bool:
    e = e.strip()
    m = ESCAPING.match(e)
    if (m and _whole_call(e, m)) or literal(e, lang):
        return True
    # a named constant (not a record's `.id`: one read from an API response can carry anyone's text)
    return re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", e) is not None


def params(lines: list[str], i: int, lang: str) -> tuple[str, list[str | None]] | None:
    """The function enclosing line i (the nearest header less indented than everything below it) and its parameter
    names, in call order; None when there is none."""
    indent = lambda s: len(s) - len(s.lstrip())  # noqa: E731
    floor = indent(lines[i - 1])
    for j in range(i - 1, max(0, i - 400), -1):
        ln = lines[j - 1]
        if not ln.strip() or indent(ln) >= floor or ln.lstrip().startswith(("//", "#", "*", "/*")):
            continue
        floor = indent(ln)
        for pat in HEADER[lang]:
            if (m := re.match(pat, ln)) and m.group(1) not in NOT_NAMES:
                text = "\n".join(lines[j - 1 : j + 10])[m.end() :]
                if lang == "rb" and not text.startswith(("(", " (")):
                    text = text.split("\n", 1)[0] + ")"
                got = args_of(text.lstrip("( ") if lang == "rb" else text)
                return (m.group(1), [_param(p, lang) for p in got]) if got is not None else None
        if floor == 0:
            return None
    return None


def _param(p: str, lang: str) -> str | None:
    if lang == "php":
        return m.group(1) if (m := re.search(r"\$(\w+)", p)) else None
    if p.startswith(("*", "...", "{", "[", "&")):
        return None  # spread or destructured: positions after it don't line up
    return m.group(0) if (m := re.match(r"[\w$]+", p)) else None


class Callers:
    def __init__(self, root: Path, files: list[str]):
        self.root, self.files = root, files
        self.sites: dict[tuple[str, str], tuple[int, list]] = {}  # (lang, name) -> (files defining it, call sites)
        self.texts: dict[str, list[str]] = {}

    def lines(self, fid: str) -> list[str]:
        if fid not in self.texts:
            try:
                self.texts[fid] = (self.root / fid).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self.texts[fid] = []
        return self.texts[fid]

    def index(self, lang: str, names: set[str]) -> None:
        """One pass over the language's files for every name not indexed yet."""
        names = {n for n in names if (lang, n) not in self.sites}
        if not names:
            return
        found = {n: (set(), []) for n in names}
        escapes: set[str] = set()
        alt = "|".join(sorted(map(re.escape, names)))
        call = re.compile(r"(?<![\w$])(" + alt + r")\s*\(")
        # the name as a value (`decodeEntities: __BROWSER__ ? decodeHtmlBrowser : undefined`): called from places
        # this index can't see, with arguments it can't read
        bare = re.compile(r"(?<![\w$.])(" + alt + r")(?![\w$]|\s*\()")
        for fid in self.files:
            if LANG.get(Path(fid).suffix) != lang:
                continue
            if is_test(fid):
                continue  # a test passing a literal says nothing about what the product passes
            try:
                text = (self.root / fid).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not any(n in text for n in names):
                continue
            for ln in text.splitlines():
                if not bare.search(ln) or re.match(r"\s*(?:import\b|export\s*\{|from\s+\S+\s+import\b|use\b|#|//|\*)", ln):
                    continue
                code = re.sub(r"""(["'`])(?:(?!\1)[^\\]|\\.)*\1""", '""', ln).split("//")[0]  # not in strings or comments
                for m in bare.finditer(code):
                    if not DEF_BEFORE.search(code[: m.start()]):
                        escapes.add(m.group(1))
            starts = None
            for m in call.finditer(text):
                starts = starts or [0] + [n.end() for n in re.finditer("\n", text)]
                line_start = starts[bisect_right(starts, m.start()) - 1]
                before = text[line_start : m.start()]
                defs, sites = found[m.group(1)]
                end = text.find("\n", m.end())
                if DEF_BEFORE.search(before) or any(re.match(p, text[line_start : end if end >= 0 else None])
                                                    for p in HEADER[lang][2:]):  # a class's method  # fmt: skip
                    defs.add(fid)
                else:
                    sites.append((fid, bisect_right(starts, m.start()), args_of(text[m.end() :])))
        for n, (defs, sites) in found.items():
            self.sites[(lang, n)] = (len(defs), [] if n in escapes else sites)

    def fixed(self, lang: str, name: str, pos: int, keyword: str, depth: int = DEPTH, seen=None) -> bool:
        """Every call of `name` passes a fixed value at parameter `pos` (named `keyword`)."""
        seen = seen or set()
        if (name, pos) in seen:
            return True  # a recursive call passing its own parameter brings in nothing new
        self.index(lang, {name})
        defs, sites = self.sites[(lang, name)]
        if not sites or defs > MAX_DEFS or len(sites) > MAX_SITES or depth <= 0:
            return False
        for fid, line, got in sites:
            if got is None or any(a.startswith(("*", "...")) for a in got):
                return False
            kw = re.compile(r"(\w+)\s*=(?!=)\s*") if lang == "py" else re.compile(r"(?!)")  # Python's keyword arguments
            named = {m.group(1): a[m.end() :] for a in got if (m := kw.match(a))}
            positional = [a for a in got if not kw.match(a)]
            arg = named.get(keyword) if keyword in named else (positional[pos] if pos < len(positional) else None)
            if arg is None or not self._fixed_arg(arg, lang, fid, line, depth, seen | {(name, pos)}):
                return False
        return True

    def _fixed_arg(self, arg: str, lang: str, fid: str, line: int, depth: int, seen: set) -> bool:
        if fixed_expr(arg, lang):
            return True
        lines = self.lines(fid)
        if not 1 <= line <= len(lines) or not IDENT.fullmatch(arg):
            return False
        if interp_safe(arg, safe_names(lines, line)):
            return True
        return self.param_fixed(lines, line, arg.lstrip("$"), lang, depth - 1, seen)

    def param_fixed(self, lines: list[str], i: int, name: str, lang: str, depth: int = DEPTH, seen=None) -> bool:
        """`name` is a parameter of the function around line i, and fixed at every one of its callers."""
        got = params(lines, i, lang)
        if not got or name not in got[1]:
            return False
        ps = got[1][1:] if lang == "py" and got[1][:1] in (["self"], ["cls"]) else got[1]
        return name in ps and self.fixed(lang, got[0], ps.index(name), name, depth, seen)


SINK_NAME = re.compile(r"(?:innerHTML\s*=|__html\s*:|mark_safe\(|\bhtml\()\s*(\$?[A-Za-z_$][\w$]*)\s*[;)}]*\s*$")
FORMAT = re.compile(r"(\bS?printf\s*\(|\bFormat\s*\()|(\.format\s*\()|(?<=['\"])\s*%\s*(\()?")


def hit_values(lines: list[str], i: int, lang: str) -> list[str] | None:
    """The values put into the statement at line i: interpolated, formatted in, joined on, or assigned whole."""
    stmt, k = lines[i - 1], i
    while stmt.count("(") > stmt.count(")") and k < min(len(lines), i + 6):
        stmt, k = stmt + "\n" + lines[k], k + 1
    vals = re.findall(r"\$\{([^}]+)\}", stmt) if lang in ("js", "php") else []
    if lang == "rb":
        vals += re.findall(r"#\{([^}]+)\}", stmt)
    if lang == "py":
        for m in re.finditer(r"\b[fF][rR]?(['\"])(.*?)\1", stmt):
            vals += re.findall(r"\{([^{}:!]+)", m.group(2))
    if lang == "php":
        vals += [v for s in re.findall(r'"(?:[^"\\]|\\.)*"', stmt) for v in re.findall(r"\$(\w+)", s)]
    for m in FORMAT.finditer(stmt):
        if m.group(1) or m.group(2) or m.group(3):
            if (got := args_of(stmt[m.end() :])) is None:
                return None
            vals += got[1:] if m.group(1) else got  # (Sprintf's first argument is the format)
        elif n := IDENT.match(stmt, m.end()):
            vals.append(n.group(0))  # "… %s" % name
    bare = re.sub(STR, '""', stmt)
    op = r"(?:\+|\s\.\s)" if lang == "php" else r"\+"
    vals += re.findall(rf"{op}\s*(\$?[A-Za-z_$][\w$.]*)(?![\w$.]*\s*\()", bare)
    vals += re.findall(rf"(\$?[A-Za-z_$][\w$.]*)\s*{op}", bare)
    if m := SINK_NAME.search(lines[i - 1]):
        vals.append(m.group(1))
    return vals


def drop_fixed(root: Path, files: list[str], out: dict, keys: tuple[str, ...]) -> None:
    """Drop the hits whose only outside values are parameters fixed at every caller."""
    callers, todo = Callers(root, files), []
    for key in keys:
        for e in out[key].hits:
            lang = LANG.get(Path(e.file).suffix)
            lines = callers.lines(e.file) if lang else []
            if not 1 <= e.line <= len(lines) or (vals := hit_values(lines, e.line, lang)) is None:
                continue
            safe = safe_names(lines, e.line)
            open_ = {v.strip() for v in vals if not (fixed_expr(v, lang) or interp_safe(v, safe))}
            if open_ and all(IDENT.fullmatch(v) for v in open_) and (fn := params(lines, e.line, lang)):
                todo.append((key, e, lang, lines, open_, fn[0]))
    if not todo:
        return
    for lang in {t[2] for t in todo}:
        callers.index(lang, {t[5] for t in todo if t[2] == lang})  # one pass for every function asked about
    for key, e, lang, lines, open_, _ in todo:
        if all(callers.param_fixed(lines, e.line, v.lstrip("$"), lang) for v in open_):
            out[key].hits.remove(e)
            out[key].data.pop(f"{e.file}:{e.line}", None)
