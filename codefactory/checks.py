# codefactory: ignore-file secret, eval, shell, tls_off, raw_html, plain_http, swallowed, debug_on, cors_any, insecure_cookie, jwt_unverified, weak_cipher, weak_hash, weak_random, secret_key_literal, sensitive_storage — the patterns themselves  # noqa: E501
"""Repository and source checks for the review: security, reliability, delivery, dependencies, docs, testing.

Pattern checks read the source text (any comment style, both languages); repository checks read manifests and CI
files. Each returns Evidence: where (file:line), what was seen, and a short excerpt, so a reader can verify it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .brief import View
from .intent import interp_safe, push_skip_explained, safe_names, swallow_intent
from .paths import is_test, is_vendored, links_outside
from .suppress import MARK
from .suppress import _parse as parse_mark

SRC_EXT = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts",
    ".go", ".java", ".kt", ".kts", ".swift", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".scala",
    ".dart", ".lua", ".ex", ".exs", ".m", ".mm", ".sh",
)  # fmt: skip


@dataclass
class Evidence:
    file: str
    line: int
    text: str  # the line, trimmed

    def at(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Check:
    key: str
    hits: list[Evidence] = field(default_factory=list)
    data: dict = field(default_factory=dict)


# ---- source patterns ------------------------------------------------------------------------------------------------

PATTERNS: dict[str, list[re.Pattern]] = {
    "secret": [
        # a key block: the header ends its line, or key data follows it in a string. Not a sentence about one
        # ("wrapped within -----BEGIN … END-----") or a format check (`starts_with("-----BEGIN PRIVATE KEY-----")`)
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[ \t]*$|"
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----(?:\\r)?\\n[A-Za-z0-9+/=]{16,}"
        ),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b"),
        re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"),
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        re.compile(
            r"""(?i)\b\w*(?:api[_-]?key|secret|token|passw(?:or)?d|auth)\w*\s*[:=]\s*['"](?=[^'"]*\d)[A-Za-z0-9+/_\-]{20,}['"]"""
        ),
    ],
    "eval": [
        re.compile(r"(?<![\w.])eval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"(?<![\w.])exec\s*\(\s*[^)]"),
        re.compile(r"\bpickle\.loads?\s*\("),
        re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"),
    ],
    "shell": [
        re.compile(r"shell\s*=\s*True"),
        re.compile(r"\bos\.system\s*\((?!\s*[\"'][^\"'{}%]*[\"']\s*\))"),  # not a fixed command: os.system("clear")
        re.compile(r"\bexecSync\s*\(\s*`[^`]*\$\{"),
        re.compile(r"\bchild_process\b.*\bexec\s*\("),
        re.compile(r"(?<![\w.])(?:system|exec|spawn|IO\.popen|shell_exec|passthru)\s*\(?\s*\"[^\"]*(?:#|\$)\{"),
        re.compile(r"`[^`]*#\{[^}]+\}[^`]*`|%x[({][^)}]*#\{"),
        re.compile(r"(?<![\w.])exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),  # child_process exec()
        re.compile(r"exec\.Command(?:Context)?\((?:\s*ctx\s*,)?\s*\"(?:ba|z)?sh\"\s*,\s*\"-c\"\s*,(?!\s*\"[^\"]*\"\s*\))"),  # Go
    ],
    "tls_off": [
        re.compile(r"verify\s*=\s*False"),
        re.compile(r"rejectUnauthorized\s*:\s*false"),
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED"),
        re.compile(r"ssl\._create_unverified_context"),
        re.compile(r"CERT_NONE"),
        re.compile(r"InsecureSkipVerify:\s*true"),  # Go
    ],
    "raw_html": [
        re.compile(r"dangerouslySetInnerHTML"),
        re.compile(r"\.innerHTML\s*=(?!=)(?!\s*(?:\"\"|''|``)\s*;?\s*$)"),  # not clearing it: `el.innerHTML = ""`
        re.compile(r"\bv-html\b"),
        re.compile(r"\{[{%][^}%\n]*\|\s*safe\b"),  # a template's `{{ x | safe }}`, not `allow|safe` in a regex
        re.compile(r"\bmark_safe\s*\("),
    ],
    "plain_http": [
        re.compile(
            r"""['"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas\.|www\.w3\.org|xmlns)[a-z0-9][^'"`\s]*""", re.I
        )
    ],
    "swallowed": [
        re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
        re.compile(r"\.catch\(\s*\(\s*\)\s*=>\s*(?:\{\s*\}|undefined|null)\s*\)"),
        re.compile(r"except(?:\s+[\w.(), ]+)?\s*:\s*pass\b"),
    ],
}
PATTERNS.update(
    {
        "debug_on": [
            re.compile(r"^\s*DEBUG\s*=\s*True\b"),
            re.compile(r"\.run\([^)]*debug\s*=\s*True"),
            re.compile(r"\bapp\.debug\s*=\s*True"),
            re.compile(r"FLASK_DEBUG\s*=\s*['\"]?1"),
        ],
        "cors_any": [
            re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]"),
            re.compile(r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True"),
            re.compile(r"Access-Control-Allow-Origin['\"]\s*[,:]\s*['\"]\*"),
            re.compile(r"\borigin\s*:\s*['\"]\*['\"]"),
            re.compile(r"(?<![\w.])CORS\(\s*app\s*\)"),
            re.compile(r"(?<![\w.])cors\(\s*\)"),
        ],
        "insecure_cookie": [
            re.compile(r"(?:SESSION|CSRF)_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False"),
            re.compile(r"(?:secure|httponly)\s*=\s*False"),
            re.compile(r"(?:httpOnly|secure)\s*:\s*false"),
        ],
        "jwt_unverified": [
            re.compile(r"verify_(?:signature|exp)['\"]?\s*:\s*False"),
            re.compile(r"jwt\.decode\([^)]*verify\s*=\s*False"),
            re.compile(r"algorithms?\s*[:=]\s*\[?\s*['\"]none['\"]", re.I),
            re.compile(r"ignoreExpiration\s*:\s*true"),
        ],
        "weak_cipher": [
            re.compile(r"AES\.MODE_ECB|/ECB/|['\"]aes-\d+-ecb['\"]", re.I),
            re.compile(r"\b(?:DES|DES3|RC4|ARC4|Blowfish)\.new\(|createCipheriv\(\s*['\"](?:des|rc4|bf)", re.I),
        ],
        "weak_hash": [
            re.compile(r"hashlib\.(?:md5|sha1)\(|createHash\(\s*['\"](?:md5|sha1)['\"]"),
            re.compile(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\""),
            re.compile(r"\b(?:md5|sha1)\.(?:Sum|New)\(|\bInsecure\.(?:MD5|SHA1)\b|\bDigest::(?:MD5|SHA1)\b"),
        ],
        "weak_random": [
            re.compile(r"(?<![\w.])random\.(?:random|randint|choice|choices|getrandbits|randrange)\("),
            re.compile(r"Math\.random\(\)"),
            # Go's math/rand (crypto/rand has none of these): rand.Intn, rand.Int63, rand.Uint64…
            re.compile(r"(?<![\w.])rand\.(?:Intn|Int63n?|Int31n?|Uint32|Uint64|Float64|Perm|Shuffle)\("),
        ],
        "secret_key_literal": [
            re.compile(r"^\s*(?:SECRET_KEY|JWT_SECRET(?:_KEY)?|SESSION_SECRET)\s*=\s*['\"][^'\"]{6,}['\"]"),
            re.compile(r"\bapp\.secret_key\s*=\s*['\"][^'\"]{6,}['\"]"),
        ],
        "sensitive_storage": [
            re.compile(
                r"(?:AsyncStorage|localStorage|sessionStorage)\.setItem\(\s*['\"`][^'\"`]*"
                r"(?:token|password|passwd|secret|jwt|credential|api_?key)",
                re.I,
            ),
        ],
    }
)
# Single patterns that mean something else in other languages: Python's exec() runs code; JavaScript's exec() is
# child_process (a shell) and Ruby's and PHP's replace or start a process.
ONLY_IN = {
    PATTERNS["eval"][2]: (".py",),
    PATTERNS["shell"][-2]: (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    PATTERNS["shell"][-1]: (".go",),
}
COMMENT_LINE = re.compile(r"\s*(?:#|//|\*|/\*|<!--|--\s)")
# words that say a credential-looking value isn't real ("xoxb-not-a-real-token", "sk_test_fake…", "<your key>")
PLACEHOLDER = r"(?i)example|placeholder|dummy|xxxx|your[_-]|changeme|<|not[-_ ]?a[-_ ]?real|fake|redacted|sample|mock"
# Checks for built-ins only some languages have: Go's eval() or Java's exec() are ordinary functions.
LANG_ONLY = {
    "eval": (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php"),
    "shell": (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php", ".go"),
}
# In tests, keys are fixtures (a PEM block in an example, "secret = 'xxxx…'"): only real credential formats count there,
# because a live AWS, GitHub, Slack, Stripe or Google key in a test is as leaked as anywhere else.
VENDOR_SECRETS = PATTERNS["secret"][1:6]
# Lines that only count when they're about something security-sensitive: an md5 for a cache key or Math.random() for a
# chart colour is fine; for a password, a token or a session it isn't.
CONTEXT = {
    "insecure_cookie": re.compile(r"cookie|session|csrf", re.I),
    "weak_hash": re.compile(
        r"passw|pwd|secret|signature|\bsign\(|hmac|credential|otp|salt|"
        r"(?:access|refresh|reset|auth|csrf|session|api|bearer)[_ -]?(?:token|key)",
        re.I,
    ),
    # a bare "token" is too vague (a draft id, a list key): it needs to be named for what it guards
    "weak_random": re.compile(
        r"(?:access|refresh|reset|auth|csrf|session|api|invite|verif\w*|bearer|login|magic)[_ -]?(?:token|key|code|id)|"
        r"secret|passw|otp|nonce|salt|csrf",
        re.I,
    ),
}
SQL_CALL = re.compile(
    r"(?:execute|executemany|executescript|query|raw|getAllAsync|getFirstAsync|runAsync|execAsync|"
    r"prepareAsync|getAllSync|runSync|executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery|"
    r"Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|find_by_sql|where|whereRaw|order|having|joins|"
    r"exec_query|select_all|select_rows)\s*\(\s*"
    r"(f['\"]|`|\"[^\"]*\"\s*(?:%|\+|\.format)|'[^']*'\s*(?:%|\+|\.format)|\"[^\"]*#\{|fmt\.Sprintf\(\s*[\"`][^\"`]*%[sv]|"
    r"\"[^\"]*\$\{?[A-Za-z_])"
)
HOST = re.compile(r"""['"`]https?://([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?[/'"`?]""", re.I)
SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WHERE|FROM)\b", re.I)
INTERP = re.compile(r"\$\{([^}]+)\}|\{([^}:!]+)[^}]*\}")
CONSTANT = re.compile(r"^[A-Z0-9_]+$|^\w+\.length$|^\w+\.map\(\(\) => ['\"]\?['\"]\)\.join\(['\"], ?['\"]\)$")


# One search per group over the whole file first: most files match none, and then no line is scanned for it.
def _group(pats: list[re.Pattern]) -> re.Pattern:
    """The patterns as one alternation, each keeping its own case-insensitivity."""
    parts = []
    for p in pats:
        body = p.pattern[4:] if p.pattern.startswith("(?i)") else p.pattern
        insensitive = p.pattern.startswith("(?i)") or p.flags & re.I
        parts.append(f"(?i:{body})" if insensitive else f"(?:{body})")
    return re.compile("|".join(parts), re.M)  # over a whole file: ^ means the start of any line


ANY = {k: _group(pats) for k, pats in PATTERNS.items()}
SQL_HINT = re.compile(
    r"execute|query|raw|Async|Sync\s*\(|Query|Exec|Statement|find_by_sql|\.(?:where|whereRaw|order|having|joins|select_all|select_rows)\s*\("
)
DOLLAR_LANGS = (".kt", ".kts", ".dart", ".php", ".groovy", ".scala")
WEAK_CONTEXT_FROM_FUNCTION = ("weak_random", "weak_hash")  # a token made in new_reset_token() is about a token
FUNC_HEADER = re.compile(r"^\s*(?:async\s+)?(?:def|func|function|fun|fn)\s+(\w+)|^\s*(?:export\s+)?(?:public|private|static)\b")


# the value part of a secret, wherever it's reported (PR comments, SARIF, annotations, the review): enough to find it
# (its first 4 characters), never enough to use it
_VENDOR_KEY = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}|xox[abpr]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|"
    r"AIza[0-9A-Za-z_-]{35})"
)
_NAMED_VALUE = re.compile(
    r"""(?i)(\b[\w.-]*(?:key|secret|token|passw|pwd|auth|credential|private)[\w.-]*["']?\s*[:=]\s*["']?)"""
    r"""([^\s"',;}]{4})[^\s"',;}]{2,}"""
)
_PEM_BODY = re.compile(r"(PRIVATE KEY-----(?:\\r)?(?:\\n)?)[A-Za-z0-9+/=]{8,}")


# raw HTML from a string literal with nothing put into it (no ${…}, no +): `el.innerHTML = '<b>Copied</b>'`,
# `__html: "<br>"`, also inside a page a Go or Python file holds as text
CONSTANT_HTML = re.compile(
    r"""(?:\.innerHTML\s*=|__html\s*:|mark_safe\(|v-html\s*=\s*)\s*(["'`])(?:(?!\1)(?!\$\{)[^\\]|\\.)*\1\s*[;,)}]*\s*(?:/?>)?\s*$"""
)


def redact(text: str) -> str:
    """The text with secret values cut to their first 4 characters: `AKIA…`, `API_KEY = "sk_l…"`."""
    text = _VENDOR_KEY.sub(lambda m: m.group(0)[:4] + "…", text)
    text = _NAMED_VALUE.sub(lambda m: m.group(1) + m.group(2) + "…", text)
    return _PEM_BODY.sub(lambda m: m.group(1) + "…", text)


def _excerpt(line: str) -> str:
    t = line.strip()
    return t if len(t) <= 140 else t[:137] + "…"


# a security linter's suppression on the line (gosec's `//nolint:gosec`, bandit's `# nosec`, Sonar's NOSONAR): the authors
# looked at this line and decided; a credential is never excused this way
NOSEC = re.compile(r"(?://|#)\s*(?:nosec\b|nolint:\s*[\w,]*\bgosec\b|NOSONAR\b|noqa:\s*[\w, ]*\bS\d{3}\b)")
NOSEC_KEYS = {"tls_off", "eval", "shell", "raw_html", "sql_built", "weak_hash", "weak_random"}


TLS_SETTING = re.compile(r"\b(?:if|elif|else\s+if|unless)\b.*\b\w*(?:verify|insecure|ssl|tls|cert|skip)\w*\b", re.I)


def _under_tls_setting(lines: list[str], i: int) -> bool:
    """The line sits in a branch of an `if` on a verification setting (`if verify is False:` / its `else:`), as
    requests and HTTP clients do for their `verify=` option: the user's choice, not an override."""
    indent = len(lines[i - 1]) - len(lines[i - 1].lstrip())
    for j in range(i - 2, max(-1, i - 14), -1):
        text = lines[j]
        if not text.strip():
            continue
        level = len(text) - len(text.lstrip())
        if level >= indent:
            continue
        head = text.strip()
        if head.startswith(("else", "} else")) and not TLS_SETTING.search(head):
            indent = level + 1  # the else of an `if` further up: look for that `if` at this level
            continue
        return bool(TLS_SETTING.search(head))
    return False


def _token_question(lines: list[str], i: int, text: str) -> bool:
    """An unverified decode inside an `is_…`/`has_…` function (a yes/no question about the token, such as who issued
    it), in a file that verifies tokens properly elsewhere. Returning the unverified claims is never this."""
    if lines[i - 1].lstrip().startswith("return") or not re.search(r"jwt\.decode\([^)]*\balgorithms\s*=", text):
        return False
    for j in range(i - 2, max(-1, i - 15), -1):
        if m := re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[j]):
            return bool(re.match(r"(?:is|has)_", m.group(1)))
    return False


def _docstring_lines(text: str) -> set[int]:
    """Lines inside a Python docstring: documentation, where `SECRET_KEY = 'development key'` is an example to copy
    (Flask's Config), not configuration."""
    import ast

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                out.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
        # and any string spanning lines: a message or help text that mentions a setting (celery's CERT_NONE warning)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and (node.end_lineno or node.lineno) > node.lineno:
            out.update(range(node.lineno + 1, (node.end_lineno or node.lineno) + 1))
    return out


def _ignored(lines: list[str], i: int, key: str, file_kinds: set[str] | None) -> bool:
    """`codefactory: ignore <check>` on the line or the one above, or `ignore-file` for the file (no kinds = all); for
    security patterns, also a security linter's suppression on the line itself."""
    if file_kinds is not None and (not file_kinds or key in file_kinds):
        return True
    if key in NOSEC_KEYS and 1 <= i <= len(lines) and NOSEC.search(lines[i - 1]):
        return True
    for ln in (i, i - 1):
        if 1 <= ln <= len(lines) and (m := MARK.search(lines[ln - 1])) and not m.group(1):
            kinds, _ = parse_mark(m.group(2))
            if not kinds or key in kinds:
                return True
    return False


CHECK_KEYS = [
    *PATTERNS,
    "sql_built",
    "module_state",
    "fetch_no_timeout",
    "hosts",
    "error_boundary",
    "swallowed_ok",
    "go_server_timeout",
]


def source_files(root: Path, graph: dict) -> list[str]:
    """Every source file to run line checks on: the graph's, plus any on disk the analyzers couldn't read (TypeScript
    without Node.js, other languages without the language pack). A credential in a file nobody could parse is still a
    credential."""
    from .config import load_config

    seen = {f["id"] for f in graph["files"]}
    skip = set(load_config(root).ignore)
    out = set(seen)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".") and not d.endswith(".egg-info")]
        for name in filenames:
            if name.endswith(SRC_EXT) and not name.endswith((".min.js", ".d.ts")):
                out.add(Path(dirpath, name).relative_to(root).as_posix())
    return sorted(f for f in out if not links_outside(root, f) and not is_vendored(f))


def scan_sources(root: Path, files: list[str]) -> dict[str, Check]:
    """Every source file's pattern hits, in parallel and cached per file (see analyzers/parallel)."""
    from .analyzers import parallel

    items = [(fid, (str(root), fid)) for fid in files if fid.endswith(SRC_EXT)]
    per_file = parallel.run(root, "checks", items, _scan_one, tool="checks")
    out = {k: Check(k) for k in CHECK_KEYS}
    for fid in files:
        for key, got in per_file.get(fid, {}).items():
            out[key].hits += [Evidence(fid, line, text) for line, text in got["hits"]]
            for k, v in got["data"].items():
                out[key].data.setdefault(k, v)  # hosts: the first file that uses each
    return out


def _scan_one(root: str, fid: str) -> dict:
    found = _scan(Path(root), [fid])
    return {k: {"hits": [[e.line, e.text] for e in c.hits], "data": c.data} for k, c in found.items() if c.hits or c.data}


def _scan(root: Path, files: list[str]) -> dict[str, Check]:
    keys = [
        *PATTERNS,
        "sql_built",
        "module_state",
        "fetch_no_timeout",
        "hosts",
        "error_boundary",
        "swallowed_ok",
        "go_server_timeout",
    ]
    out = {k: Check(k) for k in keys}
    for fid in files:
        if not fid.endswith(SRC_EXT):
            continue
        try:
            text = (root / fid).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        # generated code is checked like a test: only for vendor credentials (regenerate it, don't hand-fix it)
        test = is_test(fid) or GENERATED.search("\n".join(lines[:12])) is not None
        marks = [parse_mark(m.group(2))[0] for ln in lines if (m := MARK.search(ln)) and m.group(1)]
        file_kinds = set().union(*marks) if marks and all(marks) else (set() if marks else None)

        def hit(key: str, i: int, lines=lines, file_kinds=file_kinds) -> bool:  # bound to this file's lines
            return not _ignored(lines, i, key, file_kinds)

        present = {
            k: (VENDOR_SECRETS if test and k == "secret" else v)
            for k, v in PATTERNS.items()
            if (not test or k == "secret") and (k not in LANG_ONLY or fid.endswith(LANG_ONLY[k])) and ANY[k].search(text)
        }
        sql_here = not test and SQL_HINT.search(text) is not None
        hosts_here = not test and "://" in text
        boundary_here = re.search(r"ErrorBoundary|componentDidCatch|getDerivedStateFromError", text) is not None
        state_here = not test and fid.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")) and "let " in text

        prose = _docstring_lines(text) if fid.endswith(".py") and set(present) - {"secret"} else set()
        for i, line in enumerate(lines, 1):
            if len(line) > 2000:  # minified or data
                continue
            for key, pats in present.items():  # tests: only secrets (a test may do anything; a leaked key is leaked)
                if key != "secret" and (COMMENT_LINE.match(line) or i in prose):
                    continue  # prose about a pattern ("mark_safe() it at the end") isn't the code; a key is leaked anywhere
                if any(p.search(line) and (p not in ONLY_IN or fid.endswith(ONLY_IN[p])) for p in pats) and hit(key, i):
                    if key == "secret_key_literal" and re.search(r"\{\{|\{%|<%=|\$\{", line):
                        continue  # a project template's placeholder (`SECRET_KEY = "{{ secret_key }}"`), filled in later
                    if key == "jwt_unverified" and _token_question(lines, i, text):
                        continue  # `is_saleor_token`: a yes/no peek at who issued it, in a file that verifies tokens
                    if key == "tls_off" and line.lstrip().startswith(("import ", "from ")):
                        continue  # importing the constant isn't using it
                    if key == "tls_off" and (
                        re.search(r"\bif\s+\w[\w.]*\s+else\b|\?\s*\w+\s*:", line) or _under_tls_setting(lines, i)
                    ):
                        continue  # chosen by a setting (`CERT_REQUIRED if verify else CERT_NONE`): the user's option
                    if key == "raw_html" and CONSTANT_HTML.search(line):
                        continue  # a fixed string: no one's data can get into it
                    if key == "raw_html" and re.search(r"mark_safe\(.*\bsettings\.[A-Z_]+", line):
                        continue  # the site's own configuration, not user data
                    if key == "plain_http" and re.match(r"\s*(?:\*|//|#|/\*)", line):  # an example in a doc comment
                        continue
                    if key in CONTEXT and not CONTEXT[key].search(line):
                        header = next((h for h in reversed(lines[max(0, i - 7) : i - 1]) if FUNC_HEADER.match(h)), "")
                        if key not in WEAK_CONTEXT_FROM_FUNCTION or not CONTEXT[key].search(header):
                            continue
                    if key == "secret" and re.search(PLACEHOLDER, line):
                        continue
                    if key == "swallowed" and (why := swallow_intent(line, lines[i - 2] if i > 1 else "")):
                        out["swallowed_ok"].hits.append(Evidence(fid, i, why))  # deliberate: counted, not reported
                        continue
                    out[key].hits.append(Evidence(fid, i, redact(_excerpt(line)) if key == "secret" else _excerpt(line)))
            if sql_here and (m := SQL_CALL.search(line)) and hit("sql_built", i):
                stmt = " ".join(lines[i - 1 : i + 4])
                if SQL_WORD.search(stmt):
                    py_format = not m.group(1).startswith("`")  # {name}: Python f-strings (and Ruby's #{name})
                    start = m.end() - 1 if m.group(1).endswith("#{") else m.end()  # keep Ruby's brace
                    body = stmt[start : start + 600]
                    if not py_format:  # just this template literal, not the code after it
                        body = re.split(r"(?<!\\)`", body, maxsplit=1)[0]
                    names = [a or (b if py_format else "") for a, b in INTERP.findall(body)]
                    names = [n for n in names if n]
                    if m.group(1).endswith("#{"):  # Ruby: #{params[:email]} (a colon is fine inside)
                        names = re.findall(r"\{([^}]+)\}", body.split('"')[0])
                    dollar = m.group(1).startswith('"') and "$" in m.group(1) and "#{" not in m.group(1)
                    if dollar:  # "$name" is interpolation in Kotlin, Dart, PHP, Groovy and Scala, not elsewhere
                        if not fid.endswith(DOLLAR_LANGS):
                            continue
                        names += re.findall(r"\$\{?([A-Za-z_][\w.]*)", stmt[m.start(1) : m.start(1) + 600].split('"')[1])
                    safe = safe_names(lines, i)
                    risky = [n for n in names if not CONSTANT.match(n.strip()) and not interp_safe(n, safe)]
                    sprintf = m.group(1).startswith("fmt.")  # %s / %v pasted in; %d can't carry SQL
                    concat = m.group(1).endswith("+")
                    if concat:  # "… id = " + id: risky unless every value joined in is a number
                        joined = re.findall(r"(?:^|\+)\s*([A-Za-z_$][\w$.]*(?:\(\))?)\s*(?=\+|\)|,|$)", body.split(";")[0])
                        concat = not joined or any(not interp_safe(n, safe) for n in joined)
                    if risky or sprintf or concat or m.group(1).endswith("%") or ".format" in m.group(1):
                        out["sql_built"].hits.append(Evidence(fid, i, _excerpt(line)))
                        out["sql_built"].data.setdefault(f"{fid}:{i}", risky[:4])
            if hosts_here and "://" in line and not re.match(r"\s*(//|#|\*|/\*)", line):  # used, not just mentioned
                for host in HOST.findall(line):
                    if host not in out["hosts"].data and not re.search(r"example\.|localhost|w3\.org|schema", host):
                        out["hosts"].data[host] = f"{fid}:{i}"
            if boundary_here and re.search(r"ErrorBoundary|componentDidCatch|getDerivedStateFromError", line):
                out["error_boundary"].hits.append(Evidence(fid, i, _excerpt(line)))
            if state_here and re.match(r"^(?:export\s+)?let\s+\w+", line) and hit("module_state", i):
                out["module_state"].hits.append(Evidence(fid, i, _excerpt(line)))
        if (
            not test
            and fid.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))  # the web's fetch; elsewhere it's any name
            and re.search(r"(?<![\w.])fetch\s*\(", text)
            and not re.search(r"\bsignal\b|AbortSignal\.timeout|timeout", text)
        ):
            ln = next(i for i, text in enumerate(lines, 1) if re.search(r"(?<![\w.])fetch\s*\(", text))
            out["fetch_no_timeout"].hits.append(Evidence(fid, ln, _excerpt(lines[ln - 1])))
        if not test and fid.endswith(".go"):  # the default client never times out
            server = next(
                (m for m in re.finditer(r"\bhttp\.ListenAndServe(?:TLS)?\(|&?http\.Server\{", text)
                 if not COMMENT_LINE.match(lines[text.count("\n", 0, m.start())])),
                None,
            )  # fmt: skip
            if server and not re.search(r"ReadHeaderTimeout|ReadTimeout|TimeoutHandler", text):
                ln = text.count("\n", 0, server.start()) + 1
                if hit("go_server_timeout", ln):
                    out["go_server_timeout"].hits.append(Evidence(fid, ln, _excerpt(lines[ln - 1])))
            for i, line in enumerate(lines, 1):
                code = line.split("//", 1)[0]
                if re.search(r"\bhttp\.(?:Get|Post|Head|PostForm)\(", code) and hit("fetch_no_timeout", i):
                    out["fetch_no_timeout"].hits.append(Evidence(fid, i, _excerpt(line)))
        if not test and fid.endswith(".py"):
            for i, line in enumerate(lines, 1):
                if (
                    i < len(lines)
                    and re.match(r"\s*except\s*(?:\(?\s*(?:Exception|BaseException)\b[^:#]*)?:\s*$", line)  # broad only
                    and lines[i].strip() == "pass"
                    and not swallow_intent(line + " " + lines[i], lines[i - 2] if i > 1 else "")
                    and hit("swallowed", i)
                ):
                    out["swallowed"].hits.append(Evidence(fid, i, _excerpt(line + " " + lines[i].strip())))
                if re.search(r"\brequests\.(get|post|put|patch|delete|head)\s*\(", line) and "timeout" not in " ".join(
                    lines[i - 1 : i + 3]
                ):
                    out["fetch_no_timeout"].hits.append(Evidence(fid, i, _excerpt(line)))
                if re.match(r"^\s+global\s+\w+", line):
                    out["module_state"].hits.append(Evidence(fid, i, _excerpt(line)))
    return out


# ---- repository ----------------------------------------------------------------------------------------------------

CI_FILES = [
    ".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", ".azure-pipelines", "Jenkinsfile",
    ".travis.yml", "bitbucket-pipelines.yml", ".buildkite", ".drone.yml", ".woodpecker.yml", ".woodpecker",
    ".cirrus.yml", ".semaphore", ".teamcity", "appveyor.yml", ".appveyor.yml", "buildspec.yml", "cloudbuild.yaml",
    "cloudbuild.yml", "bamboo-specs", ".tekton", "rio.yml", ".rio.yml", "codefresh.yml", ".harness", "bitrise.yml",
    "codemagic.yaml", ".gitea/workflows", ".forgejo/workflows", ".taskcluster.yml", "wercker.yml", ".concourse",
]  # fmt: skip
CI_NAMES = "GitHub Actions, GitLab, CircleCI, Jenkins, Azure, Travis, Bitbucket, Buildkite, Drone, Cirrus, TeamCity, Rio, …"


def repo_levels(root: Path) -> list[Path]:
    """The analyzed folder, then each folder above it up to the top of its git repository: CI, the README and the
    license usually live at the top, so a review of a subfolder (`internal/`, one package of a monorepo) finds them."""
    out = [root]
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                             timeout=10).stdout.strip()  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return out
    if not top:
        return out
    top_p, here = Path(top).resolve(), root.resolve()
    while here != top_p and top_p in here.parents:
        here = here.parent
        out.append(here)
    return out


def _rel(root: Path, p: Path) -> str:
    return os.path.relpath(p, root).replace("\\", "/")


LOCKS = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "requirements.lock",
    "Cargo.lock",
    "go.sum",
]


def _python_deps(pyproject: str) -> list[str]:
    """Package names a pyproject.toml depends on (project and optional dependencies, Poetry's tables)."""
    import tomllib

    try:
        data = tomllib.loads(pyproject)
    except ValueError:
        return []
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs += group
    poetry = data.get("tool", {}).get("poetry", {})
    specs += list(poetry.get("dependencies", {})) + list(poetry.get("dev-dependencies", {}))
    return [re.split(r"[\s<>=!~\[;@]", s, maxsplit=1)[0].lower() for s in specs if isinstance(s, str) and s]


PUBLIC_ENV = r"(?i)(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_|PUBLIC_|\w*PUBLIC_KEY\b)"
# a generated file's own header says so (emscripten output, protobuf, `go generate`): its patterns are the generator's
GENERATED = re.compile(r"@generated|Code generated .* DO NOT EDIT|\bDO NOT EDIT\b|auto-?generated|\bemscripten\b", re.I)


def _holds_secret(env: Path) -> bool:
    """An env file with a real value for a secret-looking key (a template with `APP_KEY=` empty isn't a leak)."""
    try:
        text = env.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for m in re.finditer(
        r"^\s*(?:export\s+)?(\w*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)\w*)[ \t]*=[ \t]*(.*)$", text, re.M | re.I
    ):
        if re.match(PUBLIC_ENV, m.group(1)):
            continue  # bundled into the client by design (VITE_, NEXT_PUBLIC_…), or a public key
        value = m.group(2).strip().strip("'\"")
        if len(value) >= 6 and not re.search(PLACEHOLDER + r"|^\$\{?\w+|changethis|secret$|password$", value, re.I):
            return True
    return False


def scan_repo(root: Path) -> dict:
    info: dict = {
        "ci": [],
        "ci_steps": set(),
        "ci_on_push": False,
        "locks": [],
        "manifests": [],
        "npm_dev_only": False,
        "floating": [],
        "unpinned_py": [],
        "runtime_pin": [],
        "readme": None,
        "license": None,
        "env_files": [],
        "frameworks": set(),
        "deps": {},
        "deploy": [],
    }
    from .config import load_config

    real = root.resolve()  # (Windows: the same folder can be C:\\Users\\RUNNER~1\\… or C:/Users/runneradmin/…)
    levels = repo_levels(real)
    declared = list(load_config(root).ci)  # factory.toml `ci = ["…"]`: a CI system this list doesn't know
    for level in levels:
        for c in [*CI_FILES, *declared]:
            p = level / c
            if p.is_dir():
                info["ci"] += [_rel(real, f) for f in sorted(p.iterdir()) if f.is_file() and not f.name.startswith(".")]
            elif p.is_file():
                info["ci"].append(_rel(real, p))
        if info["ci"]:
            break  # the nearest level with CI is this folder's
    for f in info["ci"]:
        try:
            t = (real / f).read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for step, words in {
            "tests": ["test", "pytest", "jest", "vitest", "unittest"],
            "lint": ["lint", "ruff", "flake8", "eslint"],
            "typecheck": ["tsc", "mypy", "pyright", "typecheck"],
            "build": ["build"],
        }.items():
            if any(w in t for w in words):
                info["ci_steps"].add(step)
        if re.search(r"\bpush\s*:", t) or re.search(r"on:\s*\[?\s*push", t) or push_skip_explained(t):
            info["ci_on_push"] = True  # runs on push, or says why it deliberately doesn't
    info["locks"] = [name for name in LOCKS if (root / name).exists()]
    pkg = root / "package.json"
    if pkg.is_file():
        info["manifests"].append("package.json")
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        # only dev tooling (linters, a JS test runner in a Python project): nothing that ships drifts
        info["npm_dev_only"] = bool(data.get("devDependencies")) and not (
            data.get("dependencies") or data.get("peerDependencies")
        )
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        info["deps"].update(deps)
        info["floating"] = [
            f"{k}@{v}" for k, v in deps.items() if v in ("*", "latest", "") or v.startswith(("git", "http", "github:"))
        ]
        if "engines" in data:
            info["runtime_pin"].append("package.json engines")
        for name, fw in (
            ("react-native", "React Native"),
            ("expo", "Expo"),
            ("react", "React"),
            ("next", "Next.js"),
            ("vue", "Vue"),
            ("express", "Express"),
            ("@nestjs/core", "NestJS"),
            ("svelte", "Svelte"),
        ):
            if name in deps:
                info["frameworks"].add(fw)
        info["deploy"] += [k for k in data.get("scripts", {}) if re.search(r"deploy|release|publish|ota", k)]
    for req in ("requirements.txt", "requirements-dev.txt"):
        p = root / req
        if p.is_file():
            info["manifests"].append(req)
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.split("#")[0].strip()
                if s and not s.startswith("-") and "==" not in s and "@" not in s:
                    info["unpinned_py"].append(s)
                if s and not s.startswith("-"):
                    info["deps"][re.split(r"[\s<>=!~\[;@]", s, maxsplit=1)[0].lower()] = ""
    if (root / "pyproject.toml").is_file():
        info["manifests"].append("pyproject.toml")
        t = (root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        info["deps"].update({name: "" for name in _python_deps(t)})
        for name, fw in (("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI"), ("sqlalchemy", "SQLAlchemy")):
            if re.search(rf"\b{name}\b", t, re.I):
                info["frameworks"].add(fw)
        if "requires-python" in t:
            info["runtime_pin"].append("requires-python")
    for f in (".nvmrc", ".node-version", ".python-version", ".tool-versions", "runtime.txt"):
        if (root / f).exists():
            info["runtime_pin"].append(f)
    names = ("README.md", "README.rst", "README.txt", "README", "readme.md")
    info["readme"] = next((_rel(real, lv / f) for lv in levels for f in names if (lv / f).exists()), None)
    licenses = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")
    info["license"] = next((_rel(real, lv / f) for lv in levels for f in licenses if (lv / f).exists()), None)
    info["env_files"] = [
        p.name
        for p in root.glob(".env*")
        if p.is_file()
        and not p.name.endswith((".example", ".sample", ".template", ".dist"))
        and not links_outside(root, p.name)
        and _holds_secret(p)
    ]
    if info["readme"]:
        t = (real / info["readme"]).read_text(encoding="utf-8", errors="replace").lower()
        info["readme_run"] = bool(re.search(r"install|npm |pip |yarn |make |cargo |go run|docker", t))
    return info


# ---- testing -------------------------------------------------------------------------------------------------------


def test_reach(v: View, also: set[str] | frozenset = frozenset()) -> set[str]:
    """Functions a test calls or hands on (a callback), directly or through others (`also`: ones tests reach in ways
    the graph doesn't link, followed the same way)."""
    out_edges: dict[str, list[str]] = {}
    for e in v.g["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], []).append(e["dst"])
    start = [fid for fid, f in v.fn.items() if is_test(f["file"])] + [fid for fid in also if fid in v.fn]
    seen, q = set(start), deque(start)
    while q:
        for nxt in out_edges.get(q.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen
