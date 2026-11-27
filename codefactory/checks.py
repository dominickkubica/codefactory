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
from .callers import drop_fixed
from .intent import expected_failure, interp_safe, push_skip_explained, safe_names, swallow_intent
from .paths import is_doc_sample, is_sample_code, is_test, is_vendored, link_copies, links_outside
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
        re.compile(r"(?<![\w.>])eval\s*\("),  # not a method (`$redis->eval(` runs a Lua script on Redis)
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"(?<![\w.])exec\s*\(\s*[^)]"),
        re.compile(r"\bpickle\.loads?\s*\("),
        re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"),  # Python's: js-yaml 4's load is safe (see ONLY_IN)
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
            re.compile(r"\balgorithms?\s*[:=]\s*\[?\s*['\"]none['\"]", re.I),  # not `profileSigningAlgorithm: 'none'`
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
    PATTERNS["eval"][4]: (".py",),  # yaml.load: js-yaml 4 removed the unsafe loader, so in JavaScript it's safe
    PATTERNS["shell"][-2]: (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    PATTERNS["shell"][-1]: (".go",),
    PATTERNS["shell"][4]: (".rb", ".php", ".pl", ".sh", ".bash", ".py"),  # `"…#{x}"` / `"…${x}"` in a double-quoted string
    PATTERNS["shell"][5]: (".rb",),  # Ruby's backticks and %x(): in JavaScript a backtick is a template string
}
COMMENT_LINE = re.compile(r"\s*(?:#|//|\*|/\*|<!--|--\s)")
# words that say a credential-looking value isn't real ("xoxb-not-a-real-token", "sk_test_fake…", "<your key>")
PLACEHOLDER = (
    r"(?i)example|placeholder|dummy|xxxx|your[_-]|changeme|<|not[-_ ]?a[-_ ]?real|fake|redacted|sample|mock|"
    r"['\"](?:e2e|test)[-_]|['\"]0{8,}|['\"]abcd(?:ef)?[0-9]*(?:abcd|1234)|"  # `e2e-test-secret`, all zeros, `abcd…1234`
    r"['\"]([A-Za-z0-9])\1{7,}['\"]"  # one character over and over (`SECRET_KEY = "AAAAAAAAAAAAAAAAAAAA"` in a test config)
)
# Checks for built-ins only some languages have: Go's eval() or Java's exec() are ordinary functions.
LANG_ONLY = {
    "eval": (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php"),
    "shell": (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php", ".go"),
}
# In tests, keys are fixtures (a PEM block in an example, "secret = 'xxxx…'"): only real credential formats count there,
# because a live AWS, GitHub, Slack, Stripe or Google key in a test is as leaked as anywhere else.
VENDOR_SECRETS = PATTERNS["secret"][1:6]
VENDOR_PATTERNS = PATTERNS["secret"][:6]  # a key block and the vendors' formats; the last one is the generic rule
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
# migration folders: `migrations/`, `db/migrate/`, and gitea's versioned `modelmigration/v1_13/` (not its `base/`
# helpers, nor `immigration/`)
MIGRATION_DIR = re.compile(
    r"(?:^|/)(?:migrations?|migrate|post_migrate)/|(?:^|/)(?:models?|schema|db|data)[_-]?migrations?/v\d", re.I
)
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


TLS_SETTING = re.compile(
    r"\b(?:if|elif|else\s+if|unless|case|when)\b.*\b\w*(?:verify|insecure|ssl|tls|cert|skip|unsafe|unauthori[sz]ed)\w*\b", re.I
)
# the same TLS config checks the certificate its own way (pinned roots, expected names, a callback): Go has to skip its
# hostname check to do that (traefik's Consul Connect)
# (or it's a server asking for the client's certificate and checking it itself: `ClientAuth: tls.RequestClientCert`,
# Node's `requestCert` with `socket.authorized` checked per request; skipping verification there is how that's done)
OWN_VERIFY = re.compile(
    r"\b(?:RootCAs|VerifyPeerCertificate|VerifyConnection|PeerCertSANs|checkServerIdentity|ClientAuth|requestCert)\b|"
    r"\.authorized\b"
)


def _under_tls_setting(lines: list[str], i: int) -> bool:
    """The line sits in a branch of an `if` on a verification setting (`if verify is False:` / its `else:`), as
    requests and HTTP clients do for their `verify=` option: the user's choice, not an override."""
    indent = len(lines[i - 1]) - len(lines[i - 1].lstrip())
    ternary = False
    for j in range(i - 2, max(-1, i - 40), -1):  # (an `else:` may be far from its `if`: requests' cert_verify)
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
        if head.startswith(("?", ":")):
            ternary, indent = True, level  # `cond ? {…} : { rejectUnauthorized: false }` across lines
            continue
        if ternary and re.search(r"\w*(?:verify|secure|ssl|tls|cert|skip|unsafe|unauthori[sz]ed)\w*", head, re.I):
            return True
        if not re.match(r"(?:\}\s*)?(?:if|elif|else|unless|case|when|switch|match)\b", head):
            indent = level  # inside an object or call being built (`agent = new https.Agent({`): keep climbing
            continue
        return bool(TLS_SETTING.search(head))
    return False


I18N = re.compile(r"(?:^|/)(?:locales?|i18n|translations?|lang|langs|l10n)/", re.I)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _named_not_secret(fid: str, lines: list[str], i: int) -> bool:
    """What the generic `name = "value"` rule catches but isn't a credential: a translation's `password: …`, a constant
    whose value is a name or a path (`USER_OAUTH2_BAD_REQUEST = 'user_oauth2_bad_request'`, `GUEST_TOKEN: 'api/v1/…'`),
    a UUID under a password-ish name (a passkey provider's AAGUID), a PostHog project key (public by design), or an
    example in documentation (Elixir's @doc, a doctest prompt)."""
    line = lines[i - 1]
    if I18N.search(fid) or re.match(r"\s*(?:iex>|>>>|\.\.\.>)", line) or i in _elixir_doc_lines(lines):
        return True
    if re.search(r"(?i)\bfor (?:instance|example)\b|\be\.g\.,? ", line):
        return True  # an example inside prose (meilisearch's OpenAPI description: "…for instance: apiKey: '6436…'")
    values = re.findall(r"""['"]([^'"]{8,})['"]""", line)
    if not values:
        return False
    value = values[-1]
    if value.startswith("phc_"):
        return True
    name = line.split("=")[0].split(":")[0]
    if UUID.match(value) and not re.search(r"key|secret|token", name, re.I):
        return True
    if value.strip().upper() == re.sub(r"\W", "", name).strip().upper():
        return True  # an enum whose value is its own name (`JWT_SECRET = 'JWT_SECRET'`)
    if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", value):
        return True  # the name of an environment variable that holds it (`ENV_GRANT_TOKEN = "N8N_RUNNERS_GRANT_TOKEN"`)
    if re.search(r"(?:characters|chars|alphabet|charset)$", name.strip(), re.I):
        return True  # the alphabet a password is drawn from (`PasswordCharacters = "abc…XYZ0123…"`)
    if re.search(r"(?:client|app|application|project|tenant|account)_?id$", name.strip(), re.I):
        return True  # an OAuth client ID or an app ID identifies; it doesn't authenticate
    if re.search(
        r"(?:_|\b)(?:name|header|param|field|label|prefix)s?$",
        re.sub(r"\W+$", "", name.split()[-1] if name.split() else ""),
        re.I,
    ):
        return True  # the name of a cookie, header or key to look up (`REFRESH_COOKIE_NAME = 'n8n-chat-oauth-refresh'`)
    parts = [p for p in re.split(r"[_\-/.:]", value) if p]
    if len(parts) == 1:  # camelCase words (`consoleOAuth2Provider`), not random characters
        parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", value)
        words = [p for p in parts if p.isalpha() and len(p) >= 3]
        short = sum(len(p) for p in parts if len(p) < 3)
        if "".join(parts) != value or len(words) < 2 or sum(p.isdigit() for p in parts) > 1 or short * 3 > len(value):
            return False  # random characters split into fragments, not words
    return len(parts) >= 2 and all(
        re.fullmatch(r"[a-z]{1,15}\d?|[A-Z][a-z]{0,14}\d?|[A-Z]{1,15}\d?|v\d+|\d{1,6}", p) for p in parts
    )


def _elixir_doc_lines(lines: list[str]) -> set[int]:
    """Lines inside an Elixir `@moduledoc` / `@doc` heredoc: documentation, with example configuration."""
    out, start = set(), None
    for n, text in enumerate(lines, 1):
        if start is None and re.match(r'\s*@(?:module)?doc\s+(?:~[sS])?"""', text):
            start = n
        elif start is not None and text.strip() == '"""':
            out.update(range(start, n + 1))
            start = None
    return out


def _token_question(lines: list[str], i: int, text: str) -> bool:
    """An unverified decode inside an `is_…`/`has_…` function (a yes/no question about the token, such as who issued
    it), in a file that verifies tokens properly elsewhere. Returning the unverified claims is never this."""
    verified = re.search(r"jwt\.decode\((?:[^()]|\([^()]*\))*?\balgorithms\s*=", text)  # (`get_key()` inside the call)
    if lines[i - 1].lstrip().startswith("return"):
        return False
    above = "\n".join(lines[max(0, i - 8) : i])
    if re.search(
        r"#.*\b(?:unverified|authenticat\w+ (?:the|it|later|before)|verif\w+ (?:later|elsewhere|first|before))", above, re.I
    ):
        return True  # the comment says what the peek is for and where the real check happens
    for j in range(i - 2, max(-1, i - 40), -1):
        if m := re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[j]):
            name = m.group(1)
            # a yes/no question (is_saleor_token) or a read of the expiry or issuer, not authentication
            return (
                bool(re.match(r"(?:is|has)_", name) and verified)
                or bool(re.search(r"expir|_exp\b|exp_|issuer|peek|unverified|header|kid\b|routing|owner", name, re.I))
                or bool(re.match(r"(?:is|has)_\w*(?:token|jwt)", name))
            )
    return False


HTTP_HOST = re.compile(r"http://([^/\s\"'`:)?#]+)", re.I)
NAMESPACE_HOSTS = re.compile(
    r"(?:^|\.)(?:w3\.org|purl\.org|schema\.org|xmlns\.com|ns\.adobe\.com|docs\.oasis-open\.org|sitemaps\.org|"
    r"json-schema\.org|openid\.net|xml\.org|apache\.org/xml|java\.sun\.com|maven\.apache\.org|ogp\.me|"
    r"rdfs\.org|microformats\.org|opensearch\.org|webdav\.org|s3\.amazonaws\.com/doc|activitystreams|joinmastodon\.org/ns)$",
    re.I,
)
LINK_CONTEXT = re.compile(
    r"\bhref\s*[=:]|\bxmlns\b|targetNamespace|\bcredits?\b|@see\b|@link\b|\bid\s*[:=]\s*[\"']http|\bto\s*=\s*[\"']http|"
    r"TermDefinition|\bnamespace\b|\bschemaLocation\b|\bhomepage\b|\blicen[cs]e\b|\bcitation\b|\bsource_?url\b.*#|"
    r"\bdocs?_?url\b|\bdocumentation\b|\bexamples?\s*:|add_preloaded|\bwebsite\b|\binfo_?url\b|\breference\b",
    re.I,
)


def internet_http(line: str) -> bool:
    """A plain `http://` address this line could request over the internet: not a local or single-label host (a
    Docker service, `localhost`), a private network address, an example or test domain, an XML / JSON-LD namespace,
    or a link meant for people (`href=`, credits, a license)."""
    if LINK_CONTEXT.search(line):
        return False
    for m in HTTP_HOST.finditer(line):
        host = m.group(1).lower().rstrip(".")
        if "." not in host or host.endswith((".local", ".localhost", ".internal", ".svc", ".test", ".example", ".invalid",
                                              ".lan", ".home", ".corp", ".docker")):  # fmt: skip
            continue
        if re.match(r"(?:10|127)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0", host):
            continue
        if re.match(r"(?:[\w-]+\.)*example\.(?:com|org|net)$|^(?:www\.)?example\b", host) or NAMESPACE_HOSTS.search(host):
            continue
        if re.search(r"/(?:ns|schemas?|xmlns|vocab|terms|rdf|dtd)\b", line[m.end() : m.end() + 40]):
            continue  # http://host/ns/…, a vocabulary's identifier
        return True
    return False


PUBLIC_KEY_NOTE = re.compile(
    r"safe to (?:be )?(?:embed|commit|publish|shar|includ)\w*|not (?:a |really )?secret|(?:is|are) public\b|"
    r"public (?:client|by design)|intentionally (?:public|committed|embedded)|compromised|publicly (?:known|disclosed)|"
    r"for (?:running )?(?:the |these )?examples?\b|request your own",
    re.I,
)


def _not_a_working_key(lines: list[str], i: int) -> bool:
    """A credential-shaped value that can't be one: a vendor format filled with a run or a sequence (a test's
    `sk_live_AAAA…`, `ghp_ABCdef1234567890…`), or one the comment above calls public (the GitHub CLI's OAuth app
    secret, a demo's shared key, a published compromised CA key)."""
    line = lines[i - 1]
    for p in VENDOR_PATTERNS[1:]:
        m = p.search(line)
        if m:
            body = re.sub(r"^[A-Za-z]{2,8}[_-](?:live_|test_)?|^AKIA|^AIza|^xox[abpr]-", "", m.group(0))
            if not looks_random(body[:40] if len(body) >= 12 else body + "x" * 12):
                return True
    if "PRIVATE KEY-----" in line and re.search(r"A{16,}", "".join(lines[i : i + 3])):
        return True  # a key block padded with AAAA…: a deliberately broken example key (mitmproxy's)
    above = "\n".join(lines[max(0, i - 6) : i])
    near = "\n".join(lines[max(0, i - 6) : i + 6])
    if re.search(r"(?i)docsearch|algolia", near) and re.search(r"\b(?:indexName|appId|index_name|app_id)\b", near):
        return True  # Algolia DocSearch's search-only key: made to ship in the page
    return PUBLIC_KEY_NOTE.search(above) is not None


def _method_named_eval(lines: list[str], i: int) -> bool:
    """A class method named eval being defined, not called: `eval(params: T[]): string {`, its parameters and
    return type over several lines. After the closing parenthesis a definition goes on to a return type or a body; a
    call goes on to the end of its statement."""
    m = re.match(r"\s*(?:(?:public|private|protected|static|async|override)\s+)*eval\s*\(", lines[i - 1])
    if not m:
        return False
    text = "\n".join(lines[i - 1 : i + 11])
    depth = 0
    for j in range(m.end() - 1, len(text)):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        if depth == 0:
            return re.match(r"\s*(?::|\{)", text[j + 1 :]) is not None
    return False


def _fixed_code(line: str, text: str) -> bool:
    """Code execution of nothing anyone supplies: `new Function` with only literal arguments, `exec` of a file the
    repository ships by a literal name, or a YAML load in a file using ruamel.yaml (whose loader is safe by default)."""
    if m := re.search(r"\bnew\s+Function\s*\((.*)\)", line):
        args = re.sub(r"""(["'`])(?:(?!\1)[^\\$]|\\.)*\1""", "", m.group(1))
        if not re.search(r"[A-Za-z_$]", args):
            return True
    if re.search(r"\bexec\s*\(\s*open\s*\(\s*['\"][^'\"]+['\"]\s*\)\.read\(\)", line):
        return True
    return bool(re.search(r"\byaml\.load\s*\(", line) and re.search(r"\bruamel\b", text)
                and not re.search(r"typ\s*=\s*['\"]unsafe['\"]", text))  # fmt: skip


def _template_lines(lines: list[str]) -> set[int]:
    """Lines inside a multi-line template literal that opens at the end of a line or straight into markup
    (`` const html = ` `` / `` `<!DOCTYPE html> ``) and runs to the next backtick. Narrow on purpose: counting
    backticks goes wrong on a regex like `/[`{|}]/`."""
    out, inside = set(), False
    for n, ln in enumerate(lines, 1):
        if inside:
            out.add(n)
            if "`" in ln.replace("\\`", ""):
                inside = False
        elif re.search(r"(?:[=(,:]|return)\s*(?:/\*.*?\*/\s*)?`\s*(?:<[^`]*)?$", ln):  # (`= /* js */ \``)
            inside = True
    return out


STORIES = re.compile(r"\.stor(?:y|ies)\.(?:[cm]?[jt]sx?|mdx|svelte|vue)$")


def _ruby_heredoc_lines(lines: list[str]) -> set[int]:
    """Lines inside Ruby heredocs (`<<-MD` … `MD`, `<<~TEXT`): text, where backticks are formatting."""
    out, end = set(), None
    for n, ln in enumerate(lines, 1):
        if end is not None:
            if ln.strip() == end:
                end = None
            else:
                out.add(n)
        elif m := re.search(r"<<[-~]?(['\"]?)([A-Z_][A-Z0-9_]*)\1", ln):
            end = m.group(2)
    return out


def _comment_line(line: str) -> bool:
    return re.match(r"\s*(?://|#|\*|/\*|--|<!--)", line) is not None


def _in_comment(lines: list[str], i: int) -> bool:
    """Line i is a comment: a `//` or `#` line, or inside a `/* … */` block opened on an earlier line."""
    if re.match(r"\s*(?://|#(?!\[)|\*|/\*|\{/\*|<!--)", lines[i - 1]):
        return True
    for back in range(i - 2, max(-1, i - 40), -1):
        ln = re.sub(r"""(["'`])(?:(?!\1)[^\\]|\\.)*\1""", "", lines[back])  # (not `"src/**/*.ts"` in a string)
        if "*/" in ln:
            return False
        if "/*" in ln:
            return True
    return False


def _constant_after(lines: list[str], i: int) -> bool:
    """`el.innerHTML =` and then one string literal that runs over the next lines with nothing interpolated: a
    constant SVG on the next line, a `<style>` block in a template literal."""
    m = re.search(r"(?:\.innerHTML|\.outerHTML)\s*=\s*", lines[i - 1])
    if not m:
        return False
    text = lines[i - 1][m.end() :] + "\n" + "\n".join(lines[i : i + 200])
    lit = re.match(r"""\s*(["'`])((?:(?!\1)[^\\]|\\.)*)\1\s*(?:;|$|\n)""", text)
    return bool(lit) and not (lit.group(1) == "`" and "${" in lit.group(2)) and (lit.group(1) == "`" or "\n" not in lit.group(2))


# setItem("jwt", "") clears it; a timestamp next to a token's name (a dismissal time) isn't one
STORED_NOTHING = (
    r"""setItem\(\s*(['"`])[^'"`]*\1\s*,\s*(?:(['"`])\2|null|undefined|String\(\s*Date\.now\(\)\s*\)|Date\.now\(\)|"""
    r"[\w.]+\.getTime\(\))"
)


def _in_outbound_request(lines: list[str], i: int) -> bool:
    """Line i sits inside the arguments of an outgoing request (`fetch(url, { headers: {…} })`): what it sets is a
    request header, not the response this server sends."""
    for j in range(i, max(0, i - 12), -1):
        m = re.search(r"(?<![\w$.])(?:fetch|axios(?:\.\w+)?|got|ky|request|\$fetch|ofetch)\s*\(", lines[j - 1])
        if m:
            seg = lines[j - 1][m.end() :] + "\n" + "\n".join(lines[j:i])
            seg = re.sub(r"""(["'`])(?:(?!\1)[^\\]|\\.)*\1""", '""', seg)
            return seg.count("(") >= seg.count(")")  # (still inside the call's parentheses)
    return False


def _fixed_fstring(lines: list[str], i: int, name: str) -> bool:
    """`name` was last set, in the few lines before line i, to an f-string of only fixed values:
    `cmd = rf'grep -rl {SNAPSHOTS_DIR}'`."""
    safe = None
    for j in range(i - 1, max(0, i - 12), -1):
        if m := re.match(rf"""\s*{name}\s*=\s*(?:[rR]?[fF]|[fF][rR])(["'])(.*)\1\s*$""", lines[j - 1]):
            safe = safe_names(lines, j) if safe is None else safe
            return all(interp_safe(e, safe) for e in re.findall(r"\{([^{}:!]+)", m.group(2)))
        if re.match(rf"\s*{name}\s*[+]?=", lines[j - 1]):
            return False
    return False


def _fixed_shell(lines: list[str], i: int) -> bool:
    """`shell=True` on a call whose command is one plain string literal (no f-string, `%`, `.format` or `+` on it)."""
    for j in range(i, max(0, i - 8), -1):
        if m := re.search(r"\b(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)\s*\(", lines[j - 1]):
            after = lines[j - 1][m.end() :] + " " + " ".join(ln.strip() for ln in lines[j:i])
            if re.match(r"""\s*r?(["'])[^"']*\1\s*,""", after):  # (then `,`: not `% x` or `.format`)
                return True
            return bool((v := re.match(r"\s*(\w+)\s*,", after)) and _fixed_fstring(lines, j, v.group(1)))
    return False


SANITIZED = re.compile(
    r"saniti[sz]e|purify|DOMPurify|escape\w*\(|\besc\(|trusted_?html\(\s*['\"`]|&quot;|&lt;|xss\(|textContent|"
    r"\w+_safe\b|\brender(?:_to_string)?\(",  # (Django: arguments escaped into *_safe, a rendered template autoescapes)
    re.I,
)


def _safe_html(lines: list[str], i: int) -> bool:
    """HTML from nothing outside: a value sanitized on the way, calls of built-in functions with no data passed
    (`patchTheme(nightfox())`), a numeric counter, or a constant `__html` on the next lines."""
    line = lines[i - 1]
    if re.search(r"""(["'`])[^"'`]*\bv-html\b[^"'`]*\1""", line) and not re.search(r"\bv-html\s*=", line):
        return True  # the words "v-html" in a message
    rhs = re.split(r"innerHTML\s*=|__html\s*:|mark_safe\(|\bv-html\s*=", line, maxsplit=1)[-1]
    if SANITIZED.search(rhs):
        return True
    if re.search(r"\btemplate\w*\.innerHTML\s*=", line, re.I):
        return True  # parsed into an inert <template>: nothing runs until it's taken out and used
    subs = re.findall(r"\$\{([^}]+)\}", rhs)
    whole = rhs.strip().rstrip(";")
    if (subs and all(interp_safe(s, safe_names(lines, i)) for s in subs)) or (
        re.fullmatch(r"[A-Za-z_$][\w$]*", whole) and whole in safe_names(lines, i, span=400)
    ):
        return True  # only fixed values: `window.status = '${pageStatus}'` (one of four literals), a constant SVG sprite
    if re.search(r"dangerouslySetInnerHTML=\{\{\s*$", line) and re.match(
        r"\s*__html\s*:\s*`", lines[i] if i < len(lines) else ""
    ):
        literal = "\n".join(lines[i : i + 60]).split("`", 2)
        if len(literal) > 2 and "${" not in literal[1]:
            return True  # a fixed script in a template literal over several lines
    if not rhs.strip() or rhs.count("`") % 2 or rhs.count("(") > rhs.count(")") or rhs.rstrip().endswith(("(", "+", "`")):
        return False  # the value goes on below (`mark_safe(` / a template literal over several lines): read, not judged
    rest = re.sub(r"""(["'])(?:(?!\1)[^\\]|\\.)*\1""", "", rhs)
    rest = re.sub(r"`[^`$]*`", "", rest)
    rest = re.sub(r"[A-Za-z_$][\w$.]*\s*\(", "(", rest)  # function names: their arguments are what counts
    names = set(re.findall(r"(?<![\w$.])[A-Za-z_$][\w$]*", rest)) - {"true", "false", "null", "undefined", "this"}
    if not names and "${" not in rhs and "{" not in rest.replace("{{", ""):
        return True
    if re.search(r"__html\s*:", line) is None and re.search(r"dangerouslySetInnerHTML=\{\{\s*$", line):
        nxt = " ".join(lines[i : i + 3])
        return CONSTANT_HTML.search(nxt.split("}}")[0] + ",") is not None or bool(SANITIZED.search(nxt.split("}}")[0]))
    return False


# languages whose strings interpolate `{name}` (Python f-strings, C#'s $"…", PHP's "{$x}", Ruby's #{x}, Kotlin and
# Dart's ${x}, Swift's \(x))
BRACE_LANGS = (".py", ".cs", ".php", ".rb", ".kt", ".kts", ".dart", ".scala", ".groovy", ".swift")


NOT_SECURITY = re.compile(r"bucket|rate_?limit|throttl|cache|refresh_key|etag|fingerprint|dedup|checksum|"
                          r"\bnonce\b\s*:\s*Math|cnonce|SignatureNonce", re.I)  # fmt: skip


def _keyed_not_secured(lines: list[str], i: int) -> bool:
    """The hash or random value only names something: the line, or the function it's in (up to 25 lines up), says
    it's a rate-limit bucket, a cache key, an ETag or a fingerprint."""
    if NOT_SECURITY.search(lines[i - 1]):
        return True
    for j in range(i - 2, max(-1, i - 26), -1):
        if FUNC_HEADER.match(lines[j]):
            body = "\n".join(lines[j : min(len(lines), i + 12)])
            return NOT_SECURITY.search(body) is not None and not re.search(r"passw|hmac|signature", body, re.I)
    return False


def looks_random(value: str) -> bool:
    """A value that could be a working secret: long enough, varied, not a run (AAAA…) or a sequence (123456, abcdef),
    and not built from words (`magical_password`, `petclinic`, `testpass`). Placeholders and demo defaults fail."""
    import math

    v = value.strip().strip("'\"")
    if len(v) < 12 or re.search(r"(.)\1{3,}", v):
        return False
    low = v.lower()
    if any(s in low for s in ("0123", "1234", "2345", "3456", "4567", "5678", "6789", "abcd", "bcde", "cdef", "qwer", "asdf")):
        return False
    if re.search(r"[a-z]{5,}", low) and re.search(
        r"pass|secret|test|demo|example|sample|change|admin|local|default|dev|user|word|token|magic|super|root|guest|dummy|"
        r"fake|mock|placeholder|insecure|please|replace|your|mysql|postgres|redis|mongo|minio|click|house|rust|clinic|"
        r"forge|polar|key",
        low,
    ):
        return False
    counts = {c: v.count(c) for c in set(v)}
    entropy = -sum(n / len(v) * math.log2(n / len(v)) for n in counts.values())
    return entropy >= 3.0


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
    copies = link_copies(root, out)
    return sorted(f for f in out if not links_outside(root, f) and not is_vendored(f) and f not in copies)


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
    drop_fixed(root, files, out, ("sql_built", "raw_html", "shell"))  # a parameter every caller passes a literal
    if any("axios" in e.text for e in out["fetch_no_timeout"].hits) and _axios_default_timeout(root, files):
        # set once for the whole app (`axios.defaults.timeout = 300_000` in the server's constructor)
        out["fetch_no_timeout"].hits = [e for e in out["fetch_no_timeout"].hits if "axios" not in e.text]
    return out


def _axios_default_timeout(root: Path, files: list[str]) -> bool:
    for fid in files:
        if fid.endswith((".ts", ".js", ".mjs", ".cjs", ".tsx")):
            try:
                if "defaults.timeout" in (root / fid).read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                continue
    return False


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
        # generated code, and examples and docs samples, are checked like a test: only for vendor credentials
        test = (is_test(fid) or is_doc_sample(fid) or is_sample_code(fid)
                or STORIES.search(fid) is not None  # Storybook stories: demo props, not the product's data
                or GENERATED.search("\n".join(lines[:12])) is not None
                or (fid.endswith((".js", ".mjs", ".cjs")) and BUNDLED.search("\n".join(lines[:6])) is not None))  # fmt: skip
        marks = [parse_mark(m.group(2))[0] for ln in lines if (m := MARK.search(ln)) and m.group(1)]
        file_kinds = set().union(*marks) if marks and all(marks) else (set() if marks else None)

        def hit(key: str, i: int, lines=lines, file_kinds=file_kinds) -> bool:  # bound to this file's lines
            return not _ignored(lines, i, key, file_kinds)

        present = {
            k: (VENDOR_SECRETS if test and k == "secret" else v)
            for k, v in PATTERNS.items()
            if (not test or k == "secret") and (k not in LANG_ONLY or fid.endswith(LANG_ONLY[k])) and ANY[k].search(text)
        }
        templated: set[int] | None = None
        sql_here = not test and SQL_HINT.search(text) is not None
        in_migration = MIGRATION_DIR.search(fid) is not None  # names, by design
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
                    if key == "eval" and (
                        re.search(r"\bfunction\s+eval\s*\(|\bdef\s+eval\s*\(|['\"][^'\"]*\beval\(\)[^'\"]*['\"]", line)
                        or _method_named_eval(lines, i)
                    ):
                        continue  # a method named eval (a parser node's, a Redis client's), or "eval()'d code" in a string
                    if key == "eval" and _fixed_code(line, text):
                        continue  # new Function("return import(x)"), exec(open("config.py").read()), ruamel's safe load
                    if key == "insecure_cookie" and re.search(
                        r"(?i)(?:csrf|xsrf)\w*[^\n]*http_?only|http_?only[^\n]*(?:csrf|xsrf)", line
                    ):
                        continue  # a CSRF cookie the page's script must read: HttpOnly would break it, by design
                    if key == "insecure_cookie" and re.search(r"#[^\n]*force_ssl|//[^\n]*force_?ssl", line, re.I):
                        continue  # (Rails) `secure: false, # … set by force_ssl`: the flag comes from force_ssl
                    if key == "insecure_cookie" and re.search(r"\?\s*[\w.]+\s*:\s*false\b", line):
                        continue  # copying another cookie's own flag (an HTTP client's cookie jar), not setting one
                    if key == "secret_key_literal" and re.match(r"\s*(\w+)\s*=\s*['\"]\1['\"]", line):
                        continue  # an enum whose value is its own name (hoppscotch's InfraConfig.JWT_SECRET)
                    if key == "secret_key_literal" and re.search(r"\{\{|\{%|<%=|\$\{", line):
                        continue  # a project template's placeholder (`SECRET_KEY = "{{ secret_key }}"`), filled in later
                    if key == "jwt_unverified" and _token_question(lines, i, text):
                        continue  # `is_saleor_token`: a yes/no peek at who issued it, in a file that verifies tokens
                    if key == "tls_off" and (line.lstrip().startswith(("import ", "from "))
                                             or re.match(r"""\s*['"]\w+['"]\s*:\s*(?:\w+\.)?CERT_NONE\b""", line)
                                             or re.search(r"(?:==|!=|\bis\s+(?:not\s+)?)\s*(?:\w+\.)?CERT_NONE\b", line)
                                             or re.search(r"\.get_ciphers\(\)", line)
                                             or re.match(r"\s*if\s*\(?\s*!?\w*(?:verify|skip|insecure|unsafe|unauthori[sz]ed|"
                                                         r"allow\w*cert)\w*\s*\)?\s*(?:\)|:|\{|return\b)", line, re.I)
                                             or re.match(r"""\s*[A-Z_][A-Z0-9_]*\s*=\s*[rbuf]?['"]""", line)):  # fmt: skip
                        continue  # importing the constant, a name-to-constant table, a warning message's text
                    if key == "tls_off" and (
                        re.search(r"\bif\s+\w[\w.]*\s+else\b|\?\s*\w+\s*:", line)
                        or re.search(
                            r"(?i)\w*(?:verify|insecure|ssl|tls|cert|skip|ignore|unauthori[sz]ed)\w*\s*(?:===?\s*true\s*)?(?:&&|\?)",
                            line,
                        )
                        or _under_tls_setting(lines, i)
                        or OWN_VERIFY.search("\n".join(lines[max(0, i - 7) : i + 6]))
                    ):
                        continue  # chosen by a setting (`CERT_REQUIRED if verify else CERT_NONE`): the user's option
                    if key == "shell" and fid.endswith(".rb") and i in _ruby_heredoc_lines(lines):
                        continue  # Markdown in a heredoc (a description's `#{payload_path}`), not a command
                    if key == "shell" and fid.endswith(".rb") and re.search(r'"[^"]*`[^`"]*#\{[^}]+\}[^`"]*`[^"]*"', line):
                        continue  # backticks inside a message string ("append `--trace` to the `#{cmd}` command")
                    if key == "shell" and (subs := re.findall(r"\$\{([^}]+)\}", line)) and "`" in line:
                        safe = safe_names(lines, i)
                        if all(interp_safe(s, safe) for s in subs):
                            continue  # every value in the command is a number or from a fixed list (parseInt, …)
                    if key in ("raw_html", "sql_built", "shell", "eval") and _in_comment(lines, i):
                        continue  # prose about the call ("This usage of dangerouslySetInnerHTML is safe since…")
                    if key == "shell" and fid.endswith(".py") and "shell" in line and _fixed_shell(lines, i):
                        continue  # `subprocess.run("git log -1 HEAD", shell=True)`: a fixed command, nothing to inject
                    if key == "raw_html" and (CONSTANT_HTML.search(line) or _safe_html(lines, i) or _constant_after(lines, i)):
                        continue  # a fixed string, built-in theme CSS, or sanitized first: no one's data can get into it
                    if key == "raw_html" and re.search(r"mark_safe\(.*\bsettings\.[A-Z_]+", line):
                        continue  # the site's own configuration, not user data
                    if key == "plain_http" and (re.match(r"\s*(?:\*|//|#|/\*)", line) or not internet_http(line)):
                        continue  # an example in a doc comment, a Docker service, a namespace, a link for people
                    if key in CONTEXT and not CONTEXT[key].search(line):
                        header = next((h for h in reversed(lines[max(0, i - 7) : i - 1]) if FUNC_HEADER.match(h)), "")
                        if key not in WEAK_CONTEXT_FROM_FUNCTION or not CONTEXT[key].search(header):
                            continue
                    if key in ("weak_hash", "weak_random") and _keyed_not_secured(lines, i):
                        continue  # a hash for a rate-limit bucket, a cache or refresh key: an identifier, not protection
                    if key == "weak_hash" and re.search(r"(?i)pwned\s*passwords|haveibeenpwned|\bhibp\b", text):
                        continue  # the Pwned Passwords range API takes a SHA-1 prefix (k-anonymity): the protocol, not a choice
                    if key == "cors_any" and (_in_outbound_request(lines, i) or "configureServer" in text):
                        continue  # a header sent *to* another API (opsgenie), or Vite's dev-server middleware
                    if key == "sensitive_storage" and re.search(STORED_NOTHING, line):
                        continue  # setItem("jwt", ""): clearing it, or a timestamp beside it; nothing secret is stored
                    if key == "weak_cipher" and re.search(r"(?i)\bRSA/ECB/", line):
                        continue  # JCA's "RSA/ECB/…" names no block mode: RSA encrypts one block, ECB is a placeholder
                    if key == "secret" and (
                        re.search(r"(?:^|/)\.?gitleaks(?:ignore|\.toml)$|(?:^|/)(?:__)?mocks?(?:__)?(?:/|\.[jt]sx?$)", fid)
                        or (_comment_line(line) and not any(p.search(line) for p in VENDOR_PATTERNS))
                        or re.search(r"(?i)\bnot (?:a |really )?secret\b", line)
                    ):
                        continue  # a scanner's allowlist, a mock, an example in a comment, a value its line calls public
                    if key == "secret" and re.search(PLACEHOLDER, line):
                        continue
                    if key == "secret" and _not_a_working_key(lines, i):
                        continue  # sk_live_AAAA…, ghp_ABCdef1234…: a test's stand-in; or a key its comment says is public
                    if key == "secret" and COMMENT_LINE.match(line) and "PRIVATE KEY-----" in line:
                        continue  # a key block shown in a doc comment (okhttp's KDoc): an example of the format
                    if key == "secret" and not any(p.search(line) for p in VENDOR_PATTERNS) and _named_not_secret(fid, lines, i):
                        continue  # the generic `token = "…"` rule only: a vendor key or a key block is leaked anywhere
                    if key == "swallowed" and (
                        why := swallow_intent(line, lines[i - 2] if i > 1 else "") or expected_failure(lines, i)
                    ):
                        out["swallowed_ok"].hits.append(Evidence(fid, i, why))  # deliberate: counted, not reported
                        continue
                    out[key].hits.append(Evidence(fid, i, redact(_excerpt(line)) if key == "secret" else _excerpt(line)))
            if sql_here and not in_migration and (m := SQL_CALL.search(line)) and hit("sql_built", i):
                stmt = " ".join(lines[i - 1 : i + 4])
                literal = re.search(r"""(["'`])((?:(?!\1)[^\\]|\\.)*)\1""", stmt[m.start() :])
                # (the SQL words must be in the call's text: `queue.execute("MockWebServer …")` names a task, not a query)
                callee = line[m.start() : m.start(1)]  # (Rails' `where("email = …")`: the method is the SQL word)
                if SQL_WORD.search(stmt) and (literal is None or SQL_WORD.search(literal.group(2) + " " + callee)
                                              or m.group(1).startswith("fmt.")):  # fmt: skip
                    py_format = not m.group(1).startswith("`")  # {name}: Python f-strings (and Ruby's #{name})
                    start = m.end() - 1 if m.group(1).endswith("#{") else m.end()  # keep Ruby's brace
                    body = stmt[start : start + 600]
                    if not py_format:  # just this template literal, not the code after it
                        body = re.split(r"(?<!\\)`", body, maxsplit=1)[0]
                    elif not fid.endswith(".py"):  # a statement ends at `;`: the next lines are other code
                        body = body.split(";", 1)[0]
                    names = [a or (b if py_format else "") for a, b in INTERP.findall(body)]
                    names = [n for n in names if n]
                    if py_format and not fid.endswith(BRACE_LANGS):
                        names = []  # `{ … }` after a Go or Java call is a block, not interpolation (`return err`)
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
                        segment = body.split(";")[0]
                        joined = re.findall(r"(?:^|\+)\s*([A-Za-z_$][\w$.]*(?:\(\))?)\s*(?=\+|\)|,|$)", segment)
                        only_text = not re.search(
                            r"(?:^|\+)\s*[A-Za-z_$(]", re.sub(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'", "''", segment)
                        )
                        concat = not only_text and (not joined or any(not interp_safe(n, safe) for n in joined))  # (text
                        # joined to text, a statement split over lines, has nothing in it to inject)
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
                if templated is None:
                    templated = _template_lines(lines)
                if i not in templated:  # (not page script inside a template literal: a VS Code webview's HTML)
                    out["module_state"].hits.append(Evidence(fid, i, _excerpt(line)))
        if (
            not test
            and fid.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))  # the web's fetch; elsewhere it's any name
            and re.search(r"(?<![\w.])fetch\s*\(", text)
            and not re.search(r"\bsignal\b|AbortSignal\.timeout|timeout", text)
        ):
            # the first real call: not a comment, a function or method of that name, a data: or extension URL, or a
            # file bundled with the code (`fetch(new URL("./font.ttf", import.meta.url))`)
            ln = next((i for i, text in enumerate(lines, 1) if re.search(r"(?<![\w.])fetch\s*\(", text)
                       and not COMMENT_LINE.match(text) and not re.search(
                           r"function\s+fetch\b|\bfetch\s*\([^)]*:\s*[\w<>\[\]]+[^)]*\)\s*[:{;]|import\.meta\.url|"
                           r"data:|dataUrl|chrome-extension://|moz-extension://|blob:", " ".join(lines[i - 1 : i + 1]))),
                      None)  # fmt: skip
            if ln:
                out["fetch_no_timeout"].hits.append(Evidence(fid, ln, _excerpt(lines[ln - 1])))
        if (
            not test
            and fid.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
            and re.search(r"\baxios\b", text)
            and not re.search(r"\btimeout\b|\bsignal\b", text)  # (axios.create({ timeout }), defaults.timeout, a signal)
        ):  # axios waits forever by default, like fetch
            for i, line in enumerate(lines, 1):
                call = re.search(r"\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\s*\(", line)
                if call and hit("fetch_no_timeout", i):
                    out["fetch_no_timeout"].hits.append(Evidence(fid, i, _excerpt(line)))
        if not test and fid.endswith(".go"):  # the default client never times out
            server = next(
                (m for m in re.finditer(r"(?<![\w.])http\.ListenAndServe(?:TLS)?\(|&?(?<![\w.])http\.Server\{", text)
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
                    and not expected_failure(lines, i)
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
# a library's own build copied in, read from its first lines rather than its path: a webpack runtime
# (`webpackJsonp`, `__webpack_require__`), or the version banner a library's build keeps (`/*! Vue.js v2.7.14`,
# `@license React v16.13.1`). A project's own copyright header has no version number.
BUNDLED = re.compile(
    r"(?m)webpackJsonp|__webpack_require__|webpackBootstrap|^/\*{6}/|"
    r"^\s*(?:/\*!|\*|/\*\*?)\s*(?:@license\s+)?[A-Za-z][\w.@/ -]{1,40}?\s+(?:v\d+\.\d+(?:\.\d+)?|\d+\.\d+\.\d+)\b"
    r"(?=[\s\S]*(?:/\*!|@license|\(c\)|Copyright|Licen[cs]e))"
)
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
        dev_value = r"|^disabled$|for[-_ ]local|local[-_ ]dev|[-_]development$"  # appwrite's local defaults
        template = r"your|example|change|placeholder|dummy|secret[-_]?key|replace|insecure"
        if (len(value) >= 6 and not re.search(PLACEHOLDER + r"|^\$\{?\w+|changethis|secret$|password$" + dev_value, value, re.I)
                and not re.search(template, value, re.I)):  # fmt: skip
            return True  # (`your-secret-key`, `insecure-…` are a template's defaults; `hunter2hunter2` is someone's)
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
                listed = p.iterdir() if os.access(p, os.R_OK | os.X_OK) else ()  # (unreadable: skipped, as walks do)
                info["ci"] += [_rel(real, f) for f in sorted(listed) if f.is_file() and not f.name.startswith(".")]
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
        for p in sorted(root.glob(".env*"))
        if p.is_file()
        and not p.name.endswith((".example", ".sample", ".template", ".dist"))
        and not re.match(r"\.env\.(?:test|testing|ci|development|dev)\b", p.name)  # test and development settings
        and not links_outside(root, p.name)
        and _holds_secret(p)
    ]
    if info["readme"]:
        t = (real / info["readme"]).read_text(encoding="utf-8", errors="replace").lower()
        info["readme_run"] = bool(re.search(r"install|npm |pip |yarn |make |cargo |go run|docker", t))
    return info


# ---- testing -------------------------------------------------------------------------------------------------------


def test_reach(v: View, also: dict[str, set[str]] | set[str] | frozenset = frozenset()) -> set[str]:
    """Functions a test calls or hands on (a callback), directly or through others (`also`: ones tests reach in ways
    the graph doesn't link, followed the same way; as a dict, with the test files that reach each, if known)."""
    out_edges: dict[str, list[str]] = {}
    for e in v.g["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], []).append(e["dst"])
    tests = [fid for fid, f in v.fn.items() if is_test(f["file"])]
    mocks = {f["file"]: set(f["mocks"]) for f in v.fn.values() if f.get("mocks") and is_test(f["file"])}
    by = also if isinstance(also, dict) else {}
    mine: dict[str, list[str]] = {}
    for fid in tests:
        if v.fn[fid]["file"] in mocks:
            mine.setdefault(v.fn[fid]["file"], []).append(fid)
    start = [fid for fid in tests if v.fn[fid]["file"] not in mocks]
    for fid in also:  # reached by name: as it is, unless every test file naming it mocks things (then with each's)
        files = by.get(fid) or ()
        if fid not in v.fn:
            continue
        if not files or any(file not in mocks for file in files):
            start.append(fid)
        else:
            for file in files:
                mine[file].append(fid)
    seen, q = set(start), deque(start)
    while q:
        for nxt in out_edges.get(q.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    # a test file that mocks functions (vi.mock, patch): what it runs reaches them only when the test calls them
    # itself. Each such file goes on from where the rest stopped (what they reach, it reaches without mocks too).
    more: set[str] = set()
    for file, mocked in mocks.items():
        local, q = set(mine[file]), deque(mine[file])
        while q:
            cur = q.popleft()
            for nxt in out_edges.get(cur, []):
                if nxt in seen or nxt in local or (nxt in mocked and v.fn.get(cur, {}).get("file") != file):
                    continue
                local.add(nxt)
                q.append(nxt)
        more |= local
    return seen | more
