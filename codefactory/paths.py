"""What kind of file a path is. One definition, used by every check, so they all agree on what's a test."""

from __future__ import annotations

import functools
import re
from pathlib import Path

TEST_DIRS = (
    "tests",
    "test",
    "testing",
    "__tests__",
    "__mocks__",
    "spec",
    "t",
    "testdata",
    "fixtures",
    "playwright",
    "cypress",
)  # t/: celery's; playwright/, cypress/: end-to-end suites
# a folder or file named for tests among other words: e2e-auth-server/, test-utils/, prepare-v1-test-db.mjs
TEST_TOKEN = re.compile(r"(?:^|[-_.])(?:e2e|tests?|testing)(?:[-_.]|$)", re.I)
SCRIPT_DIRS = ("scripts", "script", "tools", "bin", "benchmarks", "benchmarking", "build-logic", "buildSrc")


def ignored(path: str, ignore: list[str]) -> bool:
    """In a folder factory.toml's `ignore` names (fixtures, vendor…): left out of every check, like the analyzers do."""
    return bool(set(path.replace("\\", "/").split("/")[:-1]) & set(ignore))


def drop_ignored(checks: dict, root) -> dict:
    """Remove evidence in ignored folders from a {key: Check} result."""
    from .config import load_config

    ignore = load_config(root).ignore
    if ignore:
        for c in checks.values():
            c.hits = [e for e in c.hits if not ignored(e.file, ignore)]
    return checks


# folders no check needs to look inside: dependencies, environments, build output, caches
NOT_SOURCE = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".codefactory",
                        "site-packages", "dist", "build", "Pods", ".expo", ".next", ".nuxt", ".gradle", "DerivedData",
                        "coverage", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "bower_components"})  # fmt: skip


def walk(root, names: tuple[str, ...] = (), suffixes: tuple[str, ...] = (), skip=NOT_SOURCE, hidden: bool = True):
    """Relative paths (posix) of the files under `root` with one of these names or suffixes (all files if neither),
    pruning `skip` folders (and hidden ones unless `hidden`) before descending: `Path.rglob` walks all of
    node_modules first and filters after, which on a JavaScript project is most of the time spent."""
    import os

    root = str(root)
    plain, links = set(), []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and (hidden or not d.startswith("."))]
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        for name in filenames:
            if (names or suffixes) and name not in names and not name.endswith(suffixes):
                continue
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if os.path.islink(os.path.join(root, rel)):
                links.append(rel)
            else:
                plain.add(rel)
                yield rel
    copies = link_copies(root, plain | set(links))
    for rel in links:
        if rel not in copies and not links_outside(root, rel):
            yield rel


# someone else's code copied in (a bundled jQuery, a minified build): its patterns aren't this project's to fix
VENDORED = re.compile(
    r"(?:^|/)(?:vendor|vendored|third_party|thirdparty|3rdparty|bower_components|external-crates|sljit|pcre2)/|"
    r"\.min\.(?:js|css)$"
)  # (whole libraries copied in: Appwrite's crates/…/pcre2/sljit, meilisearch's external-crates)


def is_vendored(path: str) -> bool:
    return bool(VENDORED.search(path.replace("\\", "/")))


# documentation and example code: a top-level docs site or examples folder (docs/, dev-docs/, examples/), and tutorial
# folders anywhere (docs_src/, tutorials/). Not `app/docs/`: a product can have a documents feature.
DOC_SAMPLE = re.compile(
    r"^(?:[\w-]*docs?|documentation|examples?|samples?|website|playgrounds?)/|(?:^|/)(?:docs_src|tutorials?)/", re.I
)


# example, sample, snippet and template code at any depth (packages/platform/examples/, connect-snippets/,
# templates/simple-server-example/): what a project shows others how to build, not what it serves
EXAMPLE_CODE = re.compile(r"(?:^|[-_/])(?:examples?|samples?|snippets?|demos?|templates?)(?:[-_/]|$)", re.I)


def is_example_code(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")[:-1]
    for i in range(len(parts) - 1):  # below src/main/ (Java, Kotlin, Scala) the folders are a package name:
        if parts[i] == "src" and parts[i + 1] in ("main", "test"):  # org/springframework/samples/petclinic
            parts = parts[:i]
            break
    return bool(EXAMPLE_CODE.search("/".join(parts)))


def is_sample_code(path: str) -> bool:
    """Example, sample, demo and starter-template code (`examples/`, `samples/guide/`, `template-vanilla-ts/`,
    `project_template/`), but not a web app's `templates/` folder, whose files are the app's own pages."""
    parts = [p for p in path.replace("\\", "/").split("/")[:-1] if p.lower() not in ("templates", "template")]
    return is_example_code("/".join([*parts, "x"]))


def is_doc_sample(path: str) -> bool:
    return bool(DOC_SAMPLE.search(path.replace("\\", "/")))


@functools.lru_cache(maxsize=65536)
def is_test(path: str) -> bool:
    """tests/…, __tests__/…, test_*.py, *_test.py, *.test.ts, *.spec.js…"""
    parts = path.replace("\\", "/").split("/")
    name = parts[-1]
    return (
        any(p in TEST_DIRS or TEST_TOKEN.search(p) for p in parts[:-1])
        or (len(parts) > 1 and parts[0] in ("integration", "integration_tests"))  # nest's integration/, at the top only
        or TEST_TOKEN.search(name.rsplit(".", 1)[0]) is not None
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
        or TEST_NAME.search(name) is not None
    )


# Other languages' conventions: Go's x_test.go, Ruby's x_spec.rb, Java/Kotlin/C#/Swift/Scala's FooTest(s).java
TEST_NAME = re.compile(r"_(?:test|spec|tests)\.\w+$|[a-z0-9]Tests?\.(?:java|kt|cs|swift|scala|groovy|php|m)$")


def is_script(path: str) -> bool:
    """One-off tooling (scripts/, tools/, bin/ at the top, or a package's own scripts/ in a monorepo): matters less
    than the product's code."""
    parts = path.replace("\\", "/").split("/")
    # (or a seed script: fills a database with demo rows once, `prisma/seed-pbac-only.ts`, `examples/…/seed.py`)
    return parts[0] in SCRIPT_DIRS or "scripts" in parts[1:-1] or bool(SEED.match(parts[-1]))


SEED = re.compile(r"seed(?:s|ers?)?(?:[-_.][\w-]+)*\.(?:py|rb|php|[cm]?[jt]sx?|go|exs?)$", re.I)


# Platform and architecture tags in file names (Go's file_linux_amd64.go, C's io_win32.c, Python's _posix.py).
PLATFORM = re.compile(
    r"[._-](?:linux|darwin|windows|win32|win64|nt|posix|unix|bsd|freebsd|netbsd|openbsd|dragonfly|solaris|illumos|aix|"
    r"plan9|android|ios|macos|osx|wasm|wasip1|js|zos|hurd|amd64|x86_64|x64|386|x86|i386|arm|arm64|aarch64|armv7|"
    r"mips|mipsle|mips64|mips64le|ppc|ppc64|ppc64le|riscv|riscv64|s390x|loong64|sparc64|generic|noasm|purego|asm|"
    r"cgo|nocgo|other|fallback|stub|stubs|default)(?=[._-]|$)",
    re.I,
)


def platform_variants(a: str, b: str) -> bool:
    """Two files that are the same file for different platforms (their copies are on purpose)."""
    if a == b:
        return False
    da, _, na = a.rpartition("/")
    db, _, nb = b.rpartition("/")
    if da != db:
        return False
    sa, sb = PLATFORM.sub("", na.rsplit(".", 1)[0]), PLATFORM.sub("", nb.rsplit(".", 1)[0])
    return sa == sb and (sa != na.rsplit(".", 1)[0] or sb != nb.rsplit(".", 1)[0])


def cache_dir(root) -> Path | None:
    """The repository's cache folder (`.codefactory/`), or None when it can't be trusted: a symbolic link (writes and
    the diff's cleanup would land wherever it points) or committed to git (a pull request could plant results that
    hide its findings). Then nothing is cached: every run analyzes in full."""
    found = _cache_dir(str(Path(root).resolve()))
    return Path(found) if found else None


@functools.lru_cache(maxsize=64)
def _cache_dir(root: str) -> str | None:
    import subprocess
    import sys

    d = Path(root) / ".codefactory"
    why = ""
    if d.is_symlink() or (d.exists() and not d.is_dir()):
        why = "is a symbolic link or a file"
    else:
        try:
            out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", ".codefactory"], capture_output=True,
                                 text=True, timeout=60)  # fmt: skip
            if out.returncode == 0 and out.stdout.strip("\0"):
                why = "is committed to git"
        except (OSError, subprocess.TimeoutExpired):
            pass  # no git: nothing can be committed
    if why:
        print(f"codefactory: {d} {why}, so it isn't used as a cache (a repository could use it to redirect writes or "
              "plant results); analyzing in full.", file=sys.stderr)  # fmt: skip
        return None
    return str(d)


# A file's stamp, for the caches: size, modification time and change time. The change time catches a copy that keeps
# the old modification time (cp -p, tar, rsync -t); a file changed within RACY_NS of the stamp being taken isn't
# trusted at all, since a second same-size edit in the same clock tick would look unchanged (git's "racy" rule).
RACY_NS = 2_000_000_000


def file_stamp(st) -> str:
    return f"{st.st_size}|{st.st_mtime_ns}|{st.st_ctime_ns}"


def racy(st, now_ns: int) -> bool:
    return max(st.st_mtime_ns, st.st_ctime_ns) >= now_ns - RACY_NS


def links_outside(root, rel) -> bool:
    """A file that is a symbolic link to somewhere outside `root`. Its text isn't the repository's (a pull request can
    commit `config.py -> ~/.aws/credentials`), so no check reads it. A link within the repository is fine, and
    skipped where its target is read anyway (link_copies). (Folder links aren't descended into: os.walk doesn't
    follow them.)"""
    import os

    full = os.path.join(str(root), str(rel))
    if not os.path.islink(full):
        return False
    try:
        return not Path(full).resolve().is_relative_to(Path(root).resolve())
    except (OSError, RuntimeError):  # a loop, or unreadable: not ours either
        return True


def link_copies(root, rels) -> set[str]:
    """The links among `rels` (files under `root`) to a file of the repository that is read anyway: listed itself, or
    through an earlier link. Its text would be analyzed, and reported, once per path (owid/etl links 102 step files to
    one shared module). Links to outside the repository are left to links_outside."""
    import os

    rels = set(rels)
    out: set[str] = set()
    links = sorted(r for r in rels if os.path.islink(os.path.join(str(root), r)))
    if not links:
        return out
    top = Path(root).resolve()
    seen: set[str] = set()
    for rel in links:
        try:
            real = Path(root, rel).resolve()
        except (OSError, RuntimeError):
            continue
        if not real.is_relative_to(top):
            continue
        target = real.relative_to(top).as_posix()
        if target in seen or (target in rels and target not in links):
            out.add(rel)
        seen.add(target)
    return out


def write_file(path, text: str) -> None:
    """Write a file, never through a symbolic link: an output path inside a repository (the Action's comment file, a
    baseline) can be a link a pull request committed, pointing at something to overwrite or, once read back, publish."""
    import os

    path = Path(path)
    if path.is_symlink():
        raise OSError(f"{path} is a symbolic link; not writing through it")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)  # (and no link swapped in meanwhile)
    with os.fdopen(os.open(path, flags, 0o644), "w", encoding="utf-8") as f:
        f.write(text)


# Development and test infrastructure: dev containers, sandboxes, test harnesses, benchmark and release-check setups,
# and files named for development (docker-compose.dev.yml, Dockerfile.playwright, compose.override.yml). What runs
# there isn't what ships, so container and compose findings about it aren't findings about the product.
DEV_DIRS = re.compile(
    r"(?:^|/)(?:\.devcontainer|\.codesandbox|\.gitpod|\.oss-scanner|devcontainer|playwright|cypress|e2e|benchmarks?|bench|"
    r"perf|load-?tests?|releasing|docs?|examples?|samples?|demos?|playgrounds?|sandbox|fixtures|integration|dev|"
    r"development|local|testing|tests?)/",
    re.I,
)
DEV_NAME = re.compile(r"(?:^|[._-])(?:dev|devel|development|local|test|tests|testing|ci|e2e|playwright|cypress|override|"
                      r"example|sample|demo|debug|docs|bench|benchmark|buildx?|builder)(?:[._-]|$)", re.I)  # fmt: skip


def is_dev_setup(path: str) -> bool:
    """A Dockerfile or compose file for developing, testing or demonstrating, not for running the product."""
    path = path.replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    return (
        bool(
            DEV_DIRS.search(path)
            or DEV_NAME.search(name.lower().replace("dockerfile", "").replace("docker-compose", "").replace("compose", ""))
        )
        or is_test(path)
        or is_example_code(path)
    )


VERSION_PART = re.compile(r"(?<![^/_-])(?:\d{4}-\d{2}-\d{2}|\d{8})(?![^/_.-])")  # dated: frozen on purpose
BUILD_OUTPUT = re.compile(r"(?:^|/)(?:priv/static|dist|build|out|public/build|static/dist)/|\.(?:min|bundle)\.[cm]?js$", re.I)


def deliberate_copies(files: list[str]) -> bool:
    """Copies made on purpose: one file per dated version (a data pipeline's frozen steps, `2024-12-06/x.py` and
    `2026-05-22/x.py`; `reader/v2` and `reader/v3` sharing code is still worth merging), per-crate build scripts,
    build outputs, vendored code, or examples and starter templates that each stand alone."""
    if all(BUILD_OUTPUT.search(f) or is_vendored(f) or is_sample_code(f) for f in files):
        return True
    names = {f.rsplit("/", 1)[-1] for f in files}
    if names == {"build.rs"}:
        return True  # Cargo build scripts: one per crate, each the same few lines of scaffold
    folders = [f.rsplit("/", 1)[0] for f in files]
    if len(set(folders)) < len(files):
        return False
    dirs = {VERSION_PART.sub("V", d) for d in folders}
    # (also the same step re-dated under a renamed source: `cdc/2026-11-06/x.py` from `reports/2025-03-14/x.py`)
    if len(dirs) == 1 and "V" in next(iter(dirs)):
        return True
    return len(names) == 1 and all(VERSION_PART.search(d) for d in folders)
