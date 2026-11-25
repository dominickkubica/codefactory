"""What kind of project this is, before judging it: the assessment step a security audit starts with.

Detected from manifests, the attack surface and the source text, each conclusion with the evidence for it:

- kind: mobile app, web app (UI + API), web service, desktop app, web front-end, command-line tool, data pipeline,
  library (and the other roles a repository also plays: a backend with a CLI, an app with scripts)
- deployment: where it runs and who can reach it: local-first on a device, a client of some backend, a server bound to
  this machine, a LAN, every interface, or deployed (Docker, Vercel, Fly…); a CLI or library on the user's machine
- users: one person (the device owner, whoever runs it), many accounts with sign-in, or a server with no sign-in found
- sensitive data: health and fitness, financial, location, contact details, photos and camera, accounts and passwords

The review ranks findings with it (`rerank.py`): the same line means different things in a local-first app, a public
API and a command-line tool. Detection can be wrong, so `[profile]` in factory.toml corrects any part of it.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .paths import is_test

MAX_READ = 400_000  # bytes per file read for sensitive-data detection: past that it's data or generated
SKIP_DIRS = {"node_modules", ".git", ".codefactory", ".venv", "venv", "dist", "build", "Pods", ".expo"}

# category -> (specific APIs: one use is enough; words: in at least two files; dependencies that mean it on their own).
# Both are matched on code with comments and strings removed, so prose and patterns about the data don't count.
SENSITIVE: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "health and fitness": (
        r"\bHealthKit\b|\bHKHealthStore\b|\bHKQuantityType\w*|\bHKWorkout\w*|\bHealthConnect\w*|\bhealth_connect\b",
        r"\bheart_?rate\w*|\bheartRate\w*|\bblood_?(?:pressure|glucose|oxygen)\w*|\bbodyFat\w*|\bbody_?fat\w*|"
        r"\bbody_?weight\w*|\bbodyWeight\w*|\bmenstrua\w*|\bmedications?\b|\bdiagnos[ie]s\b|\bsymptoms?\b|"
        r"\bcalories\b|\bworkouts?\b|\bsleep_?(?:stage|score)\w*",
        ("react-native-health", "@kingstinct/react-native-healthkit", "react-native-health-connect", "expo-health"),
    ),
    "financial": (
        r"\bstripe\.\w+|\bStripe\(|\bplaid\w*\.\w+|\bpaymentIntent\w*|\bpayment_intent\w*|\bIBApi\b|\bib_insync\b",
        r"\bbrokerage\w*|\bbuying_?power\b|\baccount_?balance\w*|\bnet_?liquidation\w*|\bcard_?number\b|"
        r"\brouting_?number\b|\biban\b|\bportfolio\w*|\btrades?_?(?:history|log)\b|\bpayees?\b|\bpayeeId\b",
        ("stripe", "@stripe/stripe-js", "@stripe/stripe-react-native", "plaid", "plaid-python", "react-plaid-link",
         "braintree", "paypalrestsdk", "alpaca-trade-api", "alpaca-py", "ib_insync", "ibapi", "robin_stocks",
         "schwab-py", "tda-api", "tastytrade", "ccxt", "coinbase", "yodlee"),
    ),
    "location": (
        r"\bCLLocationManager\b|\bgetCurrentPositionAsync\b|\bwatchPositionAsync\b|navigator\.geolocation|"
        r"\bFusedLocationProvider\w*|\bLocationManager\b",
        r"\buser_?location\w*|\buserLocation\w*|\bcurrent_?position\b|\bcurrentPosition\b",
        ("expo-location", "react-native-geolocation-service", "@react-native-community/geolocation"),
    ),
    "contact details": (
        r"\bCNContactStore\b|\bgetContactsAsync\b|\b(?:email|phone(?:_number)?|first_name|last_name|date_of_birth)\s*"
        r"[:=]\s*(?:models\.\w+Field|Column\(|mapped_column\(|EmailStr|db\.Column)",
        r"\bdate_?of_?birth\b|\bdateOfBirth\b|\bphone_?number\b|\bphoneNumber\b|\bhome_?address\b|\bstreet_?address\b",
        ("expo-contacts", "react-native-contacts"),
    ),
    "photos and camera": (
        r"\bPHPhotoLibrary\b|\bPHPickerViewController\b|\bAVCaptureDevice\b|\blaunchImageLibraryAsync\b|"
        r"\blaunchCameraAsync\b|\bUIImagePickerController\b|\bCameraView\b",
        r"(?!)",
        ("expo-camera", "expo-image-picker", "expo-media-library", "react-native-vision-camera", "react-native-image-picker"),
    ),
    "accounts and passwords": (
        r"\bbcrypt\.\w+|\bargon2\.\w+|\bpasslib\b|\bcheck_password\(|\bset_password\(|\bhash_?password\(|"
        r"\bcreateUserWithEmailAndPassword\b|\bsignInWithPassword\b|\bpbkdf2_hmac\(",
        r"\bpassword_?hash\w*|\bpasswordHash\w*|\bhashed_?password\b",
        ("bcrypt", "bcryptjs", "argon2", "argon2-cffi", "passlib", "next-auth", "@auth/core", "passport",
         "django-allauth", "flask-login", "fastapi-users", "devise", "@clerk/clerk-react", "@clerk/nextjs",
         "firebase-admin", "@supabase/supabase-js", "supabase"),
    ),
}  # fmt: skip
# comments and string literals, removed before looking for words (newlines kept, so line numbers stay right)
NOT_CODE = re.compile(
    r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|/\*[\s\S]*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|#[^\n]*'
)

AUTH_DEPS = {
    "next-auth", "@auth/core", "passport", "django-allauth", "flask-login", "flask-jwt-extended", "fastapi-users",
    "devise", "@clerk/clerk-react", "@clerk/nextjs", "@clerk/express", "firebase-admin", "@supabase/supabase-js",
    "supabase", "pyjwt", "python-jose", "jsonwebtoken", "jose", "authlib", "djangorestframework-simplejwt",
}  # fmt: skip
LOCAL_DB = {
    "expo-sqlite": "expo-sqlite", "@op-engineering/op-sqlite": "op-sqlite", "react-native-sqlite-storage": "SQLite",
    "realm": "Realm", "@nozbe/watermelondb": "WatermelonDB", "@react-native-async-storage/async-storage": "AsyncStorage",
    "react-native-mmkv": "MMKV", "dexie": "IndexedDB (Dexie)", "idb": "IndexedDB", "localforage": "localForage",
}  # fmt: skip
TEMPLATING = {"spring-boot-starter-thymeleaf", "thymeleaf", "jinja2", "django", "rails", "actionview", "ejs", "pug",
              "handlebars", "express-handlebars", "nunjucks", "freemarker", "twig",
              "spring-boot-starter-freemarker", "htmx"}  # fmt: skip
WEB_UI = {"react", "vue", "svelte", "@angular/core", "solid-js", "preact", "next", "nuxt", "@sveltejs/kit", "astro"}
DESKTOP = {"electron": "Electron", "@tauri-apps/api": "Tauri", "pyqt5": "PyQt", "pyqt6": "PyQt", "pyside6": "PySide",
           "wxpython": "wxPython", "kivy": "Kivy"}  # fmt: skip
PIPELINE = {"pandas", "polars", "duckdb", "pyspark", "apache-airflow", "dagster", "prefect", "dbt-core", "luigi",
            "great-expectations"}  # fmt: skip
CLI_LIBS = {"click", "typer", "fire", "docopt", "commander", "yargs", "oclif", "@oclif/core", "cac", "meow"}
WORKSPACES = {"packages", "apps", "services", "libs", "modules", "projects", "crates", "plugins"}
# what a deploy job runs: a cloud CLI or action, not just the word "deploy"
DEPLOY_ACTIONS = (
    r"aws-actions|google-github-actions|azure/|flyctl|vercel|netlify|wrangler|railway|kubectl|helm |docker push|heroku"
)
DEPLOY_FILES = {
    "Dockerfile": "Docker", "docker-compose.yml": "Docker Compose", "compose.yaml": "Docker Compose",
    "vercel.json": "Vercel", "netlify.toml": "Netlify", "fly.toml": "Fly.io", "render.yaml": "Render",
    "Procfile": "Heroku-style Procfile", "app.yaml": "Google App Engine", "serverless.yml": "Serverless",
    "railway.json": "Railway", "wrangler.toml": "Cloudflare Workers", "template.yaml": "AWS SAM",
}  # fmt: skip


@dataclass
class Profile:
    kind: str = "unknown"
    kind_evidence: list[str] = field(default_factory=list)
    also: list[str] = field(default_factory=list)  # other roles the repository plays
    deployment: str = "unknown"
    deployment_evidence: list[str] = field(default_factory=list)
    users: str = "unknown"
    users_evidence: list[str] = field(default_factory=list)
    sensitive: dict[str, list[str]] = field(default_factory=dict)  # category -> evidence (file:line text, or a dependency)
    endpoints: int = 0
    open_writes: int = 0
    stores: list[str] = field(default_factory=list)
    corrected: list[str] = field(default_factory=list)  # what factory.toml's [profile] overrode

    @property
    def local_first(self) -> bool:
        return self.deployment == "local-first"

    @property
    def single_user(self) -> bool:
        return self.users == "single user"

    @property
    def server(self) -> bool:
        return self.deployment in ("local server", "LAN server", "network server", "deployed server") or self.endpoints > 0

    @property
    def reachable_by_others(self) -> bool:
        """Someone other than the person running it can send it requests."""
        return self.deployment in ("LAN server", "network server", "deployed server")

    def summary(self) -> str:
        """One line: "a mobile app, local-first, single user, holding health and fitness data"."""
        parts = [self.kind if self.kind != "unknown" else "a codebase of unknown kind"]
        if self.deployment != "unknown":
            parts.append(self.deployment)
        if self.users != "unknown":
            parts.append(self.users)
        text = ", ".join(parts)
        if self.sensitive:
            text += f", holding {_join(list(self.sensitive))} data"
        article = "an" if text[:1].lower() in "aeiou" else "a"
        return f"{article} {text}" if not text.startswith(("a ", "an ")) else text

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "kind_evidence": self.kind_evidence, "also": self.also, "deployment": self.deployment,
            "deployment_evidence": self.deployment_evidence, "users": self.users, "users_evidence": self.users_evidence,
            "sensitive": self.sensitive, "endpoints": self.endpoints, "open_writes": self.open_writes,
            "stores": self.stores, "corrected": self.corrected, "summary": self.summary(),
        }  # fmt: skip


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


# ---- manifests -----------------------------------------------------------------------------------------------------


def _manifests(root: Path) -> dict:
    """Dependencies and entry points from every manifest at the root, one folder down, and inside workspace folders
    (`packages/*`, `apps/*`, `services/*`…, where monorepos keep their parts)."""
    out: dict = {"deps": {}, "npm_bin": [], "py_scripts": [], "go_main": [], "rust_bin": False, "flutter": False,
                 "pkg_main": [], "py_lib": False, "files": set(), "lib": [], "cli": [], "android": []}  # fmt: skip
    top = [p for p in sorted(root.iterdir()) if p.is_dir() and p.name not in SKIP_DIRS and not p.name.startswith(".")]
    nested = [c for d in top if d.name in WORKSPACES for c in sorted(d.iterdir()) if c.is_dir() and c.name not in SKIP_DIRS]
    for d in [root, *top, *nested[:60]]:
        rel = "" if d == root else d.relative_to(root).as_posix() + "/"
        pkg = d / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                data = {}
            for name in {**data.get("dependencies", {}), **data.get("peerDependencies", {})}:
                out["deps"].setdefault(name, f"{rel}package.json")
            for name in data.get("devDependencies", {}):
                out["deps"].setdefault(name, f"{rel}package.json (dev)")
            if data.get("bin"):
                out["npm_bin"].append(f"{rel}package.json bin")
            if data.get("main") or data.get("exports") or data.get("module"):
                out["pkg_main"].append(f"{rel}package.json")
        py = d / "pyproject.toml"
        if py.is_file():
            try:
                data = tomllib.loads(py.read_text(encoding="utf-8"))
            except (tomllib.TOMLDecodeError, OSError):
                data = {}
            project = data.get("project", {})
            for dep in project.get("dependencies", []):
                out["deps"].setdefault(re.split(r"[\s<>=!~\[;@(]", dep, maxsplit=1)[0].lower(), f"{rel}pyproject.toml")
            for dep in data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}:
                out["deps"].setdefault(dep.lower(), f"{rel}pyproject.toml")
            scripts = {**project.get("scripts", {}), **(data.get("tool", {}).get("poetry", {}).get("scripts", {}) or {})}
            out["py_scripts"] += [f"{rel}pyproject.toml [project.scripts] {name}" for name in list(scripts)[:3]]
            out["py_lib"] = out["py_lib"] or bool(project.get("name"))
        for setup in ("setup.cfg", "setup.py"):  # older Python packaging: console_scripts entry points
            if (d / setup).is_file() and re.search(r"console_scripts", (d / setup).read_text(encoding="utf-8", errors="replace")):
                out["py_scripts"].append(f"{rel}{setup} console_scripts")
                out["py_lib"] = True
        for req in sorted(d.glob("requirements*.txt")):
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.split("#")[0].strip()
                if s and not s.startswith("-"):
                    out["deps"].setdefault(re.split(r"[\s<>=!~\[;@]", s, maxsplit=1)[0].lower(), f"{rel}{req.name}")
        if (d / "pubspec.yaml").is_file() and "flutter" in (d / "pubspec.yaml").read_text(encoding="utf-8", errors="replace"):
            out["flutter"] = True
        if (d / "Cargo.toml").is_file():
            cargo = (d / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
            out["rust_bin"] = out["rust_bin"] or "[[bin]]" in cargo or (d / "src" / "main.rs").is_file()
            for dep in re.findall(r"^([\w-]+)\s*=", cargo.split("[dependencies]", 1)[-1], re.M):
                out["deps"].setdefault(dep, f"{rel}Cargo.toml")
        if (d / "go.mod").is_file():
            for dep in re.findall(
                r"^\s*([\w./-]+)\s+v[\d.]+", (d / "go.mod").read_text(encoding="utf-8", errors="replace"), re.M
            ):
                out["deps"].setdefault(dep.split("/")[-1].lower(), f"{rel}go.mod")
        _other_manifests(d, rel, out)
        for name in DEPLOY_FILES:
            if (d / name).is_file():
                out["files"].add(f"{rel}{name}")
    for p in (root / ".github" / "workflows").glob("*.y*ml"):
        text = p.read_text(encoding="utf-8", errors="replace")
        if re.search(r"docs|pages|site|storybook|book", p.stem, re.I) or "actions/deploy-pages" in text:
            continue  # publishes documentation, not the product
        if (
            re.search(r"deploy|release|prod|publish", p.stem, re.I)
            and re.search(DEPLOY_ACTIONS, text, re.I)
            or re.search(
                r"aws-actions/amazon-ecs-deploy|google-github-actions/deploy|azure/webapps-deploy|superfly/flyctl|"
                r"amondnet/vercel-action|netlify/actions|cloudflare/wrangler-action|railwayapp|kubectl apply|helm upgrade",
                text,
                re.I,
            )
        ):
            out["files"].add(f".github/workflows/{p.name} (deploys)")
    return out


def _other_manifests(d: Path, rel: str, out: dict) -> None:
    """Maven, Gradle, RubyGems/Bundler, Composer and .NET: dependencies, and whether it builds an app or a library."""
    read = lambda p: p.read_text(encoding="utf-8", errors="replace")  # noqa: E731
    if (d / "pom.xml").is_file():
        pom = read(d / "pom.xml")
        for dep in re.findall(r"<artifactId>([\w.-]+)</artifactId>", pom)[1:]:
            out["deps"].setdefault(dep.lower(), f"{rel}pom.xml")
        if not re.search(r"spring-boot-maven-plugin|<mainClass>|maven-shade-plugin|<packaging>war", pom):
            out["lib"].append(f"{rel}pom.xml (a jar with no main class)")
        elif "<mainClass>" in pom and "spring-boot" not in pom:
            out["cli"].append(f"{rel}pom.xml mainClass")
    for name in ("build.gradle", "build.gradle.kts"):
        if (d / name).is_file():
            gradle = read(d / name)
            for dep in re.findall(r"""['"]([\w.-]+):([\w.-]+):[^'"]*['"]""", gradle):
                out["deps"].setdefault(dep[1].lower(), f"{rel}{name}")
            if "com.android.application" in gradle:
                out["android"].append(f"{rel}{name} (com.android.application)")
            elif re.search(r"\bapplication\b\s*(?:\{|$)|mainClass|id\(?\s*['\"]application", gradle, re.M):
                out["cli"].append(f"{rel}{name} application")
            elif re.search(r"java-library|com\.android\.library|`java-library`|kotlin\(\"jvm\"\)|maven-publish", gradle):
                out["lib"].append(f"{rel}{name} (a library build)")
    gemspecs = sorted(d.glob("*.gemspec"))
    if gemspecs:
        spec = read(gemspecs[0])
        (out["cli"] if re.search(r"\.executables\s*=|bindir", spec) else out["lib"]).append(f"{rel}{gemspecs[0].name}")
    if (d / "Gemfile").is_file():
        for dep in re.findall(r"^\s*gem\s+['\"]([\w-]+)", read(d / "Gemfile"), re.M):
            out["deps"].setdefault(dep.lower(), f"{rel}Gemfile")
    if (d / "composer.json").is_file():
        try:
            data = json.loads(read(d / "composer.json"))
        except ValueError:
            data = {}
        for dep in data.get("require", {}):
            out["deps"].setdefault(dep.split("/")[-1].lower(), f"{rel}composer.json")
        if data.get("type") == "library":
            out["lib"].append(f"{rel}composer.json (type library)")
        if data.get("bin"):
            out["cli"].append(f"{rel}composer.json bin")
    for csproj in sorted(d.glob("*.csproj"))[:3]:
        text = read(csproj)
        if "<OutputType>Exe" in text and "Sdk.Web" not in text:
            out["cli"].append(f"{rel}{csproj.name} (Exe)")
        elif "Sdk.Web" not in text and "<OutputType>WinExe" not in text:
            out["lib"].append(f"{rel}{csproj.name} (a class library)")
        for dep in re.findall(r'PackageReference Include="([\w.-]+)"', text):
            out["deps"].setdefault(dep.lower(), f"{rel}{csproj.name}")


# ---- detection -----------------------------------------------------------------------------------------------------


def _source(root: Path, files: list[str]) -> dict[str, str]:
    out = {}
    for fid in files:
        if is_test(fid):
            continue
        try:
            with open(root / fid, "rb") as fh:
                out[fid] = fh.read(MAX_READ).decode("utf-8", errors="replace")
        except OSError:
            continue
    return out


def _swift_files(root: Path, files: list[str]) -> list[str]:
    """Swift files: from the graph, or from disk when Swift wasn't analyzed (no language pack installed)."""
    found = [f for f in files if f.endswith(".swift")]
    if found:
        return found
    out = []
    for p in root.rglob("*.swift"):
        rel = p.relative_to(root)
        if not SKIP_DIRS & set(rel.parts):
            out.append(rel.as_posix())
            if len(out) >= 200:
                break
    return sorted(out)


def _head(root: Path, rel: str, size: int = 4000) -> str:
    try:
        with open(root / rel, "rb") as fh:
            return fh.read(size).decode("utf-8", errors="replace")
    except OSError:
        return ""


def code_only(text: str) -> str:
    """The text without comments and string literals, line numbers unchanged."""
    return NOT_CODE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _first(texts: dict[str, str], code: dict[str, str], pattern: str, min_files: int = 1, limit: int = 3) -> list[str]:
    """`file:line` and the line where the pattern occurs in code (one per file), if it does in at least `min_files`."""
    rx = re.compile(pattern)
    hits = []
    for fid, text in code.items():
        if (m := rx.search(text)) is not None:
            line_no = text.count("\n", 0, m.start()) + 1
            lines = texts[fid].splitlines()
            hits.append(f"`{fid}:{line_no}` {lines[line_no - 1].strip()[:100] if line_no <= len(lines) else ''}")
    return hits[:limit] if len(hits) >= min_files else []


def detect(root: Path, g: dict, surface=None, config: dict | None = None) -> Profile:
    """The profile of the repository at `root` (graph `g`; the attack surface if already computed)."""
    if surface is None:
        from .brief import View
        from .security import surface as find_surface

        surface = find_surface(root, g, View(g))
    m = _manifests(root)
    deps = m["deps"]
    files = [f["id"] for f in g["files"]]
    texts = _source(root, files)
    p = Profile()
    p.open_writes = 0
    has = lambda *names: [n for n in names if n in deps]  # noqa: E731

    # what it is
    roles: list[tuple[str, list[str]]] = []
    wrapped_mobile: list[str] = []
    mobile = has("expo", "react-native") or (["pubspec.yaml (Flutter)"] if m["flutter"] else [])
    if not mobile:
        apple = [
            f for f in _swift_files(root, files) if re.search(r"\bimport (?:SwiftUI|UIKit)\b", texts.get(f) or _head(root, f))
        ]
        android = [
            p_.relative_to(root).as_posix()
            for p_ in root.glob("**/AndroidManifest.xml")
            if not SKIP_DIRS & set(p_.relative_to(root).parts)
        ][:1]
        mobile = [f"{apple[0]} (SwiftUI/UIKit)"] if apple else (m["android"] or android)
        wrapper = has("@capacitor/core", "@capacitor/ios", "cordova", "@ionic/core")
        if mobile and (wrapper or (has(*WEB_UI) and len(apple) < 10)):  # a web app's thin native shell
            wrapped_mobile = mobile
            mobile = []
    if mobile:
        roles.append(("mobile app", [f"{x} in {deps[x]}" if x in deps else x for x in mobile]))
    web_ui = [f"{d} in {deps[d]}" for d in has(*WEB_UI)]
    templates = [f"{d} in {deps[d]} (server-rendered pages)" for d in has(*TEMPLATING)]
    # endpoints in top-level examples, docs or benchmarks show what a library can do, not what this project serves
    # (only near the top: `org/springframework/samples/petclinic` is a Java package, not an examples folder)
    endpoints = [
        e for e in surface.entries if not re.match(r"(?:[^/]+/)?(?:examples?|samples?|demos?|docs?|benchmarks?)/", e.file)
    ]
    frameworks = sorted({e.framework for e in endpoints})
    if endpoints and (web_ui or templates) and not mobile:
        roles.append(("web app", [f"{len(endpoints)} HTTP endpoints ({', '.join(frameworks)})", (web_ui or templates)[0]]))
    elif endpoints:
        roles.append(("web service", [f"{len(endpoints)} HTTP endpoints ({', '.join(frameworks)})"]))
    desktop = has(*DESKTOP)
    if desktop:
        roles.append(("desktop app", [f"{d} in {deps[d]}" for d in desktop[:2]]))
    if web_ui and not endpoints and not mobile and not desktop:
        roles.append(("web front-end", web_ui[:1]))
    cli = m["py_scripts"] + m["npm_bin"] + m["cli"] + [f"{c} in {deps[c]}" for c in has(*CLI_LIBS)]
    if m["rust_bin"] and has("clap", "structopt", "argh"):
        cli.append("Rust binary with clap")
    go_main = [f for f in files if f.endswith(".go") and re.search(r"^package main\b", texts.get(f, ""), re.M)]
    if go_main and not endpoints:
        cli.append(f"`{go_main[0]}` package main")
    argparse = [
        f for f in files if f.endswith(".py") and "argparse.ArgumentParser" in texts.get(f, "") and "__main__" in texts.get(f, "")
    ]
    if argparse and not cli:
        cli.append(f"`{argparse[0]}` argparse")
    if cli:
        roles.append(("command-line tool", cli[:2]))
    pipeline = has(*PIPELINE)
    if pipeline and not endpoints and not mobile:
        roles.append(("data pipeline", [f"{x} in {deps[x]}" for x in pipeline[:3]]))
    if not roles and (m["lib"] or m["py_lib"] or m["pkg_main"] or (not m["rust_bin"] and (root / "Cargo.toml").is_file())):
        roles.append(("library", (m["lib"] + m["pkg_main"])[:1] or ["a package manifest and no app or entry point"]))
    p.endpoints = len(endpoints)
    if wrapped_mobile:
        roles.append(("mobile app", [f"{wrapped_mobile[0]}, a native shell around the web app"]))
    if roles:
        p.kind, p.kind_evidence = roles[0]
        p.also = [r for r, _ in roles[1:] if r != p.kind]

    # what it keeps
    p.stores = [name for dep, name in LOCAL_DB.items() if dep in deps]
    native_db = [
        f
        for f in files
        if f.endswith(".swift") and re.search(r"\b(?:import CoreData|import SwiftData|@Model\b)", texts.get(f, ""))
    ]
    if native_db:
        p.stores.append("Core Data / SwiftData")

    # where it runs, who reaches it
    deployed = sorted(m["files"])
    if endpoints or (deployed and p.kind in ("web app", "web service")):
        if deployed:
            p.deployment = "deployed server"
            p.deployment_evidence = [f"{x} ({DEPLOY_FILES.get(x.split('/')[-1], 'CI deploy')})" for x in deployed[:3]]
        else:
            p.deployment = {"local": "local server", "configurable": "LAN server", "open": "network server"}.get(
                surface.exposure, "network server"
            )
            p.deployment_evidence = [surface.exposure_evidence or "HTTP endpoints, and nothing says where it listens"]
    elif p.kind == "mobile app":
        if p.stores:
            p.deployment = "local-first"
            p.deployment_evidence = [f"data kept on the device ({', '.join(p.stores)}), no server in the repository"]
        else:
            p.deployment = "client app"
            p.deployment_evidence = ["no local database and no server in the repository: it talks to a backend elsewhere"]
    elif p.kind in ("command-line tool", "library", "data pipeline", "desktop app"):
        p.deployment = "user's machine"
        p.deployment_evidence = [f"a {p.kind}: runs where it's installed"]
    elif p.kind == "web front-end":
        p.deployment = "browser"
        p.deployment_evidence = ["a front-end with no API of its own in the repository"]

    auth_deps = sorted(AUTH_DEPS & set(deps))
    guarded = [e for e in endpoints if e.auth]
    if auth_deps or guarded:
        p.users = "multi-user"
        p.users_evidence = ([f"{auth_deps[0]} in {deps[auth_deps[0]]}"] if auth_deps else []) + (
            [f"{len(guarded)} of {len(endpoints)} endpoints check who's asking"] if guarded else []
        )
    elif endpoints:
        p.users = "no sign-in"
        p.users_evidence = ["no endpoint checks who's asking, and no sign-in library"]
    elif p.kind in ("mobile app", "desktop app") or p.deployment == "local-first":
        p.users = "single user"
        p.users_evidence = ["no sign-in or accounts: whoever holds the device"]
    elif p.kind in ("command-line tool", "library", "data pipeline"):
        p.users = "single user"
        p.users_evidence = ["whoever runs it"]

    # what it holds
    code = {fid: code_only(text) for fid, text in texts.items()}
    for category, (strong, words, dep_names) in SENSITIVE.items():
        found = [f"{d} in {deps[d]}" for d in dep_names if d in deps][:2]
        found += _first(texts, code, strong) or _first(texts, code, words, min_files=2)
        if found:
            p.sensitive[category] = found[:3]

    _correct(p, config if config is not None else _config(root))
    return p


def _config(root: Path) -> dict:
    from .config import load_config

    return load_config(root).profile


def _correct(p: Profile, cfg: dict) -> None:
    """Apply factory.toml's [profile]: the team knows better than any detection."""
    for key in ("kind", "deployment", "users"):
        if key in cfg and cfg[key] != getattr(p, key):
            p.corrected.append(f"{key}: {getattr(p, key)} → {cfg[key]}")
            setattr(p, key, cfg[key])
            setattr(p, f"{key}_evidence", ["set in factory.toml [profile]"])
    if "sensitive" in cfg:
        wanted = cfg["sensitive"]
        dropped = [c for c in p.sensitive if c not in wanted]
        added = [c for c in wanted if c not in p.sensitive]
        for c in dropped:
            del p.sensitive[c]
        for c in added:
            p.sensitive[c] = ["set in factory.toml [profile]"]
        if dropped or added:
            p.corrected.append("sensitive: " + ", ".join([f"-{c}" for c in dropped] + [f"+{c}" for c in added]))


def markdown(p: Profile) -> list[str]:
    """The profile as review lines (a list, to splice into a report)."""
    out = [f"**{p.summary()[0].upper() + p.summary()[1:]}.**", ""]
    rows = [
        ("Kind", p.kind + (f" (also: {', '.join(p.also)})" if p.also else ""), p.kind_evidence),
        ("Runs", p.deployment, p.deployment_evidence),
        ("Users", p.users, p.users_evidence),
    ]
    out += ["| | | Evidence |", "|---|---|---|"]
    for label, value, ev in rows:
        out.append(f"| {label} | {value} | {'; '.join(ev[:2]) or '-'} |")
    for category, ev in p.sensitive.items():
        out.append(f"| Holds | {category} | {'; '.join(ev[:2])} |")
    if not p.sensitive:
        out.append("| Holds | no sensitive data found | - |")
    if p.corrected:
        out += ["", f"_Corrected in factory.toml: {'; '.join(p.corrected)}._"]
    out += ["", "_Wrong? Correct it in factory.toml (`[profile]` kind, deployment, users, sensitive) and every review "
            "and pull-request check ranks with it._"]  # fmt: skip
    return out
