# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); before 1.0, minor versions may
change command-line output.

## 0.20.3 · 2026-11-26

### Security
From an audit of codefactory itself: what a repository being analyzed, or a pull request to it, could make it do.
Each has a regression test (`tests/test_security_audit.py`).

- **A `.codefactory/` that is a symbolic link or committed to git is never used.** A pull request could point it
  elsewhere, and the diff's clean-up of old bases (which deletes folders) would have followed it; or commit a fake
  "base" that made its own findings look old. Nothing is cached then. Links inside the folder are removed, never
  followed, and a diff's base leaves out `.codefactory/` and anything linking outside (a planted link used to stop
  the diff with an error).
- **codefactory never runs the TypeScript compiler inside the analyzed repository.** It used the project's
  `node_modules/typescript`, which a pull request can commit (or plant through a dependency): running the analyzed
  code, against SECURITY.md's promise. TypeScript now needs a compiler you installed, `npm install -g typescript@5`
  (or `CODEFACTORY_TYPESCRIPT`); one found inside the repository is refused even when `node` itself is (as with
  `node_modules/.bin` on PATH during `npm run`). Module resolution still comes from the project's tsconfig. The Action
  installs its own pinned TypeScript 5.9.3. **If you relied on `npm install` in the project for TypeScript analysis,
  install TypeScript globally once.** The Claude Code session hook does it for you (`typescript@5`, when Node is
  there and no global one is).
- **Secrets are reported cut to their first 4 characters** (`AKIA…`) in the review, PR comments, SARIF and
  annotations; keys found only in git history were being re-published in full.
- **`diff --github` escapes its workflow commands**: a newline in a finding could have started a command of its own,
  and a comma or colon in a file name ended the property early (annotations from `sarif --github` now escape file
  names too).
- **Saved queries in `factory.toml` can only read** (no ATTACH, which creates a file anywhere, no writes or PRAGMA)
  and stop after 30 seconds. `codefactory query` runs read-only the same way.
- **The Action works on pull requests from forks**: the comment step (which failed on their read-only token) runs
  only for the same repository, and the result also goes to the job summary.
- **The Action installs only exact, hash-checked versions** of tree-sitter and the language pack
  (`action-requirements.txt`), and runs codefactory from its own files instead of installing it.
- **The caches notice a file copied with its old modification time** (cp -p, tar, rsync -t): stamps include the
  change time (Linux and macOS: Windows reports the creation time there, so a copy must also match the old time to
  the 100 ns to slip through), and a file changed within two seconds of being stamped isn't trusted (git's "racy"
  rule, on every system).

### Fixed
- **Projects on TypeScript 7** (the native rewrite, which ships no JavaScript API yet) made the TypeScript analyzer
  fail outright. A compiler without the API is skipped for the next one (a global TypeScript 5), and with none the
  review says how to get one.

### Profiles
From running on a set of personal repositories (18: apps, sites, class projects, scripts):

- Streamlit, Gradio, Dash and Panel apps are profiled as web apps (with where each listens by default: Streamlit on
  every interface, the others on localhost). Six Streamlit apps had read as command-line tools or data pipelines.
- Static websites (an index.html, no server code) are a kind of their own, instead of "unknown"; "No automated tests"
  and "No continuous integration" are Low for them.
- A small project (under 2,000 lines) that isn't deployed, has no accounts and holds no health or financial data gets
  "No continuous integration" as Low and "No automated tests" as Medium, each with the reason. A 391-line script had
  been told its missing CI was High. Unknown kinds keep the default.

## 0.20.2 · 2026-11-26

- On PyPI: `pip install "codefactory-cli[languages]"` (`codefactory` on PyPI is an unrelated project; the command is
  still `codefactory`). `codefactory update` and the session hook now install from PyPI, so they get released
  versions rather than whatever is on the main branch, and first remove an install from GitHub: the two share
  every file, so removing either later would have broken the other.
- The session hook uses an installed `codefactory` command when there is one (pipx, a virtualenv) and upgrades it
  with that install's own Python. Before, a pipx install on a Mac was never found: the hook tried to reinstall with
  `python3` on every session (Homebrew's Python refuses that; without developer tools, `python3` opens an install
  dialog) and never upgraded.

## 0.20.1 · 2026-11-26

Bugs found by testing every command in every environment, and a speed pass.

### Faster
- `flags` on 1.7M lines: 54 s to 0.9 s (each finding searched every function; now an index).
- `review` with nothing changed: Actual Budget 9.4 s to 4.5 s, a React Native app with node_modules 8.7 s to 2.0 s,
  1.7M lines 20 s to 11 s. File walks no longer descend into node_modules, virtualenvs and build output (Python's
  `rglob` walked all of them and filtered after); sensitive-data detection only runs its regexes on files containing
  one of its words; the iOS-permission and personal-data checks search each file once before looking at lines; the
  history secret scan prefilters with one combined pattern; git history is read in a background thread and cached by
  HEAD commit.
- `plan` on 1.7M lines: 3 s to 1.1 s (copy groups each re-scanned every finding); Django URL matching uses an index.

### Fixed
- Found by running codefactory on itself: Jinja's `| safe` filter matched `allow|safe` inside a regular expression (it
  now needs template syntax, `{{ x | safe }}`); and a key marked as intended (`codefactory: ignore-file secret`) was
  reported as deleted but still in history, because the history check took "not reported" for "not in the code".
- Line checks (credentials, SQL, shell, privacy, Swift) ran only on files an analyzer could parse: without Node.js's
  TypeScript or the language pack, JavaScript, TypeScript and other files got no line checks at all. They now run on
  every source file on disk, parsed or not; the profile reads them too, and hotspot coupling counts them.
- The graph cache ignored changes to Go, Java, Kotlin, Swift, Rust, Ruby, PHP, C# and every other tree-sitter
  language: editing such a file kept the old graph until `--no-cache`. It now covers every language an analyzer reads.
- The graph cache didn't know which parsers were installed: installing the language pack or TypeScript after a first
  run kept the graph without those languages. Parser availability is now part of the cache key.
- A subfolder of a repository (a package in a monorepo) was mishandled by everything that reads git: `diff` compared
  it with an empty base (every finding "new"), hotspots read the whole repository's history with paths that matched
  nothing, the changed-files list and the history secret scan used the top-level paths. All are now scoped to the
  folder analyzed, with paths relative to it.
- CI also runs the tests on a bare machine (no TypeScript, no language pack), as the release build does: the v0.20.0
  release build failed there.

## 0.20.0 · 2026-11-26

Shell, Make, YAML, HTML, Pkl, more Go, and patches.

### Added
- **Configuration files** (YAML, TOML, INI, `.properties`, Pkl, Terraform, Makefiles, patches) are searched for
  credentials, including unquoted ones (`REGISTRY_PASSWORD = …`, `password: …`).
- **Shell scripts and Makefile recipes:** downloads piped into a shell, `rm -rf` on a shell or Make variable that may
  be empty, `eval` of a variable.
- **docker-compose:** privileged or host-network containers, databases published on every interface, passwords in
  `environment:`. **Kubernetes:** privileged or root containers, host network/PID/IPC/paths, Secrets committed with
  their values.
- **HTML:** scripts, styles, frames, images and forms over plain HTTP; CDN scripts without integrity hashes.
- **Pkl, TOML, Terraform:** plain-HTTP URLs to registries and packages.
- **Go:** `InsecureSkipVerify`, `math/rand` for tokens, `exec.Command("sh", "-c", …)` with a built command, HTTP
  servers with no timeouts.
- **`codefactory diff --patch FILE`** (or `-`): check the lines a unified diff adds, without the repository.
- The accuracy benchmark gained 26 cases and 26 look-alikes for these (all at 100%); tuned against them and 24 public
  repositories, where 8 findings remained, all real.

## 0.19.0 · 2026-11-26

A third round of public repositories: new frameworks, and the false findings they showed (see docs/ACCURACY.md).

### Added
- Attack surface for **Laravel** (routes files, `middleware('auth')` groups) and **Symfony** (`#[Route]`,
  `#[IsGranted]`), **Rust** (Rocket and Actix attributes, Axum routers; request guards whose `FromRequest` checks a
  token or session count as auth), **ASP.NET** (minimal APIs with `RequireAuthorization()` groups, controllers with
  `[Authorize]`) and **Phoenix** (router, `pipe_through`, `live_session`, controller plugs).
- Profile: `Package.swift` libraries, `mix.exs`, full Composer names, Dockerfile variants, server-rendered pages in
  Laravel, Phoenix, Rocket and Blazor; scripts with no manifest that import a data or ML library are a data pipeline.
- A receiver declared as a repository, DAO, entity manager or database context is a database (Spring Data's
  `owners.save()`, Room's `dao.insert()`, Core Data's `context.save()`).

### Fixed
- `insert`, `save`, `update`, `select` on an unknown object are database calls only in Ruby and PHP (Active Record,
  Eloquent); in Rust, Go, Java, Kotlin and C# they're usually collections.
- Next.js handlers that call a `verify…Access/User/Session(…)` check, and webhooks that check a signature
  (`constructEvent`), count as protected.
- Committed env files are reported only when one holds a real value for a secret-looking key, not for templates.
- A private-key header counts only as a key block (ending its line, or followed by key data), not a format check.
- `catch (_: Exception) {}` (and `ignored`, `expected`) is deliberate.
- Import loops skip Rust (a crate may cycle), test helpers, and factories and seeders.
- Variables set to one of two string literals (`$x = cond ? 'a' : 'b'`) are safe in SQL.
- Code execution in a data pipeline is ranked Medium, as in a command-line tool.
- Profile: example, test and end-to-end folders aren't the product; a server project's mobile client and a Swift
  package's demo app don't make it a mobile app; generated and translation files don't count as sensitive data; an
  app's own small server doesn't change where it runs; "client app" no longer claims a backend.
- Hotspots and coupling skip vendored libraries (jQuery, DataTables…), generated code (`frb_generated.*`) and
  translation files; Rust files in one folder are one module.

## 0.18.2 · 2026-11-25

Fixes from a second round of public repositories: Rails, Django, Kotlin Android, two Go services and a data pipeline
(see docs/ACCURACY.md).

### Fixed
- Rails: auth inherited from a parent controller or added by an included concern is seen; `skip_before_action` and
  helpers like `skip_authentication only:` open just those actions.
- Django: each URL maps to one handler (nearest the urls.py, in the module it names), not every function of that name.
- Data flow: redirects to a path the app builds (`reverse()`, `url_for()`, `"/…"`, plus a query string) and values
  checked first by a validator (`if _allow_redirect(x):`, `url_has_allowed_host_and_scheme`) aren't open redirects.
- Sign-in, sign-up, password-reset and magic-link endpoints aren't counted as unprotected writes.
- Pattern checks skip comment lines (except credentials); clearing an element (`innerHTML = ""`) and `mark_safe` of a
  settings value aren't raw HTML; a sentence about a PEM block isn't a key; "not-a-real", "fake", "redacted", "sample"
  and "mock" mark placeholders.
- A test server's bind address isn't evidence of where the product listens.
- Personal data in logs or storage is ranked High for health and financial data only, not because an app has
  passwords somewhere.
- Profile: Room, SQLDelight, Realm, Hive and Drift are on-device storage; Gradle version catalogs are read; a data
  pipeline with a few endpoints stays a data pipeline (running on the user's machine); contact fields in Rails
  schemas, SQL and Prisma count.
- Hotspots: files in one Go, Kotlin, Java, Swift or C# package aren't reported as unlinked coupling.

## 0.18.1 · 2026-11-25

Fixes from assessing seven public repositories (see docs/ACCURACY.md).

### Fixed
- Spring endpoints were never found: tree-sitter starts a Java or Kotlin method at its annotation, and only the lines
  above it were read.
- `@mock.patch(...)` in tests was read as a Flask route; test files no longer contribute endpoints.
- CI injection is only reported in what a shell or github-script runs (`run:`, `script:`), not in `env:` (the safe
  pattern) or a checkout's `ref:`.
- `pull_request_target` counts as checking out fork code only when a checkout's `ref:` (or a command) fetches the PR
  head, not when the head sha is merely used; and `on: pull_request_target` written on one line is now seen.
- Data flow: `uuid.UUID`-typed parameters are safe, and `session.get/delete` is a database session, not HTTP.
- Git history: minified and vendored files (`.yarn/releases`, `dist/`, `vendor/`, `*.min.js`) aren't searched for keys.
- Profile: monorepo workspaces (`packages/*`, `apps/*`…) are read; a native shell around a web app (Capacitor, a
  few Swift files) no longer makes it a mobile app; `setup.cfg`/`setup.py` console scripts are read; server-rendered
  pages (Thymeleaf, Jinja, Django, Rails…) make a web app; docs-publishing workflows aren't deployments; a deep
  package path like `org/x/samples/` isn't an examples folder.
- Hotspots: generated files (`*.gen.ts`, `_pb2.py`, `generated/`…) don't count; a `--shallow-since` clone that covers
  the window isn't reported as partial.

## 0.18.0 · 2026-11-25

Assessment: findings ranked for the project they're in, and for where change happens.

### Added
- **Project profile** (`codefactory profile`, and section 2 of the review): kind (mobile app, web app, web service,
  desktop, front-end, command-line tool, data pipeline, library), where it runs (local-first, client app, local, LAN,
  network or deployed server, user's machine), users (single user, multi-user, no sign-in) and sensitive data
  (health and fitness, financial, location, contact details, photos and camera, accounts and passwords), each with
  evidence. Reads npm, Python, Cargo, Go, Maven, Gradle, RubyGems, Composer, .NET and Flutter manifests. `[profile]` in
  factory.toml corrects it.
- **Findings ranked for the profile**, each change shown with the default severity and the reason: an untested write
  is High when the phone holds the only copy of the data; SQL built from strings is Low in a single-user offline app;
  personal data in logs is High in an app with health or financial data; plain HTTP is Medium in a mobile app; open
  write endpoints are High when the repository deploys a server.
- **Hotspots** (`codefactory hotspots`, and section 4 of the review): from 12 months of git history, complex code
  changed often, files that change together without importing each other (with a note when it's a front-end/back-end
  contract), and busy code only one person changes. Findings in hotspots come first in their severity and say so;
  long and untested functions are ordered by how often their file changes; `plan` scores tasks in busy files up to
  twice as high.
- The dashboard shows each repository's profile; open questions follow it; the AI evidence pack checks it first.

### Changed
- Review sections are renumbered: profile (2) and where change happens (4) are new.

## 0.17.2 · 2026-11-25

### Fixed
- `diff` read none of the base commit's config files (app.json, Info.plist, Dockerfiles, entitlements, lockfiles),
  because the base is unpacked inside `.codefactory/` and those checks skipped any path through that folder. Findings
  on both sides showed as new on every pull request, and declared iOS permissions showed as fixed. Found on a real
  pull request, where four "fixed" permission findings had never been there.

## 0.17.1 · 2026-11-24

### Changed
- Releases can publish to PyPI as **`codefactory-cli`** (`codefactory` on PyPI is an unrelated project). The command
  and the import are still `codefactory`, and installs from git are unchanged.

## 0.17.0 · 2026-11-24

Supply chain.

### Added
- **`codefactory sbom`:** a deterministic CycloneDX 1.5 SBOM of every pinned dependency, with package URLs, the
  lockfile each came from, and development-only dependencies marked optional.
- **Signed, reproducible releases:** a tag builds the wheel and sdist byte-for-byte reproducibly, attests build
  provenance and the SBOM (Sigstore, verifiable with `gh attestation verify`), publishes `SHA256SUMS`, moves the
  `v0` tag for the Action, and can publish to PyPI by trusted publishing. Every action in it is pinned to a commit.
- Rails N+1 through associations: `user.posts.count` in a loop, when a model declares `has_many :posts`.
- [SECURITY.md](SECURITY.md): reporting, what codefactory does and doesn't do with your code, verifying a release.
- Tests that the same code gives byte-identical graph, review and SARIF output.

### Fixed
- Folders in `factory.toml`'s `ignore` (test fixtures, vendored code) were still read by the Dockerfile, workflow,
  entitlement and git-history checks; they're now left out everywhere, as the analyzers already did.

### Changed
- The Action pins `actions/setup-python` to a commit.
- Package metadata uses an SPDX license expression (setuptools 77+).

## 0.16.0 · 2026-11-24

Measured accuracy.

### Added
- **Accuracy benchmark:** a labeled corpus (Python, TypeScript, JavaScript, Go, Java, Kotlin, Swift, Ruby, CI and
  Docker files) with real problems and look-alikes, a harness reporting precision and recall per check
  (`python -m tests.bench`), and a CI gate that fails on any new false alarm or miss. Results in
  [docs/ACCURACY.md](docs/ACCURACY.md): 91% precision and 84% recall on held-out code before tuning.
- SQL built from strings in Java (`executeQuery`, `prepareStatement`, `createQuery`), Go (`Query`/`Exec`, including
  `fmt.Sprintf` with `%s`), Ruby (`#{}` in `execute`, `where`, `find_by_sql`) and Kotlin/PHP/Dart (`$name`).
  Numbers joined into SQL (`"… id = " + id` where `id` is an `int`) don't count.
- Shell commands built from input in Ruby (`system("… #{}")`, backticks) and JavaScript (`exec("…" + x)`).
- Weak hashes in Go (`md5.Sum`), Swift (`Insecure.MD5`) and Ruby (`Digest::MD5`); a password or token named by the
  enclosing function counts as context (`def new_reset_token(): … random.choice(…)`).
- Go's `http.Get`/`Post` (the default client never times out); broad multi-line `except: pass` in Python.
- Rails N+1: `Model.find`/`where` inside a loop.

### Fixed
- Dockerfile findings pointed one line early after a blank line.
- `exec()` in JavaScript was reported as code execution; it's `child_process`, so it's a shell command now.
- A fixed `os.system("clear")` is no longer shell injection.
- Swift `\(value)` and Kotlin `$value` in log calls are now seen as values.
- Credentials assigned to names like `SLACK_TOKEN` or `stripeApiKey` were missed (the keyword had to start a word);
  values without a digit (`token_type = 'content-transfer-encoding'`) no longer count.
- `http://` URLs in doc comments (examples, not connections) are no longer reported: 133 of 411 such findings on
  real code.
- `size = int(request.args["size"])` and `",".join("?" * n)` placeholders are recognized as safe in SQL.

## 0.15.0 · 2026-11-24

Apple platforms and typed calls.

### Added
- **Apple platform checks (Swift):** disk or database work on the main thread (`viewDidLoad`, layout, SwiftUI
  `body`), retain cycles in closures `self` keeps, `try!`/`as!`, and entitlements that turn off code-signing
  protections. In the review, SARIF and `diff`.
- **Declared-type call resolution** for the tree-sitter languages (Kotlin, Java, Swift, C#, Go, Rust, PHP, Ruby…):
  `repo.find()` goes to `OrderRepo.find` when `repo` is declared an `OrderRepo`, instead of being ambiguous.

### Fixed
- Java, Ruby and PHP method calls lost their receiver, so `DB.query()` read as `query()`.
- Overloaded methods (same name, several definitions) no longer stop a typed call from resolving.
- `cache`, `store` and `collection` alone no longer mark a call as I/O (in-memory maps and Java collections).

## 0.14.0 · 2026-11-24

Data flow and privacy.

### Added
- **Data flow (taint) for Python:** request values traced through variables and helper functions into SQL, shell
  commands, code execution, file paths, outgoing URLs, redirects and templates. Sanitizers, typed parameters, bound SQL
  parameters, dependencies and database results are respected. Each finding shows the chain from the route to the
  call. Critical for SQL, shell and code. 3.7 seconds on 1.7 million lines.
- **Privacy:** personal data in logs, sent to analytics or crash reporting, or stored unencrypted; iOS permissions
  used without a usage description; required-reason APIs without a privacy manifest. On a real Expo app it found the
  watch extension's `UserDefaults` use without a manifest, which App Store Connect would flag.
- Both in the review, SARIF and `diff`.

## 0.13.0 · 2026-11-24

Pull requests and organisations.

### Added
- **`codefactory diff`:** the findings a change adds and fixes, compared with the base branch's merge-base.
  Output: a pull-request comment, GitHub annotations or JSON, and `--fail-on` for CI. Findings are matched by
  identity, so moved code isn't new. On a real pull request (four swallowed errors fixed) it reported exactly
  those four as fixed and nothing new.
- **A GitHub Action** (`uses: dominickkubica/codefactory@main`) that keeps one comment per pull request up to date.
- **Owners from CODEOWNERS** on every finding: JSON, SARIF, plan tasks, the PR comment, and a "By owner" table in the
  review.
- **Custom rules** (`[[rule]]` in factory.toml: a regular expression, files, severity, message) and **shared policy**
  (`extends`).
- **`codefactory org`:** a dashboard across many repositories with health, findings, trends and findings per owner.
- **`accept` records who and when.**

### Fixed
- Checks for `eval`, `exec` and shell strings run only in languages where those are built-ins (Go's own `eval()`
  functions were reported as dynamic code execution).
- In test files, only real credential formats count as leaked secrets (AWS, GitHub, Slack, Stripe, Google), not
  fixture keys such as an example's private key.

## 0.12.0 · 2026-11-24

The rest of a security audit.

### Added
- **Configuration and crypto checks:** debug mode in code, CORS `*`, insecure session cookies, signing keys in the
  code, JWT verification off, ECB/DES/RC4, MD5/SHA-1 for passwords or signatures, predictable random numbers for
  secrets, and tokens in unencrypted mobile/browser storage. The last three only next to a security-sensitive name.
- **CI, containers and mobile config:** `pull_request_target` workflows that run a fork's code with secrets, PR or
  issue text pasted into shell scripts, unpinned third-party actions, containers running as root, unpinned base
  images, secrets in images, and apps allowing plain HTTP.
- **Secrets in git history:** committed once and deleted later, so still leaked; with the commit to look at.
- **Known-vulnerable dependencies** (`review --online`): every pinned version in the lockfiles of npm, yarn, pnpm,
  poetry, uv, Pipfile, requirements and constraints files, Cargo, Go, Bundler and Composer, checked against OSV.dev.
  Grouped by package with the fixed version, dev-only packages marked and ranked lower. Only package names and
  versions are sent. On real apps it found a critical `certifi` (compromised CA certificates) in a FastAPI app's
  constraints, and 21 vulnerabilities in 7 packages of a React Native app (6 of them dev-only).
- **The AI evidence pack** (`--for-ai`) includes the attack surface: every endpoint, its auth check and where it
  changes data, with instructions to check authorization per record and input validation.
- SARIF rules for every new check.

### Fixed
- Whole-file pre-checks for line patterns anchored at `^` only looked at the first line.

## 0.11.0 · 2026-11-24

Closer to a security audit.

### Added
- **The attack surface** (`codefactory surface`, and a line in the review's summary): every HTTP endpoint with its
  method, path, framework and auth check. Recognised: FastAPI, Flask, Django/DRF, Express-style routers, Next.js,
  Spring, Go, Rails and Sinatra. Also: whether each changes data or reaches risky code, and whether the server
  listens only locally, can be opened, or listens everywhere.
- **Endpoints that change data without an auth check:** a review finding, with the function where each change happens.
  Its severity depends on whether other endpoints check (an inconsistency is likely a bug) and where the server
  listens. On a real FastAPI app: 34 endpoints, 15 of them change data (including a file upload and deletes), none
  check auth, and it listens locally but has a LAN mode, so Medium.
- **Risky lines ranked by reachability:** SQL built from strings, shell commands, `eval` and raw HTML go one level up,
  with the chain (`← reached from GET /search → search → find`), when a request reaches them, and one level down when
  none does.

### Changed
- The Python analyzer labels the SQL verb of `execute("INSERT …")`/`UPDATE`/`DELETE` like it did `SELECT`, and reads
  it from triple-quoted SQL that starts on a new line.

## 0.10.1 · 2026-11-24

### Fixed (checked on real code: Apache commons-lang, OkHttp, Rack, Go's standard library)
- **Kotlin, Scala, Ruby and PHP members are public unless marked otherwise**, so a Kotlin top-level `fun` with no
  modifier is API, not dead code. Dart names without `_` are public too.
- **Overrides** (`override fun`, `@Override`) are called through the type they override and are never "unused".
- **A property getter** (`get() = …`) is part of its property, not an unnamed function.
- **Imports that name a function** (`import okhttp3.internal.isHealthy`, Java static imports) link to the file that
  defines it.
- **A function called by a name many things define** (per-platform `lock()` in Go, `isHealthy` on several types)
  counts as possibly called, as methods already did. On Go's standard library this removed 1,450 false "unused".
- **Overloads** (`indexOf(int[])`, `indexOf(long[])`…) aren't copies of each other. This removed most of the 459
  "near-duplicates" on commons-lang; the rest are real (deprecated aliases that copy their replacement).
- **Loops between classes in Java, Kotlin, C#, Swift, Scala and Dart are warn ("dependency loops")**, not high.
  Classes load lazily there, so a loop is a design smell, not a loading failure as in Python or JavaScript.
- **Transactions are followed up the whole call chain**: a function counts as inside one when every caller calls it
  in a transaction or itself always runs in one (route → service → repository).

## 0.10.0 · 2026-11-24

### Added
- **MIT license.**
- **`codefactory accept`:** marks a finding as intended, with the reason, by writing a `[[silence]]` rule to
  `factory.toml`. It takes either a kind and a place (`accept sql_built src/db/x.ts --why "…"`) or a plan task, which
  covers every finding behind it. The review's own checks now honour these rules too.
- **Measured coverage:** when the repository has a coverage report (lcov, Istanbul `coverage-final.json`,
  coverage.py `coverage.json`), "no test reaches it" comes from what actually ran, and the review names the report.
  The call-graph estimate it replaces matched Jest's report for 97.6% of functions on a 500-file app.

### Changed
- **Ordinary commands never change the repository.** They used to rewrite an outdated
  `.claude/skills/codefactory/SKILL.md`, which left clean checkouts and CI runs dirty. Now they print a note, and the
  session hook, `codefactory skill` and `codefactory update` refresh it.
- **Array searches inside loops** are reviewed only in functions that load data from storage or the network, where
  the lists can grow. A search over a handful of UI items or a fixed table isn't worth a line in a review. On a React
  Native app this went from 53 to 2.

## 0.9.4 · 2026-11-24

### Fixed (clean-slate runs on a React Native app and a FastAPI app)
- **Transactions opened by the caller count:** a function every call of which happens inside a transaction (`with
  db.session(): insert_items(…)`, `transaction(db, () => insertItems(…))`) has its writes treated as batched. On the
  React Native app, "writes inside loops" went from 4 to 1, and the one left is real.
- **Calling the transaction helper once per batch** (`for (…) await transaction(db, …)`) is the batching, not a
  write in a loop.

## 0.9.3 · 2026-11-24

### Fixed (a second pass over the same FastAPI + React app)
- **Calls in loops are classified by what they do**, and the review reports each kind separately:
  - "Writes inside loops" no longer includes file operations, program runs, or loops over fixed lists and
    migrations (which said "fine as is").
  - File copies, moves and deletes (`shutil.copy2`, `rename`, `unlink`…) count as file operations, not database
    writes.
  - `subprocess.run()` per item counts as a program run.
  - `time.sleep()` in a loop is pacing on purpose and isn't reported.
- **Reads hidden behind `execute`:** an f-string starting with `SELECT` marks a read. When the SQL can't be seen, a
  function on the way named like a read (`read_*`, `get_*`, `load_*`…) makes it one, so these are no longer filed as
  writes.
- **A function named `migrate*` counts as a migration**, wherever it lives.
- **`getattr(obj, "name")` and `hasattr` with a literal name use that name**, so a method only reached that way isn't
  reported as unused.

## 0.9.2 · 2026-11-24

What a review of a 55,000-line FastAPI + React app showed could be better.

### Changed
- **Writes inside a transaction aren't reported**: loops in `with db.session():`, `with transaction.atomic():`,
  `with conn:` (Python) or in a callback given to `transaction(…)` / `withTransactionAsync(…)` (TypeScript) are
  batched already. On a React Native app this took "writes inside loops" from 28 to 7.
- **Copy sizes count code, not docstrings**: three functions with long docstrings and a 3-line shared body were
  "~29 lines" of copies; now ~12.
- **Copies kept apart on purpose** (same file, different names, each used or public) get "share one body between
  them" advice instead of "replace it with an import of the other".
- **Long functions are ranked by decision points**, not length alone, and the count is shown: a 750-line table of
  options no longer outranks a 90-line parser full of conditions.
- **Batch suggestions use the code's naming style**: `get_order_batch(ids)` and a dict in Python, `getOrderMany(ids)`
  and a Map in TypeScript.
- **Top-level files of a package split into zones** are placed by how they're used: imported by the zones
  ("pkg shared": config, logging) or importing them ("pkg app": the CLI). One mixed zone used to look like a layer
  against the dependency order.
- **Hidden folders** (`.claude`, `.github`…) are tooling, not product code, and aren't analyzed.
- **Data stores from Python manifests**: dependencies in `pyproject.toml` and `requirements.txt` are read, and DuckDB,
  Parquet, SQLAlchemy, MySQL, Elasticsearch and S3 are recognised.

### Added
- **Snapshot tests** of every finding on the three fixture apps (`tests/golden/`): any change in what codefactory
  reports fails CI until it's reviewed (`CODEFACTORY_UPDATE_GOLDEN=1`).

## 0.9.1 · 2026-11-24

### Fixed (found reviewing a 55,000-line FastAPI + React app)
- **Python imports inside a function now apply to that function only.** Two functions importing different
  `summarize`s both linked to the last one, so the other looked unused and the loops calling it were missed.
- "Network calls without a timeout" looks for `fetch()` only in JavaScript/TypeScript, where it's the web's fetch; in
  Python a variable named `fetch` is anything.

## 0.9.0 · 2026-11-24

Big codebases and many languages.

### Added
- **Every other language through tree-sitter** (optional: `pip install "codefactory[languages]"`): Go, Java, Kotlin,
  Swift, Rust, C/C++, C#, Ruby, PHP, Scala, Dart, Lua, Elixir and more get the map, copies, calls and I/O in loops,
  sizes and unused-code hints. Calls are matched by name, and the review says so. Without TypeScript installed,
  TypeScript/JavaScript falls back to it instead of being skipped. The review's text checks (credentials, empty
  catches, SQL built from strings, plain HTTP) now read these languages too.
- **Parallel, incremental analysis:** files are parsed on every core (`CODEFACTORY_JOBS`) and cached one by one, so a
  repeat run re-reads only what changed. On 1.7 million lines of Python: 287 s to 48 s for a first run, 21 s after
  changing a file, 5 s when nothing changed; memory 3.2 GB to 1.2 GB.
- `--lang other` limits the analysis to the tree-sitter languages.

### Changed
- Near-duplicate signatures use one-permutation MinHash (64 times cheaper), are cached, and pre-screen candidates.
  The same pairs as before on a React Native app, and 0.2% more on 1.7 million lines.
- Copies between per-platform versions of a file (`x_linux.go` / `x_darwin.go`) aren't duplicates.
- Test files are recognised in more languages (`x_test.go`, `x_spec.rb`, `FooTest.java`).

### Fixed
- The review re-checked every function for each copy (quadratic): 31% of a review's time on large codebases.
- Silencing comments were re-read for every finding in a file.
- Minified JavaScript (`*.min.js`) is skipped, and function ids are unique whatever an analyzer produces.

## 0.8.1 · 2026-11-24

### Fixed (review false positives found on a real React Native app)
- **Swallowed errors:** an empty catch isn't reported when a comment says why, when it's best-effort cleanup of a
  leftover (cancelling a notification, deleting a stored item, file or cache; never the user's records), or when the
  failure becomes a fallback value (`const x = await load().catch(() => null)`). The review's limits section counts
  them. On that app: 16 reported before, 5 after, all 5 real.
- **SQL built from strings:** names that come from a fixed list or are checked against one in the lines above
  (`for (const t of Object.keys(TABLES))`, `known.has(t)`, `.filter((c) => allowed.has(c))`) and numeric expressions
  (`version + 1`, `Math.floor(v)`) are safe. Only the template literal itself is read, and `{name}` counts as
  interpolation only in Python strings.
- **Module-level state** in a UI app (React, React Native, Expo, Vue, Svelte) is reported only when exported mutable;
  per-app singletons are normal there.
- **Copied logic** in the review lists only identical or ≥85% similar groups with no test among them; lower scores are
  usually deliberate variants.
- **CI not on push** isn't reported when the workflow explains in a comment why it runs on pull requests only.
- `http://*` (an origin wildcard) isn't a plain-HTTP URL.
- A source file containing a lone surrogate character (e.g. `"\ud83d"` in a string) no longer stops the analysis.
- The skill refresh rewrites `SKILL.md` only when its instructions changed, not for a new version number alone, so
  upgrades don't leave a one-line diff in every repository.

## 0.8.0 · 2026-11-24

Staying current in Claude Code.

### Added
- **The skill keeps itself current.** `SKILL.md` records the version that wrote it; any codefactory command run in a
  repository with an older skill rewrites it, so Claude never follows instructions for commands that changed.
- `codefactory update`: upgrades codefactory from GitHub (or `--source`) and refreshes the repository's skill.
- `codefactory skill --hook`: adds a Claude Code session-start hook (`.claude/hooks/codefactory.sh`, registered in
  `.claude/settings.json` alongside existing settings) that installs codefactory if missing, upgrades it at most once
  a day, and refreshes the skill. It never blocks or fails a session.

## 0.7.0 · 2026-11-24

Hardening and documentation for a first wider release.

### Added
- **Dispatch tables** are followed in both languages: `COMMANDS[name][0](args)` and `HANDLERS[key]()` link to every
  function in the table, so command and handler tables no longer look unused or untested.
- **Friendlier errors:** problems a user can fix (an invalid `factory.toml`, a bad layer rule, a missing folder,
  TypeScript not installed) end with a one-line message; unexpected errors say how to get the full traceback.
  New global `--debug` flag (or `CODEFACTORY_DEBUG=1`).
- `codefactory --help` shows examples.
- Documentation: a rewritten README with screenshots, a [usage guide](docs/USAGE.md), a [design document](docs/DESIGN.md),
  and a contributor guide.
- Lint and format checks (ruff) in CI.

### Changed
- **Import loops count only imports that run at load time.** Imports inside functions and under `TYPE_CHECKING`
  (often placed there to break a loop), and `require()` inside functions, no longer create loops. On pip's source
  this removed a false 67-file loop.
- **Zones:** when one inferred zone holds most of the code (`pkg/_internal/…`), it's split by the next folder level.
- A search in a list written out in the code (`["a", "b"].includes(x)`) is no longer reported as O(n²).
- The viewer zooms to a traced function's reach (or centres on the function when its reach is too spread out), and
  the side panel opens at the top after each selection.
- One shared definition of "test file" and "script" across all checks.

### Fixed
- Two dead helpers and a duplicated function in codefactory itself, found by running its own review.

## 0.6.1 · 2026-11-24

### Fixed (false positives found using it on a real React Native app)
- Calls in loops over a list fixed in the code (literals, constants, `Object.entries(CONST)`, destructured constant
  pieces, `range(N)`, `.slice(0, N)`) and in migrations are info, not warn; searches and awaits in them aren't reported.
- Methods frameworks call by name (React lifecycle, web components, Angular, Django/DRF) are never unused.
- Lazy `require()` / `import()` is followed, including the `as`-cast destructuring form.

## 0.6.0 · 2026-11-23

### Added
- `codefactory sarif`: SARIF 2.1.0 for GitHub code scanning and VS Code, with rules, security severities, related
  locations, stable fingerprints, suppressions and baseline state.
- `--github` on `flags` and `check`: GitHub Actions annotations on pull requests, without code scanning.

## 0.5.0 · 2026-11-23

### Added
- `codefactory review`: a technical review report (summary, health grade, system map, findings by severity, what's
  working, gaps, questions, limits) with security, reliability, testing and delivery checks.
- `--for-ai`: an evidence pack with the riskiest functions' code, for an AI to finish the judgement calls.

## 0.4.0 · 2026-11-23

### Added
- `codefactory plan` and `prompt`: ranked tasks with steps, tests and a ready-to-paste prompt each; **Copy fix
  prompt** in the viewer.
- Silencing by comment (`codefactory: ignore <kind> — why`) or `[[silence]]` in `factory.toml`.
- `codefactory baseline` and `check`: fail CI only on new issues.

### Fixed
- Same-shaped functions with different SQL or messages are no longer reported as duplicates.

## 0.3.0 · 2026-11-23

### Added
- Calls in loops (N+1), near-duplicates (MinHash), searches and awaits in loops.
- Lenses in the viewer: duplication, efficiency, size.
- `brief`, `context`, `--json`, the Claude Code skill installer, and the analysis cache.

## 0.2.0 · 2026-11-23

### Added
- The TypeScript/JavaScript analyzer, using the project's own TypeScript compiler.
- The readable zoom-out: halls with summary cards and one conveyor per pair of halls.

## 0.1.0 · 2026-11-23

First version: the Python analyzer, issue flags (import loops, layer rules, duplicates, unused code, hubs, sizes),
the factory-floor viewer, SQL export and queries, `trace` and `path`.
