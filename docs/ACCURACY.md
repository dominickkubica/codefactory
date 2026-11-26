# Accuracy

How often codefactory is right, measured rather than claimed. Two sources: a labeled benchmark that runs in CI, and
spot checks on real repositories.

## The benchmark

`tests/fixtures/bench` is a corpus of small but realistic files in Python, TypeScript, JavaScript, Go, Java,
Kotlin, Swift and Ruby, plus a GitHub workflow, Dockerfiles and an entitlements file. `expect.txt` labels every line
where a real problem is (what *should* be reported, whether or not codefactory reports it) and the look-alikes
placed next to them: `hashlib.md5()` for an ETag beside one for a password, `os.system("clear")` beside a shell
command built from input, a parameterized query beside an interpolated one, `[weak self]` beside a strong capture.

A finding counts as correct only when the file, the line and the check all match a label. Anything else reported is
a false alarm, labeled look-alike or not. Run it with:

    python -m tests.bench            # the tables, plus each miss and false alarm
    python -m tests.bench --write    # also refresh the tables below

`tests/test_bench.py` runs it in CI and fails on any new false alarm or miss, or if precision or recall drops below
the floors in `floors.json`.

### Two parts, and why

The corpus has a **tuning** part, which the checks were fixed against, and a **held-out** part, written afterwards
in different idioms (Django, plain Node, `fmt.Sprintf`, Kotlin string templates, Swift interpolation, Rails
`where`) and measured once before any change. Numbers on a set you've tuned against flatter you; the held-out
first measurement is the honest estimate of how codefactory does on code it hasn't seen.

| | Precision | Recall |
|---|--:|--:|
| Tuning part, first measurement | 97% | 89% |
| Held-out part, first measurement (untuned) | **91%** | **84%** |
| Both, after fixing what the held-out part found | 100% | 100% |

The held-out run found six real defects, since fixed: Dockerfile findings pointed one line early when a blank line
came before `FROM`; JavaScript's `exec()` from `child_process` was reported as code execution instead of a shell
command; a constant `os.system("clear")` was reported as shell injection; Swift's `\(value)` and Kotlin's `$value`
interpolation weren't seen as values in log calls and SQL; Rails `where("… #{…}")` wasn't checked as SQL.

The last miss was a Rails association counted per row (`users.map { |u| u.posts.count }`), an N+1 that needs the
model definitions to see. codefactory now reads `has_many` declarations; the held-out part gained the model file it
would have in a real app (`models/user.rb`), and a look-alike (`u.items.count` on an attribute that isn't an
association) that must stay quiet.

### Tuning part

<!-- bench:tuning:start -->
| Check | Found | Missed | False alarms | Look-alikes | Precision | Recall |
|---|--:|--:|--:|--:|--:|--:|
| `cors_any` | 3 | 0 | 0 | 1 | 100% | 100% |
| `debug_on` | 1 | 0 | 0 | 1 | 100% | 100% |
| `docker_latest` | 1 | 0 | 0 | 0 | 100% | 100% |
| `docker_root` | 1 | 0 | 0 | 0 | 100% | 100% |
| `docker_secret` | 1 | 0 | 0 | 0 | 100% | 100% |
| `entitlement_weakened` | 1 | 0 | 0 | 1 | 100% | 100% |
| `eval` | 6 | 0 | 0 | 3 | 100% | 100% |
| `fetch_no_timeout` | 3 | 0 | 0 | 2 | 100% | 100% |
| `gha_injection` | 1 | 0 | 0 | 2 | 100% | 100% |
| `gha_pr_target` | 1 | 0 | 0 | 0 | 100% | 100% |
| `gha_unpinned` | 1 | 0 | 0 | 2 | 100% | 100% |
| `insecure_cookie` | 2 | 0 | 0 | 3 | 100% | 100% |
| `io_in_loop` | 6 | 0 | 0 | 3 | 100% | 100% |
| `ios_privacy_manifest` | 1 | 0 | 0 | 0 | 100% | 100% |
| `jwt_unverified` | 2 | 0 | 0 | 1 | 100% | 100% |
| `main_thread_io` | 1 | 0 | 0 | 1 | 100% | 100% |
| `plain_http` | 6 | 0 | 0 | 4 | 100% | 100% |
| `privacy_analytics` | 1 | 0 | 0 | 1 | 100% | 100% |
| `privacy_log` | 3 | 0 | 0 | 4 | 100% | 100% |
| `privacy_storage` | 2 | 0 | 0 | 2 | 100% | 100% |
| `quadratic_scan` | 1 | 0 | 0 | 1 | 100% | 100% |
| `raw_html` | 2 | 0 | 0 | 2 | 100% | 100% |
| `secret` | 3 | 0 | 0 | 2 | 100% | 100% |
| `secret_key_literal` | 1 | 0 | 0 | 1 | 100% | 100% |
| `sensitive_storage` | 1 | 0 | 0 | 1 | 100% | 100% |
| `shell` | 4 | 0 | 0 | 4 | 100% | 100% |
| `sql_built` | 5 | 0 | 0 | 7 | 100% | 100% |
| `swallowed` | 5 | 0 | 0 | 2 | 100% | 100% |
| `swift_force` | 2 | 0 | 0 | 1 | 100% | 100% |
| `swift_retain_cycle` | 1 | 0 | 0 | 2 | 100% | 100% |
| `taint` | 5 | 0 | 0 | 3 | 100% | 100% |
| `tls_off` | 2 | 0 | 0 | 1 | 100% | 100% |
| `weak_cipher` | 1 | 0 | 0 | 1 | 100% | 100% |
| `weak_hash` | 4 | 0 | 0 | 3 | 100% | 100% |
| `weak_random` | 2 | 0 | 0 | 2 | 100% | 100% |
| **All** | **83** | **0** | **0** | **64** | **100%** | **100%** |
<!-- bench:tuning:end -->

### Held-out part

<!-- bench:holdout:start -->
| Check | Found | Missed | False alarms | Look-alikes | Precision | Recall |
|---|--:|--:|--:|--:|--:|--:|
| `cors_any` | 1 | 0 | 0 | 0 | 100% | 100% |
| `debug_on` | 1 | 0 | 0 | 0 | 100% | 100% |
| `docker_latest` | 1 | 0 | 0 | 1 | 100% | 100% |
| `docker_root` | 0 | 0 | 0 | 1 | – | – |
| `fetch_no_timeout` | 2 | 0 | 0 | 1 | 100% | 100% |
| `insecure_cookie` | 1 | 0 | 0 | 0 | 100% | 100% |
| `io_in_loop` | 6 | 0 | 0 | 1 | 100% | 100% |
| `main_thread_io` | 1 | 0 | 0 | 0 | 100% | 100% |
| `plain_http` | 1 | 0 | 0 | 0 | 100% | 100% |
| `privacy_log` | 3 | 0 | 0 | 2 | 100% | 100% |
| `secret` | 1 | 0 | 0 | 0 | 100% | 100% |
| `shell` | 3 | 0 | 0 | 1 | 100% | 100% |
| `sql_built` | 5 | 0 | 0 | 4 | 100% | 100% |
| `swallowed` | 2 | 0 | 0 | 2 | 100% | 100% |
| `swift_force` | 1 | 0 | 0 | 1 | 100% | 100% |
| `swift_retain_cycle` | 1 | 0 | 0 | 1 | 100% | 100% |
| `taint` | 1 | 0 | 0 | 0 | 100% | 100% |
| `weak_hash` | 5 | 0 | 0 | 1 | 100% | 100% |
| `weak_random` | 2 | 0 | 0 | 2 | 100% | 100% |
| **All** | **38** | **0** | **0** | **18** | **100%** | **100%** |
<!-- bench:holdout:end -->

### What it doesn't cover

- Repository-level checks (missing CI, lockfiles, README, runtime pins), dependency vulnerabilities (they come from
  OSV), git history secrets and the structural findings (duplicates, unused code, import loops, layer rules) aren't
  in the corpus; their behavior is covered by unit tests and the golden snapshots in `tests/golden`.
- A corpus is small next to real code. Each label is one idiom; real code has more. Treat the numbers as "the
  idioms listed are handled", and the spot checks below as the evidence for real code.

## Spot checks on real code

Every check was run on real repositories and its findings read by hand; each false positive found became a fix and a
test. Repositories: a 60k-line Expo/TypeScript app with a Swift watch extension, a Python/FastAPI trading tool,
Apache Commons Lang (Java), a Kotlin library, a PHP framework, a Ruby gem, Go's standard library and 1.7 million
lines of installed Python packages.

| Finding | Before | After | What changed |
|---|---|---|---|
| Data flow (Python) | flows from typed parameters (`shot_id: int`), database results and `sys.argv` | none of those | typed parameters, database results and command-line input aren't sources of untrusted text |
| Privacy | "phone" in "On your phone, open the app"; generic words (`steps`, `sleep`, `location`) | — | only interpolated values count; generic words dropped |
| Code execution | Go functions named `eval`, Java methods named `exec` | — | built-ins checked only in languages that have them |
| Secrets | PEM keys in Go's test data | — | in tests only real vendor key formats count |
| Swallowed errors (Python) | — | 129 broad `except Exception: pass` / bare `except: pass` across 1.7M lines | multi-line form added, broad catches only: `except KeyError: pass` is deliberate and stays quiet |
| Plaintext URLs | 411 on the real repositories, 133 of them examples in doc comments | 278 | comment lines skipped |
| Secrets | `token_type = 'content-transfer-encoding'`, a Go string table; `SLACK_TOKEN = "…"` missed | caught, without those | a keyword may end a name; a credential has a digit |
| Calls (Java, Kotlin, Swift) | `repo.find()` ambiguous between classes | resolved by the declared type | declared-type resolution |

## Public repositories

Seven public projects with a known answer were assessed with 0.18 (profile, hotspots and the full review), and every
wrong result was traced to its cause and fixed with a regression test (`tests/test_public_repos.py`):

| Repository | Profile after fixes | What it caught in codefactory |
|---|---|---|
| fastapi/full-stack-fastapi-template | web app, deployed, multi-user, contact details and passwords | a typed `uuid.UUID` parameter and an ORM `session.delete()` reported as a dangerous data flow; a checkout `ref:` reported as shell injection in CI; a generated API client as the top hotspot |
| spring-projects/spring-petclinic | web app, deployed, no sign-in | Spring endpoints never found (tree-sitter starts a Java method at its annotation); a Java package named `samples` taken for an examples folder |
| httpie/cli | command-line tool | `@mock.patch(...)` in tests read as Flask routes, so a CLI looked like a web service; `setup.cfg` console scripts not read; a docs-deploy workflow taken as deploying the product |
| psf/requests | library | — |
| LoopKit/Loop | mobile app, local-first, health data | — (its one history finding, an API key committed and later removed, is real) |
| actualbudget/actual | web app (also desktop, CLI, mobile shell), deployed, multi-user, financial | manifests in `packages/*` not read; a native iOS shell taken as the main kind; the safe env-var pattern flagged as CI injection; a base-only `pull_request_target` checkout flagged as running fork code; a minified Yarn bundle as a leaked key; `on: pull_request_target` on one line missed entirely |
| gothinkster/golang-gin-realworld-example-app | web service, multi-user, passwords | — |

A second round covered other kinds of projects:

| Repository | Profile after fixes | What it caught in codefactory |
|---|---|---|
| maybe-finance/maybe (Rails) | web app, deployed, multi-user, financial, contact details, passwords | auth inherited from a base controller or added by an included concern (`include Authentication`) not seen, so 14 endpoints looked open; `skip_authentication only:` not understood; emails declared in `db/schema.rb` missed |
| healthchecks/healthchecks (Django) | web app, deployed, multi-user, passwords | each URL matched every function of that name in the project (932 "endpoints", now 147); five redirects reported as open redirects though each went to `reverse(...)` or was checked by `_allow_redirect()` first; sign-in and magic-link endpoints counted as unprotected writes; `mark_safe` of a settings value and a comment mentioning `mark_safe()` reported as raw HTML |
| android/nowinandroid (Kotlin) | mobile app, local-first | Room (from the Gradle version catalog and `@Database`) not recognised as on-device storage |
| pocketbase/pocketbase (Go) | web service, multi-user, passwords | a Go test file used as evidence of where the server listens; a comment describing a PEM block reported as a committed private key; a stored email ranked High only because the app also has passwords |
| gotify/server (Go + React) | web app, deployed, multi-user, passwords | files in one Go package reported as "changing together without importing each other" (a package needs no imports) |
| owid/etl (data pipeline) | data pipeline (also CLI, web service), user's machine | three FastAPI endpoints in an internal tool made it a "web service"; `xoxb-not-a-real-token` in a test reported as a Slack token |

A third round added frameworks and kinds not yet seen:

| Repository | Profile after fixes | What it caught in codefactory |
|---|---|---|
| shadcn-ui/taxonomy (Next.js) | web app, multi-user, financial, contact details, passwords | a handler checking access with `verifyCurrentUserHasAccessToPost()` and a Stripe webhook checking its signature counted as unprotected |
| monicahq/monica (Laravel) | web app, deployed, multi-user, contact details, financial | Laravel routes (and `middleware('auth')` groups) not found; contacts in migrations (`$table->string('first_name')`) missed; a `.env.docker` template with an empty key reported as committed secrets; SQL from one of two fixed fragments reported as injection; Laravel's model/factory pairs reported as import loops |
| dani-garcia/vaultwarden (Rust) | web app, deployed, multi-user, passwords | Rocket routes not found, and its `Headers` request guard not seen as auth; a Playwright harness's package.json taken as the product; `HashMap.insert` read as a database write (four "unprotected writes" that were caches) |
| dotnet/eShop (ASP.NET) | web service (also a mobile client), multi-user | minimal-API and controller routes not found, so its MAUI client was taken as the product |
| localsend/localsend (Flutter) | mobile app | "health data" from a generated translation file and an icon name; a format check (`starts_with("-----BEGIN PRIVATE KEY-----")`) reported as a key; Kotlin's `catch (_: Exception) {}` reported as swallowed; module cycles inside one Rust crate reported as import loops; generated bridge code as the top hotspots |
| marktext/marktext (Electron) | desktop app | translation files reported as coupled (they change together by design). Its one High finding, a shell command built from a file path, is real |
| Alamofire/Alamofire (Swift) | library | `Package.swift` not read, so its Example app made it a mobile app |
| plausible/analytics (Phoenix) | web app, deployed, multi-user, contact details, passwords | Phoenix routes not found; auth in controller plugs and `live_session` not seen |
| karpathy/nanoGPT | data pipeline | no manifest: unknown |

Of the review findings checked by hand on these repositories, the false ones were fixed (four security findings in
round 1; in round 2, every Critical and High one) and the rest held: Loop's key in history, the FastAPI template's
committed `.env`, PetClinic's unauthenticated write endpoints. The hotspots matched what the projects' histories show: Actual's transactions table (40 changes,
710 decision points), Loop's status view controller, requests' `models.py`.

Findings are leads with the exact line. The review ranks them, and anything intended can be marked in the code
(`codefactory: ignore <kind> — why`) or accepted with `codefactory accept`, with the reason kept.
