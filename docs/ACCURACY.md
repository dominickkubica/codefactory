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

Data flow for JavaScript and TypeScript (`codefactory/jstaint.py`) got its own held-out file, `holdout/js/flows.js`
(Fastify and Koa: shell, file paths, SQL, outgoing requests, redirects, `eval` and HTML in a reply, with a parsed
number, `path.basename`, an allow-list lookup, a fixed host, a local redirect and an argument list as look-alikes),
labeled before the analysis first ran on it. First measurement: 7 of 9 flows found, none of the 6 look-alikes
reported. The two misses were real defects, since fixed: `axios.get(url)` was taken for SQL (sqlite's `db.get`) and
dropped, and `reply.type("text/html").send(…)` wasn't seen as writing the response. The same file caught two older
checks out: a shell command built only from a `parseInt` value reported as injection, and `axios` calls without a
timeout not reported at all. Both fixed.

### Tuning part

<!-- bench:tuning:start -->
| Check | Found | Missed | False alarms | Look-alikes | Precision | Recall |
|---|--:|--:|--:|--:|--:|--:|
| `compose_exposed` | 1 | 0 | 0 | 2 | 100% | 100% |
| `compose_privileged` | 2 | 0 | 0 | 0 | 100% | 100% |
| `compose_secret` | 1 | 0 | 0 | 2 | 100% | 100% |
| `config_http` | 1 | 0 | 0 | 2 | 100% | 100% |
| `config_secret` | 3 | 0 | 0 | 3 | 100% | 100% |
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
| `go_server_timeout` | 1 | 0 | 0 | 0 | 100% | 100% |
| `html_mixed` | 3 | 0 | 0 | 3 | 100% | 100% |
| `html_no_sri` | 1 | 0 | 0 | 2 | 100% | 100% |
| `insecure_cookie` | 2 | 0 | 0 | 3 | 100% | 100% |
| `io_in_loop` | 6 | 0 | 0 | 3 | 100% | 100% |
| `ios_privacy_manifest` | 1 | 0 | 0 | 0 | 100% | 100% |
| `jwt_unverified` | 2 | 0 | 0 | 1 | 100% | 100% |
| `k8s_host` | 2 | 0 | 0 | 0 | 100% | 100% |
| `k8s_privileged` | 1 | 0 | 0 | 2 | 100% | 100% |
| `k8s_secret` | 1 | 0 | 0 | 1 | 100% | 100% |
| `main_thread_io` | 1 | 0 | 0 | 1 | 100% | 100% |
| `plain_http` | 6 | 0 | 0 | 4 | 100% | 100% |
| `privacy_analytics` | 1 | 0 | 0 | 1 | 100% | 100% |
| `privacy_log` | 3 | 0 | 0 | 4 | 100% | 100% |
| `privacy_storage` | 2 | 0 | 0 | 2 | 100% | 100% |
| `quadratic_scan` | 1 | 0 | 0 | 1 | 100% | 100% |
| `raw_html` | 2 | 0 | 0 | 2 | 100% | 100% |
| `secret` | 3 | 0 | 0 | 3 | 100% | 100% |
| `secret_key_literal` | 1 | 0 | 0 | 1 | 100% | 100% |
| `sensitive_storage` | 1 | 0 | 0 | 1 | 100% | 100% |
| `shell` | 5 | 0 | 0 | 5 | 100% | 100% |
| `shell_eval` | 1 | 0 | 0 | 1 | 100% | 100% |
| `shell_pipe` | 2 | 0 | 0 | 3 | 100% | 100% |
| `shell_rm_var` | 3 | 0 | 0 | 2 | 100% | 100% |
| `sql_built` | 5 | 0 | 0 | 7 | 100% | 100% |
| `swallowed` | 5 | 0 | 0 | 2 | 100% | 100% |
| `swift_force` | 2 | 0 | 0 | 1 | 100% | 100% |
| `swift_retain_cycle` | 1 | 0 | 0 | 2 | 100% | 100% |
| `taint` | 5 | 0 | 0 | 3 | 100% | 100% |
| `tls_off` | 3 | 0 | 0 | 1 | 100% | 100% |
| `weak_cipher` | 1 | 0 | 0 | 1 | 100% | 100% |
| `weak_hash` | 4 | 0 | 0 | 3 | 100% | 100% |
| `weak_random` | 3 | 0 | 0 | 3 | 100% | 100% |
| **All** | **109** | **0** | **0** | **90** | **100%** | **100%** |
<!-- bench:tuning:end -->

### Held-out part

<!-- bench:holdout:start -->
| Check | Found | Missed | False alarms | Look-alikes | Precision | Recall |
|---|--:|--:|--:|--:|--:|--:|
| `cors_any` | 1 | 0 | 0 | 0 | 100% | 100% |
| `debug_on` | 1 | 0 | 0 | 0 | 100% | 100% |
| `docker_latest` | 1 | 0 | 0 | 1 | 100% | 100% |
| `docker_root` | 0 | 0 | 0 | 1 | – | – |
| `eval` | 1 | 0 | 0 | 0 | 100% | 100% |
| `fetch_no_timeout` | 4 | 0 | 0 | 1 | 100% | 100% |
| `insecure_cookie` | 1 | 0 | 0 | 0 | 100% | 100% |
| `io_in_loop` | 6 | 0 | 0 | 1 | 100% | 100% |
| `main_thread_io` | 1 | 0 | 0 | 0 | 100% | 100% |
| `plain_http` | 1 | 0 | 0 | 0 | 100% | 100% |
| `privacy_log` | 3 | 0 | 0 | 2 | 100% | 100% |
| `secret` | 1 | 0 | 0 | 0 | 100% | 100% |
| `shell` | 5 | 0 | 0 | 3 | 100% | 100% |
| `sql_built` | 6 | 0 | 0 | 5 | 100% | 100% |
| `swallowed` | 2 | 0 | 0 | 2 | 100% | 100% |
| `swift_force` | 1 | 0 | 0 | 1 | 100% | 100% |
| `swift_retain_cycle` | 1 | 0 | 0 | 1 | 100% | 100% |
| `taint` | 10 | 0 | 0 | 6 | 100% | 100% |
| `weak_hash` | 5 | 0 | 0 | 1 | 100% | 100% |
| `weak_random` | 2 | 0 | 0 | 2 | 100% | 100% |
| **All** | **53** | **0** | **0** | **27** | **100%** | **100%** |
<!-- bench:holdout:end -->

### What it doesn't cover

- Repository-level checks (missing CI, lockfiles, README, runtime pins), dependency vulnerabilities (they come from
  OSV), git history secrets and the structural findings (duplicates, unused code, import loops, layer rules) aren't
  in the corpus; their behavior is covered by unit tests and the golden snapshots in `tests/golden`.
- A corpus is small next to real code. Each label is one idiom; real code has more. Treat the numbers as "the
  idioms listed are handled", and the spot checks below as the evidence for real code.

## Precision on real code

The benchmark says the idioms in it are handled; it can't say how often a finding is right on code nobody wrote for
it. This section can. Locations reported on the [corpus](CORPUS.md) are sampled per check (at most 25 per check and 3
per repository, the more serious first) and each one is labeled by reading the code, with the reason kept beside the
label in `tools/corpus/labels.json`. `python tools/precision.py score` re-reads the labels against what the current
code reports, so a change to a check shows at once which wrong findings it removed and which right ones it lost.
Checks whose claim is true by construction (a missing README, an unpinned version, a long function) aren't sampled.

<!-- precision:start -->
741 locations labeled across 69 repositories (round 1, the sample the fixes were made against). **First measurement: 321 right (43%). Now, counted findings only: 217 of the 251 still reported are right (86%)**: the fixes removed 179 wrong ones and lost 20 right ones. Checks marked *hint* are listed, not counted.

| Check | First measured | Now | 95% interval (now) | Still reported | Wrong removed | Right lost |
|---|--:|--:|--:|--:|--:|--:|
| Import loops (N) | 52% | 100% | 72%–100% | 10 | 12 | 3 |
| Container runs as root | 36% | 100% | 68%–100% | 8 | 16 | 1 |
| Raw HTML injected into pages *(hint)* | 40% | – |  | – | – | – |
| HTTP servers without timeouts (Go) *(hint)* | 71% | – |  | – | – | – |
| Possible retain cycles: closures kept by self that capture self strongly | 100% | 100% | 57%–100% | 5 | 0 | 0 |
| Important code no test reaches (N function) | 38% | 100% | 51%–100% | 4 | 15 | 5 |
| Required-reason API without a privacy manifest | 100% | 100% | 44%–100% | 3 | 0 | 0 |
| Predictable random numbers for secrets *(hint)* | 33% | – |  | – | – | – |
| Broken encryption mode or cipher (ECB, DES, RC4) | 100% | 100% | 21%–100% | 1 | 0 | 0 |
| No error boundary around the UI | 100% | 100% | 21%–100% | 1 | 0 | 0 |
| Personal data in unencrypted storage | 100% | 100% | 21%–100% | 1 | 0 | 0 |
| Unused code (N function) | 12% | 100% | 21%–100% | 1 | 22 | 2 |
| Network calls without a timeout | 80% | 95% | 76%–99% | 20 | 4 | 1 |
| Third-party scripts without integrity hashes | 76% | 93% | 69%–99% | 14 | 3 | 0 |
| MD5 / SHA-1 used for security | 64% | 90% | 60%–98% | 10 | 4 | 0 |
| TLS certificate checks turned off *(hint)* | 53% | – |  | – | – | – |
| Any website may call this API (CORS *) | 88% | 88% | 70%–96% | 25 | 0 | 0 |
| Module-level mutable state (N place) | 88% | 88% | 70%–96% | 25 | 0 | 0 |
| Dynamic code execution (eval / exec / pickle / unsafe YAML) | 56% | 88% | 64%–97% | 16 | 9 | 0 |
| Queries or requests inside loops (N) in N place | 44% | 88% | 53%–98% | 8 | 13 | 4 |
| Request data reaches dangerous calls (N proven flow) *(hint)* | 32% | – |  | – | – | – |
| Copied logic in N group (~N lines) | 60% | 87% | 62%–96% | 15 | 8 | 2 |
| App allows unencrypted HTTP | 67% | 86% | 49%–97% | 7 | 2 | 0 |
| Downloads piped straight into a shell | 71% | 83% | 44%–97% | 6 | 1 | 0 |
| Shell commands built at runtime | 72% | 82% | 61%–93% | 22 | 3 | 0 |
| Tokens or passwords in unencrypted storage | 80% | 80% | 38%–96% | 5 | 0 | 0 |
| SQL assembled from strings *(hint)* | 32% | – |  | – | – | – |
| Dependency loops (N) | 58% | 77% | 50%–92% | 13 | 5 | 1 |
| Personal data written to logs | 36% | 75% | 47%–91% | 12 | 13 | 0 |
| Session cookies without Secure / HttpOnly | 50% | 75% | 30%–95% | 4 | 2 | 0 |
| N error silently swallowed | 28% | 67% | 35%–88% | 9 | 15 | 1 |
| Credentials in configuration files *(hint)* | 40% | – |  | – | – | – |
| Shell `eval` of a variable | 40% | 67% | 21%–94% | 3 | 2 | 0 |
| Credentials committed in source *(hint)* | 9% | – |  | – | – | – |
| Privileged containers or the host's network (docker-compose) | 50% | 50% | 9%–91% | 2 | 0 | 0 |
| Environment files committed *(hint)* | 0% | – |  | – | – | – |
| Kubernetes Secrets committed with their values | 0% | 0% | 0%–79% | 1 | 1 | 0 |
| Array searches inside loops over loaded data (N) *(hint)* | 28% | – |  | – | – | – |
| Databases published on every interface (docker-compose) *(hint)* | 0% | – |  | – | – | – |
| Debug mode switched on in code *(hint)* | 0% | – |  | – | – | – |
| Endpoints that change data without an auth check (N) *(hint)* | 16% | – |  | – | – | – |
| File or program operations inside loops in N place *(hint)* | 76% | – |  | – | – | – |
| JWT checks turned off *(hint)* | 0% | – |  | – | – | – |
| Passwords for CI services written into workflows | 0% | – |  | 0 | 7 | 0 |
| Passwords written into docker-compose | 0% | – |  | 0 | 16 | 0 |
| Plain-HTTP URLs in code *(hint)* | 12% | – |  | – | – | – |
| Plain-HTTP URLs in configuration (Pkl, TOML, Terraform…) *(hint)* | 0% | – |  | – | – | – |
| Writes inside loops in N place *(hint)* | 24% | – |  | – | – | – |
| `rm -rf` on a variable that may be empty | 0% | – |  | 0 | 6 | 0 |
| `try!` / `as!` that crash on failure (Swift) *(hint)* | 0% | – |  | – | – | – |

**Held out (latest, round 7)**: 149 more locations of counted findings, sampled and labeled after the fixes before it, that no fix was made against: **95 right (64%, 95% interval 56%–71%)**. This is the number to expect on code codefactory hasn't been tuned on. Each held-out round, counted findings only, as measured then: round 2: 79/153 (52%); round 3: 77/132 (58%); round 4: 72/110 (65%); round 5: 68/96 (71%); round 6: 0/34 (0%); round 7: 106/225 (47%).

| Check | Held out | 95% interval | Labeled |
|---|--:|--:|--:|
| Dependency loops (N) | 100% | 68%–100% | 8 |
| Module-level mutable state (N place) | 100% | 68%–100% | 8 |
| Network calls without a timeout | 100% | 68%–100% | 8 |
| App allows unencrypted HTTP | 100% | 34%–100% | 2 |
| Personal data sent to analytics or crash reporting | 100% | 34%–100% | 2 |
| Downloads piped straight into a shell | 100% | 21%–100% | 1 |
| No error boundary around the UI | 100% | 21%–100% | 1 |
| Possible retain cycles: closures kept by self that capture self strongly | 100% | 21%–100% | 1 |
| Required-reason API without a privacy manifest | 100% | 21%–100% | 1 |
| Copied logic in N group (~N lines) | 88% | 53%–98% | 8 |
| Import loops (N) | 88% | 53%–98% | 8 |
| Third-party scripts without integrity hashes | 80% | 38%–96% | 5 |
| Any website may call this API (CORS *) | 75% | 41%–93% | 8 |
| MD5 / SHA-1 used for security | 75% | 41%–93% | 8 |
| Important code no test reaches (N function) | 62% | 31%–86% | 8 |
| Unused code (N function) | 62% | 31%–86% | 8 |
| N error silently swallowed | 50% | 22%–78% | 8 |
| Personal data written to logs | 50% | 22%–78% | 8 |
| Queries or requests inside loops (N) in N place | 50% | 22%–78% | 8 |
| Tokens or passwords in unencrypted storage | 50% | 22%–78% | 8 |
| Passwords written into docker-compose | 50% | 9%–91% | 2 |
| Shell `eval` of a variable | 50% | 9%–91% | 2 |
| Container runs as root | 38% | 14%–69% | 8 |
| Dynamic code execution (eval / exec / pickle / unsafe YAML) | 25% | 7%–59% | 8 |
| Shell commands built at runtime | 0% | 0%–32% | 8 |
| Broken encryption mode or cipher (ECB, DES, RC4) | 0% | 0%–79% | 1 |
| Personal data in unencrypted storage | 0% | 0%–79% | 1 |
| Pods using the node's network, processes or files (Kubernetes) | 0% | 0%–79% | 1 |
| Workflow runs a fork's code with this repository's secrets | 0% | 0%–79% | 1 |
<!-- precision:end -->

### Round 7: 126 repositories, and what generalizes

A held-out sample of 225 counted locations, nearly all (142 of the 149 still counted) from the 50 repositories added
in round 6, which no check had been tuned on: **106 right (47%, 95% interval 41–54%)** as drawn, against 71% in
round 5 on the first 76 repositories. The checks tuned on those didn't carry over to new web backends: credentials
0 of 8, shell commands built at runtime 0 of 8, SQL 1 of 8, data flow 2 of 8, eval 2 of 8, and 0 right for JWT,
CI injection, image secrets, debug mode, predictable random and iOS usage strings. The same misses kept recurring:
test, seed and dev code; placeholder values; sanitizers and validators the check doesn't know (`conditional_escape`,
signed redirects, knex bindings); options that are off only behind a setting; names that look like the risky thing.

Every check under half right across the held-out rounds pooled (2–7) is now a hint, listed but not counted, until
it is fixed: credentials (0 of 15), config credentials, image secrets, CI injection, JWT, debug mode, predictable
random, iOS usage strings, committed .env files, signing keys, data flow (2 of 43), SQL (18 of 40), raw HTML (13 of
40), TLS off (4 of 13), Go server timeouts. On the same round-7 labels the checks still counted were **95 of 149
right (64%, 95% interval 56–71%)**; by severity High 19 of 24, Medium 71 of 116. That is the number to expect on
unfamiliar code today. Network timeouts (8 of 8), dependency and import loops (15 of 16), module state (8 of 8),
copied logic (7 of 8), CORS (6 of 8) and MD5/SHA-1 (6 of 8) held up.

### Data flow on real apps: 0 of 34

The data-flow check ("Request data reaches dangerous calls") found only 11 flows in the first 76 repositories, too
few to measure. With 50 more repositories chosen for web backends it reports 98: it finds the textbook flaws in the
deliberately vulnerable training apps (Juice Shop's SQL injection in login and search and its SSRF in the profile
image upload; NodeGoat's `eval` of request fields, open redirect and SSRF), which are kept out of every precision
sample. On real applications, a sample of 34 flows from 13 of them was **right 0 times**: every flow was guarded on
the way. Redirects checked by a safe-URL validator (`url_has_allowed_host_and_scheme`, `is_safe_url`), paths kept
inside a folder (`is_relative_to`, `isPathInside`), outbound URLs whose host is fixed and only the query comes from
the request, values from a signed token, bound SQL parameters. Recognizing those guards is the next fix; until then
read a data-flow finding as "look here", not as a found vulnerability.

### Round 5, by severity and check

68 of 96 right (71%, 95% interval 61–79%). By severity: Critical 0 of 1, High 13 of 20 (65%), Medium 40 of 56
(71%), Low 15 of 19 (79%). Unused code went from 2 of 8 in round 4 to 6 of 8, untested code from 3 of 8 to 6 of 8,
import loops from 6 of 8 to 7 of 8. Still weak: swallowed errors, raw HTML and copied logic (4 of 8 each), root
containers (4 of 7: base images whose shipped image sets a user, entrypoints that drop privileges with `su-exec`).
Two of the four swallowed-error misses (a query-cache prefetch, a promise handled later) were already fixed by
changes made in parallel with this round, before the labels came in; they count against this round all the same.

### Round 4, by severity and check

By severity: Critical 1 of 3, High 13 of 23 (57%), Medium 51 of 65 (78%), Low 7 of 19 (37%). Security checks 38 of
53 (72%), quality 34 of 57 (60%). Reliable on this sample: timeouts, eval and pickle, CORS, module-level state,
root containers, runtime shell commands (each 7 or 8 of 8). Weak: credentials (0 of 2: names of secrets, not
values), raw HTML (2 of 8: constant markup and sanitizing the line doesn't show), unused code (2 of 8: called by a
framework or a library's visitor), untested code (3 of 8: tests that reach it through a data provider, a dynamic
`import()` or `reverse()`). Each sample is small; read these as where to look next, not as settled per-check rates.

### What the first measurement found

Most wrong findings weren't wrong about the line; they were about the wrong kind of code. A published database
port or a password in `docker-compose.yml` is real in a deployment, and in an open-source repository it is almost
always a developer's local database or a CI service container: 0 of 45 such locations were right. The same held for
dev containers, sandboxes, benchmark setups, starter templates and test fixtures. The rest were three kinds:
names that only look like the risky call (a parser method called `eval`, `TaskQueue.execute`, a local `fetch`),
values made safe on the way (identifier quoting, a validator, a fixed host, an option the user has to turn on), and
structure the call graph can't see (a method called through its interface, a route reached by a request test, a
name used in a `.vue` file). Each pattern is fixed generically and pinned by a test in
`tests/test_precision_lessons.py`, next to a true case that must stay reported.

### How far to trust these numbers

- **Labels.** Each location was labeled by a reviewer agent reading the code to the rubric below; 40 of them,
  picked at random, were labeled again independently: the two agreed on 34 of 39 (87%; one was left unsure), and the
  disagreements went both ways.
- **Tuned vs held out.** The fixes were made against the first sample, so its "now" column flatters: it says the
  patterns found are gone, not how a new repository will look. The held-out sample (when present above) was drawn
  and labeled after the fixes and is the honest estimate.
- **Sample size.** 25 per check at most, so a check's interval is wide; the overall figure is the tight one.
- **What's left out.** Recall isn't measured here (that needs knowing what wasn't reported; the benchmark does it),
  and checks whose claim is true by construction (a missing README, an unpinned version) aren't sampled.

### How a location is labeled

A location is **right** when the code there does what the finding says and is the kind of code the finding is meant
for, so the question in its "verify" text is worth asking. It is **wrong** when the claim doesn't hold for this code.
Reachability and exploitability aren't judged: a shell command built from a value that is right there in the
function counts as right even if that value is safe in practice, because that is the question the finding hands
the reader. Per check:

| Check | Right when | Wrong when |
|---|---|---|
| Shell commands, SQL, code execution, raw HTML | a value that isn't a constant reaches the shell string, SQL text, `eval`/`exec`/`pickle`/unsafe YAML or the HTML sink | every interpolated value is a constant or comes from a fixed list; no shell is involved (`execFile`, an argument list); the name only looks like the sink (a method called `eval`, `RegExp.exec`); a sanitizer or `SafeLoader` is applied |
| Data flows (taint) | the traced path exists and nothing on it validates or escapes the value | a step in the path doesn't happen, or the value is checked on the way |
| Credentials, config secrets, CI and compose passwords | the value looks like a working secret | a placeholder, test or example value, a public client ID or key, a value read from the environment |
| TLS or JWT checks off | verification is off by default or always | it's off only when someone sets an option for it, or the code verifies some other way |
| Network calls without a timeout | the call can wait forever: no timeout argument, client default or abort signal | a timeout is set anywhere on the path, or it isn't a network call |
| Queries or requests inside loops | each iteration issues a query or request (through the call chain shown), with the count set by data | the chain doesn't reach I/O, or the loop is a retry, poll or paging loop |
| Writes / file operations inside loops | each iteration writes or does file I/O that could be grouped | the loop runs once or a fixed few times, or the call isn't I/O |
| Errors silently swallowed | a broad catch discards the error without logging, rethrowing or returning it | the error is logged, rethrown or turned into a value the caller checks, or the catch is for one expected error |
| Module-level mutable state | the module-level value is reassigned or mutated after import | it's never changed after it's set up, or it's a type or constant |
| Import loops | every edge of the loop is an import that runs when the module loads | an edge is type-only (`import type`, `TYPE_CHECKING`) or inside a function, or the loop doesn't exist |
| Unused code | nothing calls or refers to the function | it's called, exported as public API of a library, invoked by a framework (route, hook, override, decorator, reflection) or used by a test |
| Important code no test reaches | no test calls it directly or through its callers | a test reaches it |
| Copied logic | the bodies are the same logic and could share one function | the similarity is only shape (boilerplate, generated code, different behavior) |
| Endpoints that change data without an auth check | the endpoint changes data and no authentication applies to it | auth applies (middleware, guard, decorator, base class), or it's public by design and checks something else (sign-in, a signed webhook) |
| CORS, cookies, cleartext HTTP, plain-HTTP URLs | the setting is on in configuration that ships, or the code requests a plain `http://` address on the internet | it's development-only configuration, or the address is local, an example, a namespace or a link in text |
| Containers and compose | the image that ships runs as root; a database port is published on every interface by a compose file that deploys | the stage is a build stage that doesn't ship; the base image runs as a non-root user; the compose file is for development, tests or CI |
| Weak hash or random | it protects something: a password, token, signature or secret | it's a checksum, cache key, ETag or other non-security use |
| Personal data in logs or storage | the value logged or stored is personal data (email, phone, name, address, health) | the name suggests it but the value isn't |
| Swift crashes, retain cycles, privacy manifest | the force-unwrap can fail on real input; the closure kept by `self` captures `self` strongly; the app ships on iOS and uses the API with no manifest | the value can't fail; the capture is weak or the closure isn't kept; the target isn't an iOS app |

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
