# Backlog

The working plan: what's next, in order, and why. Update it when an item is done (move it to the changelog) or the
order changes. Longer-range ideas live in [docs/DESIGN.md](docs/DESIGN.md#roadmap).

## Why this order

Before running on hundreds more repositories, make each run tell us more. 76 repositories are accounted for
([docs/CORPUS.md](docs/CORPUS.md)), but "accounted for" today means a person read every Critical and High finding.
That doesn't scale to 1,000. A measured precision per check does: it says which checks to trust, which to fix, and
lets triage at 1,000 repositories be a sample instead of a full read.

## Now

1. **Precision on real code, per check.** *(in progress)* Sample findings from the corpus by check, label each true
   or false with the reason, and publish precision with a confidence interval in [docs/ACCURACY.md](docs/ACCURACY.md).
   Labels are kept in the repo, so re-running after a change shows what moved. Then fix the worst checks first.
   - Done: 729 locations labeled across 50 checks (`tools/corpus/labels.json`), a second reviewer agreeing on 87% of
     a blind sample. First measurement: 43% right. About 25 false-positive patterns fixed, each with a regression
     test (`tests/test_precision_lessons.py`).
   - Done: re-scored on a fresh corpus run (tuned sample 43% → 68%) and labeled a held-out sample of 190 locations
     nobody tuned against: **46%**. Published in docs/ACCURACY.md.
   - Done (round 2 → 3): checks under 50% held out became hints (writes, file operations and array searches in loops,
     compose database ports, plain-HTTP URLs); the generic gaps were fixed. Round 3 held out: **58%** (77 of 132,
     95% interval 50–66%), from 52%.
   - Done (round 3 → 4): endpoints without an auth check (0 of 7) and Swift `try!`/`as!` (0 of 4) are hints. Kaizen:
     import loops (C# namespaces, PHP short names, Ruby gems: 11 wrong gone), Python packages under `lib/`
     (streamlit unused code 234 → 18), Compose previews, published packages' API. None right lost.
   - Done: round 4 held out: **65%** (72 of 110, 95% interval 56–74%). Medium 78%, High 57%, Low 37%.
   - Done (kaizen from round 4): about 25 wrong locations gone, none right lost (see the changelog).
   - Open from round 4: tests reaching code through a PHPUnit data provider or a dynamic `import()`; unused-code
     callers in Angular `$watch` listeners and sandbox APIs; swallowed errors whose promise is handled later
     (`Promise.allSettled`); SQL whose interpolated value is a literal at every caller (needs call-site data);
     findings whose "reached from" chain runs through wrong name-matched calls (`/healthz` → TypeORM DDL: not enough
     labeled signal yet to change reachability); gitea `UpdateRepositoryNames` writes lost to the `sync.Once` fix.
   - Done: round 5 held out **71%** (68 of 96); round 6 grew the corpus to 126 repositories.
   - Now: data-flow guards (0 of 34 right on real apps: safe-URL validators, path containment, fixed hosts, signed
     tokens, bound parameters); speed (n8n ~10 min: the TypeScript analyzer falls back and the runner analyzes
     twice). Then round 7 held out, including the new repositories.
   - Open: mocks set in vitest/jest setup files; `const s = vi.spyOn(…)` then `s.mockX`; Ruby `.select { }` blocks
     read as queries; PHP `use` loops (no load-time edge); "reached from" chains through wrong name-matched calls.

## Next

2. **Data-flow tracing for JavaScript and TypeScript.** *(first version built: `codefactory/jstaint.py`, 12 flows
   and 16 real-world look-alikes in `tests/test_jstaint.py`; not yet measured on the corpus)* Python has real taint analysis (request data followed through
   assignments and calls to SQL, shell, redirects, HTML); JS/TS has line patterns only. Most of the corpus is JS/TS.
   Follow `req.query`/`req.body`/`req.params`, Next.js `searchParams` and route `params`, Nest `@Body()`/`@Query()`,
   Fastify and Koa to the same sinks, with the same sanitizer list idea. Reuse the TypeScript analyzer's type
   information where it's available.
   - Done when: the bench has JS/TS taint labels (tuning and held-out), and corpus precision for it is measured.
3. **Auth, middleware and routes we miss.** Router-level middleware (`router.use(auth)`, Nest guards on a
   controller, Next.js `middleware.ts` matchers), more route styles. Known open cases from the corpus:
   - ~~appwrite: Utopia PHP routes aren't detected~~ (done: 745 routes, `scope` labels as auth).
   - django: admin redirects through `add_preserved_filters(...)` are reported as open redirects.
   - wagtail: a redirect built by a helper that is handed the request.

## Then

4. **Grow the corpus toward 1,000** in batches of 50–100, now triaged by sampling with the measured precision, and
   new repositories chosen for kinds and frameworks the corpus lacks.
5. **Release** once 1–3 land (ask before bumping: a version bump on main publishes to PyPI).

## Ideas, not scheduled

- Type-aware call resolution for Go (gopls) and Rust (rust-analyzer).
- Graph diffs between commits; safe `--fix` for exact duplicates and unused functions.
- Precision on the prefetch hook: does the injected context answer the question it was given?
