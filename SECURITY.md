# Security

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository (a private
security advisory). Don't open a public issue. You'll get an answer within a week; a fix for anything serious ships
as a patch release with an advisory crediting you, unless you'd rather not be named.

In scope: anything that lets a repository being analyzed make codefactory do something it shouldn't (run code, read
or write files outside the repository and its `.codefactory/` folder, send data anywhere), and anything in the
GitHub Action that exposes a token or lets a pull request from a fork act with the repository's rights.

## What codefactory does and doesn't do

- **It never runs the code it analyzes.** Python is parsed with `ast`, other languages with tree-sitter; nothing is
  imported, built or executed. TypeScript is read by a TypeScript compiler run in Node, and only one you installed:
  `CODEFACTORY_TYPESCRIPT`, or a global install (`npm install -g typescript@5`), never one inside the analyzed
  repository (its `node_modules` is the repository's code). The global install is found next to `node`, or with
  `npm root -g` run from your home folder so the repository's `.npmrc` isn't read. The GitHub Action installs its own
  pinned TypeScript. The other program it starts is `git`, for history and diffs.
- **Its cache can't be turned against it.** It never uses a `.codefactory/` that is a symbolic link or committed to
  git (then nothing is cached: a pull request could otherwise redirect its writes and clean-up, or plant results
  that hide its findings), never follows a link inside it, and leaves out of a diff's base anything that links
  outside the folder. A file changed within two seconds of being stamped isn't trusted from the cache.
- **It reads only the repository.** A file that is a symbolic link to somewhere outside it (`config.py ->
  ~/.aws/credentials`) is skipped by every check, analyzer and lockfile reader, and a patch's paths can't climb out of
  its folder. Outputs (`-o`, the PR comment, the baseline) are never written through a symbolic link.
- **Secrets it finds are reported cut to their first 4 characters** (`AKIA…`), in the review, PR comments, SARIF
  and annotations, including keys found only in git history.
- **A repository's settings can only read.** Saved queries in `factory.toml` run read-only on an in-memory copy of
  the graph (no ATTACH, writes or PRAGMA) and stop after 30 seconds. `[[rule]]` patterns shaped for catastrophic
  backtracking (`(a+)+`) are refused, and query names and rule ids are plain text. Annotations it prints for GitHub
  are escaped, so a finding's text can't become a workflow command.
- **It stays on the machine.** The only network call is `review --online` (dependency vulnerabilities from
  OSV.dev), which sends package names and versions and nothing else, and only when asked. `update` installs from
  PyPI (`codefactory-cli`) when you run it.
- **It writes only** the outputs you ask for, the cache in `.codefactory/`, and, for `accept` and `skill`, the files
  those commands describe.
- **No runtime dependencies.** The optional `[languages]` extra adds tree-sitter and its grammar pack.
- **The GitHub Action** runs codefactory from its own files (nothing fetched for it), installs the language pack and
  TypeScript at exact versions (`action-requirements.txt`, hash-checked), keeps its comment file in the runner's
  temporary folder (outside the checkout), posts the comment only on pull requests from the same repository (a fork's
  token can't write; the result goes to the job summary), always enforces `fail-on` (a step that fails counts as a
  failure), and never runs the pull request's own TypeScript compiler.
- **Its own CI and release** pin every action to a commit and every install to a hash (`build-requirements.txt` for
  the build backend), keep no token after checkout, and only ever move the `v0` tag forward.

## Running on a repository you don't trust

Everything in the analyzed repository is the author's: its source, but also `factory.toml` (saved queries, custom
rules, silenced findings, the profile), `.codefactory/`, `node_modules/`, symbolic links and file names. codefactory
treats all of it as data: it never runs it, never writes through it, and never lets it point outside the repository.
What the author can still do is shape the result: `factory.toml` can silence findings or declare the project's
profile. For a pull request from someone you don't trust, read its `factory.toml` changes as part of the review, the
same as any code.


## Supported versions

The latest release. Fixes aren't backported before 1.0.

## Verifying a release

Every release from 0.17.0 on is built by GitHub Actions from the tagged commit
([release.yml](.github/workflows/release.yml), every action pinned to a commit), with:

- **Build provenance** (SLSA, signed through Sigstore) for the wheel and sdist, and a signed **SBOM** (CycloneDX)
  attestation. Check that a file was built by this repository's workflow from a tag:

  ```bash
  gh attestation verify codefactory-0.22.1-py3-none-any.whl --repo dominickkubica/codefactory
  ```

- **SHA-256 sums** (`SHA256SUMS`) attached to the release.
- **Reproducible builds.** Rebuilding the tag gives byte-identical files:

  ```bash
  git checkout v0.22.1
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  pip install --require-hashes --no-deps -r build-requirements.txt
  python -m build --no-isolation
  python tools/reproducible_sdist.py dist/*.tar.gz
  sha256sum dist/*        # the same as SHA256SUMS
  ```

For the GitHub Action, pin a release tag (`@v0.22.1`) or, strictest, its commit SHA, rather than `@main`.
