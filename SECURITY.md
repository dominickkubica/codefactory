# Security

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository (a private
security advisory). Don't open a public issue. You'll get an answer within a week; a fix for anything serious ships
as a patch release with an advisory crediting you, unless you'd rather not be named.

In scope: anything that lets a repository being analyzed make codefactory do something it shouldn't (run code, read
or write files outside the repository and its `.codefactory/` folder, send data anywhere), and anything in the
GitHub Action that exposes a token or lets a pull request from a fork act with the repository's rights.

## What codefactory does and doesn't do

- **It doesn't run the code it analyzes, with one exception you control.** Python is parsed with `ast`, other
  languages with tree-sitter; nothing is imported, built or executed. TypeScript is read by the TypeScript compiler,
  run in Node, and by default that is the project's installed one (`node_modules/typescript`): code from the
  project's dependencies, the same package its own build runs. It never runs a compiler committed to the repository;
  `CODEFACTORY_PROJECT_TYPESCRIPT=0` switches the project's off (then `CODEFACTORY_TYPESCRIPT` or a global install is
  used); and the GitHub Action uses its own pinned TypeScript unless its `project-typescript` input says otherwise.
  The other program it starts is `git`, for history and diffs.
- **Its cache can't be turned against it.** It never uses a `.codefactory/` that is a symbolic link or committed to
  git (then nothing is cached: a pull request could otherwise redirect its writes and clean-up, or plant results
  that hide its findings), never follows a link inside it, and leaves out of a diff's base anything that links
  outside the folder. A file changed within two seconds of being stamped isn't trusted from the cache.
- **Secrets it finds are reported cut to their first 4 characters** (`AKIA…`), in the review, PR comments, SARIF
  and annotations, including keys found only in git history.
- **A repository's settings can only read.** Saved queries in `factory.toml` run read-only on an in-memory copy of
  the graph (no ATTACH, writes or PRAGMA) and stop after 30 seconds. Annotations it prints for GitHub are escaped, so
  a finding's text can't become a workflow command.
- **It stays on the machine.** The only network call is `review --online` (dependency vulnerabilities from
  OSV.dev), which sends package names and versions and nothing else, and only when asked. `update` installs from
  PyPI (`codefactory-cli`) when you run it.
- **It writes only** the outputs you ask for, the cache in `.codefactory/`, and, for `accept` and `skill`, the files
  those commands describe.
- **No runtime dependencies.** The optional `[languages]` extra adds tree-sitter and its grammar pack.
- **The GitHub Action** runs codefactory from its own files (nothing fetched for it), installs the language pack and
  TypeScript at exact versions (`action-requirements.txt`, hash-checked), posts its comment only on pull requests
  from the same repository (a fork's token can't write; the result goes to the job summary), and never runs the
  pull request's own TypeScript compiler unless told to.

## Supported versions

The latest release. Fixes aren't backported before 1.0.

## Verifying a release

Every release from 0.17.0 on is built by GitHub Actions from the tagged commit
([release.yml](.github/workflows/release.yml), every action pinned to a commit), with:

- **Build provenance** (SLSA, signed through Sigstore) for the wheel and sdist, and a signed **SBOM** (CycloneDX)
  attestation. Check that a file was built by this repository's workflow from a tag:

  ```bash
  gh attestation verify codefactory-0.20.3-py3-none-any.whl --repo dominickkubica/codefactory
  ```

- **SHA-256 sums** (`SHA256SUMS`) attached to the release.
- **Reproducible builds.** Rebuilding the tag gives byte-identical files:

  ```bash
  git checkout v0.20.3
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  pip install build==1.2.2.post1 && python -m build
  python tools/reproducible_sdist.py dist/*.tar.gz
  sha256sum dist/*        # the same as SHA256SUMS
  ```

For the GitHub Action, pin a release tag (`@v0.20.3`) or, strictest, its commit SHA, rather than `@main`.
