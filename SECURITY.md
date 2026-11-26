# Security

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository (a private
security advisory). Don't open a public issue. You'll get an answer within a week; a fix for anything serious ships
as a patch release with an advisory crediting you, unless you'd rather not be named.

In scope: anything that lets a repository being analyzed make codefactory do something it shouldn't (run code, read
or write files outside the repository and its `.codefactory/` folder, send data anywhere), and anything in the
GitHub Action that exposes a token or lets a pull request from a fork act with the repository's rights.

## What codefactory does and doesn't do

- **It never runs the code it analyzes.** Python is parsed with `ast`, TypeScript with the compiler's parser, other
  languages with tree-sitter. Nothing is imported, built or executed. The one external program it starts is `node`,
  for the TypeScript compiler, and `git`, for history and diffs.
- **It stays on the machine.** The only network call is `review --online` (dependency vulnerabilities from
  OSV.dev), which sends package names and versions and nothing else, and only when asked. `update` installs from
  the GitHub repository when you run it.
- **It writes only** the outputs you ask for, the cache in `.codefactory/`, and, for `accept` and `skill`, the files
  those commands describe.
- **No runtime dependencies.** The optional `[languages]` extra adds tree-sitter and its grammar pack.

## Supported versions

The latest release. Fixes aren't backported before 1.0.

## Verifying a release

Every release from 0.17.0 on is built by GitHub Actions from the tagged commit
([release.yml](.github/workflows/release.yml), every action pinned to a commit), with:

- **Build provenance** (SLSA, signed through Sigstore) for the wheel and sdist, and a signed **SBOM** (CycloneDX)
  attestation. Check that a file was built by this repository's workflow from a tag:

  ```bash
  gh attestation verify codefactory-0.20.1-py3-none-any.whl --repo dominickkubica/codefactory
  ```

- **SHA-256 sums** (`SHA256SUMS`) attached to the release.
- **Reproducible builds.** Rebuilding the tag gives byte-identical files:

  ```bash
  git checkout v0.20.1
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  pip install build==1.2.2.post1 && python -m build
  python tools/reproducible_sdist.py dist/*.tar.gz
  sha256sum dist/*        # the same as SHA256SUMS
  ```

For the GitHub Action, pin a release tag (`@v0.20.1`) or, strictest, its commit SHA, rather than `@main`.
