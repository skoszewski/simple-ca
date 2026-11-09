# Instructions for Claude AI Coding Assistant

## General

- Simple CA version 1.x.x is a development release and minor release may introduce breaking changes, until a stable release is defined.
- Changes are always categorized as:
  - feature (feat): a new feature or enhancement - bumps the minor version number.
  - fix: a bug fix - bumps the patch version number.
  - gap: a bug in design or implementation, or a missing required feature - bumps the patch version number.
- Tests are run **only** on user request, do not run test suite on your own.
- Work in the repository only, do not make changes outside of it, unless requested.
- The project is multi-platform and includes features that are not available on developer's workstation. Docker may not be available.
- Do not propose next actions, unless asked.

## Requests

- A request starting with `feat:`, `fix:` or `gap:` is a change to make.
- A request starting with `bug:` is a report: analyze it, give the cause and a fix or options, and
  wait for the decision before changing anything.
- A request prepended with `do` is a task to complete. For example, `do fix: ...` is a request to fix something, and `do feat: ...` is a request to add a feature.

## Code

- Go standard library only; `go-pkcs12` and serve-markdown's `render` package, which draws the
  `/help/` page, are the dependencies, and no other is added.
- `simple-ca-trust` uses each platform's standard library only: `cmd/simple-ca-trust` the Go
  standard library, `trust/windows` the .NET base class library, without NuGet packages, and
  `trust/macos` Swift with the system frameworks, without package dependencies.
- The command line uses the standard `flag` package, without a command framework.
- Commands are grouped as `simple-ca GROUP COMMAND`: `ca`, `cert`, `crl` and `token`, with the
  verb `create` for making things; `serve` stands alone. No flat commands are added.
- The names of flags, issuing CAs, certificate types and tokens are kebab-case (`kebabCaseRE`); JSON keys
  and file names are snake_case.
- `simple-ca-mini.py` uses the Python standard library and runs the `openssl` command for every
  cryptographic operation, with command-line switches only and no configuration files; it has no
  cryptographic code of its own. Its `VERSION` is the version of the release that changes it.

## Documentation

- `README.md` holds the essentials only: the overview, installation, a quick start with a root CA
  alone, the list of guides, the serve-markdown mention and the licence.
- The guides are in `docs/`, with lower-case file names; the signing API clients are described in
  `docs/examples.md`.
- Documentation describes the current state only.
- Markdown and comments are wrapped at about 100 columns; files are plain ASCII.

## Changelog and releases

- Follow the `changelog-release` skill: before every edit of `CHANGELOG.md`, check whether the
  newest entry is released (a commit with its summary line, or its tag); a released entry is never
  changed, and the next change gets a new entry.
- The summary line of an entry summarizes changes and may not include less prominent ones.
- `release.mjs` is run only with `-n` unless the user asks; `--push` only on request.
