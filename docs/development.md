---
title: Development
---

## Building

`./build.mjs` needs Node.js and Go; the tests need `openssl` on the `PATH`. It writes the
executables to `bin/`, and the intermediate files of a build, such as the directories the
archives are packed from, to `.build/`; `.gitignore` leaves both out.

```sh
./build.mjs                    # build simple-ca, request-cert, token-setup, request-token,
                               # simple-ca-wif and simple-ca-lite for the host, and
                               # simple-ca-trust on Linux
./build.mjs build linux/arm64  # build simple-ca-linux-arm64, request-cert-linux-arm64,
                               # token-setup-linux-arm64, request-token-linux-arm64,
                               # simple-ca-wif-linux-arm64, simple-ca-lite-linux-arm64 and
                               # simple-ca-trust-linux-arm64
./build.mjs trust              # build simple-ca-trust for the host with its own toolchain
./build.mjs trust darwin/amd64 # build simple-ca-trust-darwin-amd64, on macOS only
./build.mjs trust --self-contained windows/arm64
                               # build simple-ca-trust-windows-arm64.exe carrying the .NET runtime
./build.mjs test               # run the tests
./build.mjs check              # check formatting, vet and run the tests
./build.mjs clean              # remove bin/, .build/, dist/ and the build files of trust/macos
                               # and trust/windows
./build.mjs assets             # download the browser files of the /help/ and /docs/ pages
./build.mjs docker [--registry REGISTRY] [--push] [<goos>/<goarch>]
                               # build simple-ca:<version> and simple-ca:latest; --push pushes them;
                               # the registry defaults to SIMPLE_CA_REGISTRY
./build.mjs deb                # build the Debian packages for the architecture of the host
./build.mjs dist [--dpkg]      # write the archives of an internal release for the host to
                               # dist/, and with --dpkg the Debian packages
```

`./build.mjs deb` builds two packages with `docker buildx`, for the architecture of the host,
also when the Docker engine runs on another one:

- `simple-ca`, of `debian-package/`: the image of `debian-package/Dockerfile` compiles
  `simple-ca`, `request-cert`, `token-setup`, `request-token`, `simple-ca-wif` and
  `simple-ca-trust` and runs `dpkg-buildpackage`, and buildx writes
  `simple-ca_<version>_<arch>.deb` to `dist/`; its units are those of `systemd/` with `/usr/bin`
  paths;
- `simple-ca-lite`, of `debian-package-lite/`: the image of `debian-package-lite/Dockerfile`
  compiles `simple-ca-lite` alone, and buildx writes `simple-ca-lite_<version>_<arch>.deb`, which
  installs `/usr/bin/simple-ca-lite` and its guide, and has no units and no system user.

The version of both is `X.Y.Z-1` for the newest `CHANGELOG.md` entry `X.Y.Z`, and `X.Y.Z-N` for
an entry `X.Y.Z-N`, whose programs are those of `vX.Y.Z`; while `vX.Y.Z` is not tagged it is
`X.Y.Z~rc-N`, which dpkg orders before `X.Y.Z-N`. The `debian/changelog` of each directory, which
`.gitignore` leaves out, is written from that entry for each build. The page's
browser files are downloaded first when `assets/markdown/` holds another release, and the build
fails when that fails. [systemd](systemd.md#debian-package) describes the installed `simple-ca`
package, and [Simple CA Lite](simple-ca-lite.md#installation) the `simple-ca-lite` package.

The builds in Docker, of the packages, of the image and of `Dockerfile.test`, keep their
temporary files in a tmpfs on `/tmp`, and the release workflow packs the archives in the
temporary directory of its runner, `$RUNNER_TEMP`; only local builds of `build.mjs` use
`.build/`.

The `/help/` page, `help/index.md`, and the `/docs/` pages of `serve --docs`, the files of
`docs/`, are drawn by the `render` package of
[serve-markdown](https://github.com/skoszewski/serve-markdown), whose browser files are not in
either repository. `./build.mjs assets` downloads `serve-markdown-assets-X.Y.Z.tar.gz` of the
serve-markdown release `go.mod` names and unpacks it into `assets/markdown/`, which `serve`
embeds; `assets/markdown/.version` names the release it came from. The archive must have the
SHA-256 that `assets/markdown.sha256` holds for the release, its one line `vX.Y.Z SHA256`; a new
serve-markdown release in `go.mod` replaces that line with its own, the SHA-256 of
`serve-markdown-assets-X.Y.Z.tar.gz.sha256` of the release. `build`, `test` and `check`
download it first when `assets/markdown/` holds another release, and build without the
pages, with a warning, when the download fails. A plain `go build` embeds what
`assets/markdown/` holds, and builds without the pages when it holds only `.gitkeep`.

While the newest `CHANGELOG.md` entry is not tagged, `build`, and `trust` for `linux/*`, build
the Go programs as its release candidate: `simple-ca --version` prints
`simple-ca version v1.7.0-rc` for an open `1.7.0` entry. Once the entry is tagged, and without
git, they report the version Go derives from the module, as a plain `go build` does; the release
workflow builds with the tag. The Windows version of `simple-ca-trust` reports `dev`, or
`$InformationalVersion`, and the macOS version the version in
`trust/macos/Sources/simple-ca-trust/Version.swift`; the release workflow sets both to the tag.

`simple-ca-trust` is the Go program of `cmd/simple-ca-trust/` on Linux, which `build` builds
with the rest, and on macOS and Windows a program of the platform's own toolset, which only
`./build.mjs trust` builds, for the host or for the platform named: the Go program for `linux/*`
on any host; Swift 6.4 or later from the package in `trust/macos/` for `darwin/*` on macOS
only; and the .NET 10 SDK from `trust/windows/` for `windows/*` on any host, published as a
single `simple-ca-trust.exe` that runs on the .NET 10 runtime installed on the machine, or
carries it with `--self-contained`. `build.mjs` writes the project file of the Windows version,
`trust/windows/simple-ca-trust.csproj`, which is not in the repository, for each build. A
platform the host cannot build for is skipped with a note. The release workflow builds the Go
version for `linux/amd64` and `linux/arm64`, the macOS version for `darwin/amd64` and
`darwin/arm64` on GitHub's Xcode 27 image, and the Windows version for `windows/amd64` and
`windows/arm64`, running on the installed .NET runtime, with `build.mjs trust`, and packs each
into the archive of its platform, `simple-ca-X.Y.Z-<goos>-<goarch>.tar.gz`, a `.zip` for Windows,
with `simple-ca`, `request-cert`, `token-setup`, `request-token` and `simple-ca-wif`;
[Trust stores](trust.md) has
the commands for building it by hand. Beside it, each platform has the archive of
`simple-ca-lite` alone, `simple-ca-lite-X.Y.Z-<goos>-<goarch>.tar.gz`, a `.zip` for Windows. The
workflow also builds the Debian packages with `./build.mjs deb` for amd64 and arm64, each on a
runner of its architecture with a `docker-container` builder of buildx, and adds
`simple-ca_X.Y.Z-1_<arch>.deb` and `simple-ca-lite_X.Y.Z-1_<arch>.deb` of both to the release.

`./build.mjs dist` writes the archives the release workflow builds for the platform of the host
to `dist/`, for an internal release of [release.mjs --no-tag](#releasing):
`simple-ca-X.Y.Z-<goos>-<goarch>.tar.gz` with the six programs, and
`simple-ca-lite-X.Y.Z-<goos>-<goarch>.tar.gz` with `simple-ca-lite`, each a `.zip` on Windows,
built as the workflow builds them and versioned `vX.Y.Z` of the newest `CHANGELOG.md` entry. Only
the release workflow builds the other platforms. It refuses uncommitted changes, an entry that no
commit has the summary line of, and a host without the toolchain of its `simple-ca-trust`: Swift
on macOS and the .NET SDK on Windows. The programs of each archive are packed from
`.build/pack-<archive>/`, removed afterwards. With `--dpkg`, it also builds both Debian packages
`X.Y.Z-1` as `./build.mjs deb` does, for the architecture of the host, also when the container
engine runs on another one: with Apple's `container` CLI on macOS when it is installed, and with
`docker buildx` otherwise.

The release workflow checks the formatting and runs `go vet`, but does not run the tests; they
are run with `./build.mjs test` or `./build.mjs check`. It refuses a tag that is not on `main` or
is not the version of the newest `CHANGELOG.md` entry.

## Releasing

`CHANGELOG.md` holds every release, newest first: a `## x.y.z` heading, a summary line between
blank lines, and the changes as a list. An entry is released once a commit on `dev` has its
summary line as the message; the newest entry not yet released collects the changes made since
the last release.

`./release.mjs`, run on `dev`, releases the newest entry, without pushing anything: it commits
everything with the entry's summary line as the message. Releases made this way stay on the
machine; each next one needs a new entry, with a new version.

`./release.mjs --push REMOTE` publishes the newest entry on the git remote `REMOTE`, such as
`origin` on GitHub, and `./release.mjs --push all` on every remote `git remote` lists:

1. commits everything with the entry's summary line as the message, when the entry is not
   released yet;
2. makes the annotated tag `vx.y.z` on `dev`, unless an earlier `--push` made it; its message,
   which the workflows publish as the release notes, is the entry followed by the entries released
   since the last tagged one, each under its own heading;
3. fast-forwards `main` to `dev`;
4. pushes `dev`, `main` and the tag in one atomic push to each remote that does not have the tag
   yet; the tag builds and publishes the release there, with the workflow of
   `.github/workflows/` on GitHub and that of `.gitea/workflows/` on Gitea.

`./release.mjs --no-tag` makes an internal release: it commits the entry as `./release.mjs`
does, and with `--push REMOTE` or `--push all` it pushes `dev` alone, without a tag, so `main`
stays at the last tagged release and nothing is built. The entry goes into the notes of the next
tagged release.

```sh
./release.mjs                         # release the newest CHANGELOG.md entry, but push nothing
./release.mjs --push all              # publish the newest CHANGELOG.md entry on every remote
./release.mjs --push origin           # publish it on the remote origin alone
./release.mjs --no-tag --push origin  # push it to origin as an internal release, on dev alone
./release.mjs -n --push all           # print the commands instead of running them
```

It runs on `dev` only. It refuses to commit changes for a released entry, and to publish an entry
whose tag is on every remote named; the next change needs a new entry. A `--push` naming a remote
that `git remote` does not list is refused. A tag pushed to one remote is pushed as it is to the
others by a later `--push`. Only a tag is built: pushing `dev` or `main`
runs no workflow. An entry `x.y.z-N`, `N` from 2, is a later release of the same code with changes
to the documentation or the packaging alone: `./release.mjs --push` fast-forwards `main` to `dev`
and pushes both without a tag to the remotes named, so nothing is built and no release is made,
and the entry goes into the release notes of the next tagged release. The workflows also skip a
tag `vx.y.z-N` made by hand.
