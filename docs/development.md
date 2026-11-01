# Development

## Building

`./build.mjs` needs Node.js and Go; the tests need `openssl` on the `PATH`.

```sh
./build.mjs                    # build simple-ca and request-cert for the host, and
                               # simple-ca-trust on Linux
./build.mjs build linux/arm64  # build simple-ca-linux-arm64, request-cert-linux-arm64 and
                               # simple-ca-trust-linux-arm64
./build.mjs trust              # build simple-ca-trust for the host with its own toolchain
./build.mjs trust darwin/amd64 # build simple-ca-trust-darwin-amd64, on macOS only
./build.mjs test               # run the tests
./build.mjs check              # check formatting, vet and run the tests
./build.mjs clean              # remove the built executables
./build.mjs assets             # download the browser files of the /help/ and /docs/ pages
```

The `/help/` page, `help/index.md`, and the `/docs/` pages of `serve --docs`, the files of
`docs/`, are drawn by the `render` package of
[serve-markdown](https://github.com/skoszewski/serve-markdown), whose browser files are not in
either repository. `./build.mjs assets` downloads `serve-markdown-assets-X.Y.Z.tar.gz` of the
serve-markdown release `go.mod` names and unpacks it into `assets/markdown/`, which `serve`
embeds; `assets/markdown/.version` names the release it came from. `build`, `test` and `check`
download it first when `assets/markdown/` holds another release, and build without the
pages, with a warning, when the download fails. A plain `go build` embeds what
`assets/markdown/` holds, and builds without the pages when it holds only `.gitkeep`.

`simple-ca-trust` is the Go program of `cmd/simple-ca-trust/` on Linux, which `build` builds
with the rest, and on macOS and Windows a program of the platform's own toolset, which only
`./build.mjs trust` builds, for the host or for the platform named: the Go program for `linux/*`
on any host; Swift 6.4 or later from the package in `trust/macos/` for `darwin/*` on macOS
only; and the .NET 10 SDK from `trust/windows/` for `windows/*` on any host, published as a
single `simple-ca-trust.exe` that runs on the .NET 10 runtime installed on the machine. A
platform the host cannot build for is skipped with a note. The release
workflow does not build it; [Trust stores](trust.md) has the commands for building it by hand.

The release workflow checks the formatting and runs `go vet`, but does not run the tests; they
are run with `./build.mjs test` or `./build.mjs check`.

## Releasing

`CHANGELOG.md` holds every release, newest first: a `## x.y.z` heading, a summary line between
blank lines, and the changes as a list. An entry is released once a commit on `dev` has its
summary line as the message; the newest entry not yet released collects the changes made since
the last release.

`./release.mjs`, run on `dev`, releases the newest entry, without pushing anything: it commits
everything with the entry's summary line as the message. Releases made this way stay on the
machine; each next one needs a new entry, with a new version.

`./release.mjs --push` publishes the newest entry:

1. commits everything with the entry's summary line as the message, when the entry is not
   released yet;
2. makes the annotated tag `vx.y.z` on `dev`; its message, which the workflow publishes as the
   release notes, is the entry followed by the entries released since the last tagged one, each
   under its own heading;
3. fast-forwards `main` to `dev`;
4. pushes `dev`, `main` and the tag in one atomic push; the tag builds and publishes the release.

```sh
./release.mjs                  # release the newest CHANGELOG.md entry, but push nothing
./release.mjs --push           # publish the newest CHANGELOG.md entry
./release.mjs -n               # print the commands instead of running them
```

It refuses to commit changes for a released entry, and to publish an entry whose tag is on
GitHub; the next change needs a new entry. Only a tag is built: pushing `dev` or `main` runs no
workflow.
