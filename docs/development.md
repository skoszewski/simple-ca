# Development

## Building

`./build.mjs` needs Node.js and Go; the tests need `openssl` on the `PATH`.

```sh
./build.mjs                    # build simple-ca for the host
./build.mjs build linux/arm64  # build simple-ca-linux-arm64
./build.mjs test               # run the tests
./build.mjs check              # check formatting, vet and run the tests
./build.mjs clean              # remove the built executables
```

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
