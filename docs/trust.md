# Trust stores

`simple-ca-trust` adds the root CA and the issuing CAs of a simple-ca CA to the trust store of a
machine, so that its programs accept the certificates the CA issues, removes them, and lists the
CAs it added. It is one utility with one command line, written for each platform with the
platform's own toolset:

| Platform | Source | Built with | Store |
|---|---|---|---|
| Windows | `trust/windows/` | .NET 10 | the certificate stores of the user or the computer |
| macOS 15 or later | `trust/macos/` | Swift | the login or the System keychain, and the trust settings |
| Linux | `cmd/simple-ca-trust/` | Go | the system trust anchors |

```sh
simple-ca-trust add    [--user | --machine] [--ca-dir DIR | --file FILE]
simple-ca-trust remove [--user | --machine] [--ca-dir DIR | --file FILE]
simple-ca-trust list   [--user | --machine]
simple-ca-trust --version
```

## The CA directory or file

`--ca-dir` is the directory of the root CA or of one of its issuing CAs, as for `simple-ca`; it
defaults to `$SIMPLE_CA_DIR`, else the working directory. The CAs are read from `ca_bundle.pem`
of the root CA, the root CA and all its issuing CAs: in the directory itself, or in its parent
when its `ca_cert.pem` is that of an issuing CA.

`--file` names the certificates directly instead: the root CA certificate, such as
`ca_cert.pem` of the root CA, or a CA bundle such as `ca_bundle.pem`, PEM or DER, under any
name. It cannot be given with `--ca-dir`.

On a machine without the CA, use a copy of `ca_bundle.pem` or of the root CA's `ca_cert.pem`,
which `serve` publishes at `/ca_bundle.pem` and `/ca_cert.pem`; compare the SHA-256 fingerprint
of its root CA with the one `simple-ca ca show` prints on the CA's machine before trusting it.

The certificates must hold exactly one root CA, a CA certificate signed by its own key; every
other certificate among them must be a CA certificate the root CA signed. Certificates that do
not are refused before anything is changed.

## The commands

- `add` adds the root CA as a trusted root and the issuing CAs as intermediate CAs. On Windows
  and Linux, a CA already there is left as it is; on macOS, it is labelled again, and the root CA
  trusted again.
- `remove` removes the CAs of the bundle, and the trust of its root CA.
- `list` lists the CAs `simple-ca-trust` added, with their role, subject, expiry and SHA-256
  fingerprint, written as `simple-ca ca show` writes it. On macOS, a root CA without its trust
  settings has the role `root CA, not trusted`.

`--user`, the default on Windows and macOS, changes the store of the current user; `--machine`
changes the store of the machine, used by all its users and services, and needs Administrator or
root. Linux has only the machine's store: `--machine` is its default, and `--user` is refused.
The exit status is 0 on success, 1 on an error and 2 on a wrong command line.

## Windows

The root CA goes to Trusted Root Certification Authorities and the issuing CAs to Intermediate
Certification Authorities, of the current user, or of the computer with `--machine`, which needs
an elevated prompt. The CAs it added are those whose friendly name starts with `simple-ca: `.
`simple-ca-trust.exe` runs on the .NET 10 runtime, which must be installed, unless it was built
self-contained.

## macOS

The CAs go to the login keychain, or the System keychain with `--machine`, labelled
`simple-ca: ` and their subject, and the root CA is marked as always trusted, in the user's trust
settings or, with `--machine`, in the trust settings of all users. The issuing CAs need no trust
settings: they are found in the keychain when a chain is built.

- Trusting the root CA in the user's settings asks for the user's password in a dialog, and it is
  possible only in a session logged in at the login window, not over SSH.
- `--machine` is run with `sudo`, and then asks for nothing more.
- A `simple-ca-trust` downloaded with a browser is quarantined and refused by Gatekeeper, being
  unsigned; `xattr -d com.apple.quarantine simple-ca-trust` lifts that.

## Linux

The CAs are written, as PEM, to the directory of the trust anchors the administrator adds, and
the distribution's command rebuilds the trust store from it:

| Distribution | Directory | Command |
|---|---|---|
| Debian, Ubuntu | `/usr/local/share/ca-certificates/` | `update-ca-certificates` |
| Fedora, RHEL and derivatives | `/etc/pki/ca-trust/source/anchors/` | `update-ca-trust extract` |

Each CA is the file `simple-ca-` and the first 16 hexadecimal digits of its SHA-256
fingerprint, with `.crt`. Linux has no store of intermediate CAs: the issuing CAs are trust
anchors like the root CA, and stay trusted on their own while they are there. Browsers that keep
their own NSS databases, such as Firefox, are not changed.

## Building

The releases carry the macOS and Windows versions, as `simple-ca-trust-X.Y.Z-darwin-<goarch>.tar.gz`
and `simple-ca-trust-X.Y.Z-windows-<goarch>.zip`; the Windows one runs on the installed .NET 10
runtime. `./build.mjs trust` builds it for the host,
or `./build.mjs trust <goos>/<goarch>` for another platform the host's toolchains can build for
(see [Development](development.md)), or by hand, from the repository root:

```sh
# Linux, with Go
go build -o simple-ca-trust ./cmd/simple-ca-trust

# macOS 15 or later, with Swift 6.4 or later
swift build -c release --package-path trust/macos
cp "$(swift build -c release --package-path trust/macos --show-bin-path)/simple-ca-trust" .

# Windows, with the .NET 10 SDK and Node.js, on any host
node build.mjs trust windows/amd64
node build.mjs trust --self-contained windows/amd64
```

The project file of the Windows version, `trust/windows/simple-ca-trust.csproj`, is not in the
repository: `build.mjs trust` writes it for each build. The Windows `simple-ca-trust.exe` needs
the .NET 10 runtime on the machine it runs on; with `--self-contained` it carries the runtime
itself, about 80 MB instead of about 200 KB.
