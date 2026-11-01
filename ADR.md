# Architectural decisions

## simple-ca-trust is written with each platform's own toolset

Changing the trust store of a machine is done through the platform's own interface: the
certificate stores of Windows, the keychains and trust settings of macOS, and the anchors
directory and refresh command of Linux. Go's standard library reads the system roots but cannot
change them, and running the platforms' command-line tools would depend on their output and
options. So `simple-ca-trust` is three programs, each using only its platform's standard
library: C# with the .NET base class library on Windows, Swift with the system frameworks on
macOS, and Go on Linux. They share one command line and one rule for the file they take, so that
the guide and the habits of their users are the same on every platform.

## The macOS version uses the deprecated SecKeychain for the System keychain

Adding a certificate to the System keychain, which `--machine` needs so that all users and
services find the CA, takes a `SecKeychain` opened with `SecKeychainOpen` as the value of
`kSecUseKeychain`. Apple deprecated `SecKeychain` in macOS 10.10 but documents no other way to
address the System keychain, so it is used; the login keychain of `--user` is addressed the
same way, so that both scopes are handled alike. The deprecation warnings are ignored for the one
function that opens the keychain, with `@diagnose(DeprecatedDeclaration, as: ignored)` of
SE-0522, which Swift 6.4 implements behind the experimental feature `SourceWarningControl`,
enabled in `Package.swift`; other deprecations still warn.

## The issuing CAs are trust anchors on Linux

The issuing CAs are added with the root CA on every platform. Windows and macOS keep them as
intermediate CAs, which are trusted only through the root CA; Linux has no store for
intermediate CAs, so there they are trust anchors of their own, like the root CA.

## simple-ca-trust reads a local CA directory or file only

`simple-ca-trust` finds its CAs as every `simple-ca` command does, from `--ca-dir`,
`$SIMPLE_CA_DIR` or the working directory, and reads `ca_bundle.pem` of the root CA, or takes
the root CA certificate or a bundle named with `--file`, as a machine without the CA has it. It
downloads nothing: a root CA fetched
over the network can be replaced on the way, and adding a replaced root CA to the trust store is
the compromise the store exists to prevent, so the guide tells to compare the fingerprint of a
copied root CA with the one `simple-ca ca show` prints.
