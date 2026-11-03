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

## One kind of token, with scopes, opens the signing API and the web pages

A token of `token create` carries scopes, `sign`, `tokens` and `certs`, and the token and
certificate pages take it as their bearer token. The pages need access that survives restarts,
stays out of the logs, names who made a change and can be withdrawn from one person; the signing
tokens already do all of that, signed with the CA key and recorded, revocable, in
`tokens-db.json`, with the Go standard library alone. An OIDC login was too heavy for simple-ca, and a second kind of
credential would duplicate the commands that create, renew, revoke and purge tokens.

The CA whose key signs a token bounds what it opens: a root CA token every CA, an issuing CA
token that CA alone, so the root CA key can stay offline while the operators of an issuing CA
use the pages.

The token page grants `sign` and the scopes of its own token, and manages only the tokens whose
scopes it grants, so a user of the page cannot widen their own access, as a token with `tokens`
alone could otherwise make itself one with `certs`.

## The token and certificate pages are part of serve

`serve --webui` serves the token page at `/tokens/` and the certificate page at `/certificates/`,
next to the index page, the signing form and the help, instead of commands of their own. One
server, one port and one certificate cover every page, the tokens that open the pages make a
per-process key unnecessary, and the pages share its trusted proxies and its logging. The pages
are off by default, as they change the CA directories, and their paths are names an issuing CA
cannot take, as `/help/` and `/docs/` are.

## A setup code is exchanged for a token made at the exchange

`token create --otc` hands out a one-time setup code instead of the token, so the JWT never
travels in a message or a clipboard: it is signed at the exchange, for the client that exchanges
the code, and its validity starts then. `tokens-db.json` keeps only the SHA-256 of the code, so a
copy of the file gives no code, and the code holds 80 random bits, typed by a person in four
groups of base32. The code works once and expires, by default after 15 minutes, and
`--otc-network` keeps it to the network of its user. `/api/token-setup` needs no token, as its
caller has none yet, and looks through every CA for the code, as its user may not know its CA.

## The APIs answer with data, not text

The JSON APIs of `serve` answer with structured data: names, lists, numbers, booleans and times
in RFC 3339, never text laid out for reading, such as the lines of `cert show` or the labels of
`token describe`. The pages and the commands lay the data out each for itself, so a client reads
a field without parsing, and a change of the wording or the layout of one changes no API.
