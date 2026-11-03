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

## Refused credentials hold their client back

A setup code holds 80 bits and a token is signed, but a client that sends credentials at a high
rate should still not get to try them freely. Every route that checks a token, a setup code or
an ID token shares one guard of `serve`, which counts the refusals of each client. Past the free
ones, it holds the client back for a time that doubles with each further refusal. A held client
gets `429 Too Many Requests` without its credential being checked, so a guess made while held
back tells nothing. The count is by address, after the trusted proxies, and by /64 for IPv6,
which a single host can fill with addresses. It lives in memory: `serve` is one process, and a
restart forgetting it costs an attacker the restart. A valid credential is held back too, since
telling a held client which credential is valid would undo the hold, and the hold of a lab
user mistyping a code is seconds, while a guessing client reaches the 15 minute cap at its 16th
refusal.

## The audit log is slog lines in one file, copied to the journal or stderr by serve

The audit records are written by the standard library's `log/slog` with its `TextHandler`, which
formats and quotes the `key=value` pairs, so the format is one Go programs and logfmt tools
already read. The time comes first, keyed, as `TextHandler` writes it; `level` is left out, as
every record is of one level, and the message is the event.

One file in the root CA directory holds the records of the root CA and its issuing CAs, with the
CA in each record, so one file tells all that happened to a PKI. The records are written where
the actor is known, by the commands and the handlers of `serve`, not by the functions that
write `index.txt` and `tokens-db.json`, which do not know who called them. Each record is one
appended write to a file opened for it, which needs no lock between the commands and `serve`,
and lets `logrotate` move the file. A record that cannot be written stops no change, as a full
disk should not stop a lab CA from issuing.

`serve` also copies each record to a stream, so its records reach the log of a container, which
reads stderr, and the systemd journal. Under systemd, `serve` sends them by the journal's native
protocol, in place of stderr, so each key becomes a journal field to search by. The standard
library has no journal client; the protocol is one datagram of `KEY=value` lines to a Unix
socket, which a few lines of `net` send. The stream is detected from `$JOURNAL_STREAM` rather
than configured, as systemd sets it exactly when the stderr of a service is the journal. Linux
alone has the journal, so macOS and Windows write stderr. The commands write the file alone,
so their records do not mix with what they print.

## serve logs every record in the format of the audit records

Everything `serve` logs, its start, its pages, warnings, errors and the requests, is a `slog`
record of the same handler as the audit records, so one stream has one format that one parser
reads, and the journal gets the fields of every record. The default logger of `slog` is that
handler, and the `log` package writes through it, so a message of the standard library, such as
one of `net/http`, is a record too. The level of a record gives its journal priority and is left
out of the line, as in the audit log. The request log is off unless asked for.

## The commands and serve share core functions that print nothing

The functions that issue a certificate, make a CRL or revoke a token return their results and
print nothing; the commands print and ask, and `serve` answers and logs. A function written for
a command, which prints to stdout or asks on a terminal, is not called by `serve`, whose stdout
is not a terminal and whose output is its log.

## The lists of the pages are searched in the browser

The token and certificate pages search and filter their lists in the browser, over the list the
API answers with for a CA, and the API takes no search. A CA holds hundreds or a few thousand
tokens and certificates, which one answer carries, and the data is already structured. So the
search answers each keystroke without a request, and matches the fields as the page shows them,
such as the addresses of prefixes. The search and the filters are kept in the address of the
page, as the CA is, so a reload or a link shows the same list.

## The OIDC sign-in is a public client in the browser that gets a stored token

The pages run the authorization code flow with PKCE themselves and redeem the code from the
browser. `serve` holds no client secret and no sign-in state, and needs no route to the token
endpoint of the provider, only to its discovery document and JWKS. Entra ID allows this for a
single-page application redirect URI only, and Keycloak for a public client with the origin of
`serve` in its Web origins. One redirect URI, `/oidc-callback`, serves every page, which keeps the
registration at the provider to one entry.

The ID token is exchanged once for a token of `tokens-db.json`, and is not accepted as a bearer
token. The pages, the signing API and the scripts then see one kind of token, with its scopes, CA
and clients. A token is listed, renewed and revoked as any other, and lives as long as its
profile says, not as long as the ID token. The sign-in is another way to hand out a token, next
to a setup code, and `/token-setup` shows the token for scripts. Since a sign-in makes the token
again, access is taken away in `oidc-users.json` or at the provider, not by revoking the token.
The nonce of an ID token gives one token, so an ID token read on its way makes no second token.
The name of a token made by the sign-in belongs to its OIDC user, and a token of that name that
is not the user's is never replaced.

A user has one token per CA, so the sign-ins of a user do not pile up tokens in
`tokens-db.json`. A new sign-in replaces that token, which a user may not know is used elsewhere,
in a script or another browser. So a sign-in with an active token stops and asks, and the ID
token is used up only once a token is given, so the answer goes back with the same ID token.
Giving the active token again, unchanged, lets browsers share it, but hands one JWT to every
sign-in of the user while it is valid; it is therefore offered only with `oidc.reuse_token`.

A user gets the profile of the first rule matching the user or a group, in the order of the
file, so the file reads top down. A role whose value names a profile gives it without a rule.
Entra ID app roles and Keycloak roles are given to users and groups at the provider, and they
carry their value in the ID token, unlike Entra ID groups, which are object IDs and drop out of a
token past 200. The rules come first, so a named user or a group can be given a profile other
than that of the user's roles.
