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

## JWTs of token types are issued to api tokens with the scope federate, never stored

`tokens-db.json` holds the tokens of simple-ca alone, the api tokens. A JWT for Google or
Microsoft Entra workload identity federation is a short-lived credential of another verifier: it
is signed when it is asked for, recorded in the audit log, and not stored, so the file does not
grow with every JWT and simple-ca never has to accept one. simple-ca refuses a JWT with an issuer
or an audience, which its own tokens never have, as the same CA key signs both.

A workload gets its JWTs unattended with an api token with the scope `federate`, made for one
token type with its audience and claims. The identity of the requester decides what the JWT
holds; the request sets nothing, so a stolen token gets no other subject, audience or claims than
its operator gave it, and revoking the token stops new JWTs at once. This is the model of the
scope `sign`, whose token carries the certificate types and names it may sign. `federate` is a
scope like the others: a token with it and no token type gets no JWTs, and grants the scope on the
token page, as a token of an OIDC profile with `federate` does for the person who creates the
tokens of the machines. `token issue` prints one JWT on the CA host, for the cases without a
token.

Built-in token types, `google` and `azure`, carry what each verifier requires, and
`federation.types` of `simple-ca.json` redefines them or adds types from them, as `types` does
for certificates, so an operator names a target once. The issuer and the token types are one
section, `federation`, apart from the `tokens` defaults of `token create`, as both concern the
JWTs of other verifiers alone; the name avoids `oidc`, the sign-in where simple-ca is the client. The type is read when a JWT is issued, so a change of
`simple-ca.json` applies to the next JWT. The longest validity of a type is at most that of its
base, such as the 24 hours of Google, and its validity bounds a JWT that outlives the revocation
of its token.

The CA key signs these JWTs, as it signs every token, and its public key is published as a JWK;
the key is public already in the CA certificate. The `kid` is the RFC 7638 thumbprint of the key,
so it is computed, never stored, and changes only with the key. Tokens issued before the `kid`
verify still, as simple-ca reads only `alg` of the header.

`token create --cert-type` names the certificate types a token allows, so it reads apart from
`--federate-type`; `--type`, its former name, stays accepted and is hidden from the usage of
`token create` alone, as `cert create --type` keeps it.

## request-token has one subcommand for each token it gets

The machine of a workload needs one kind of token at a time: the api token of its setup code, the
JWT, or the access token of one cloud. Each is a subcommand of `request-token`, so a command line
names its result, and a subcommand takes its own options alone, without checks of which options
exclude each other. One `federation.json` serves them all: each subcommand reads the keys it uses,
so a credential file and the commands of an operator share one file.

Google's client libraries and `gcloud` refresh their access tokens themselves from a credential
file, so `request-token` writes that file instead of being a wrapper around each tool. Its JWT
comes from an executable source, `request-token jwt --google-executable`, which gets a new JWT
whenever Google needs one, or from a file that `request-token jwt --output` renews, for a host
that does not allow executable sources; the user chooses with `--credential-source`. The
executable source runs the absolute paths of the program and of the configuration file, since
the libraries run it from any directory.

## The session of simple-ca builds on x/term, and its contexts hold option values per CA

`simple-ca` without arguments runs a session, so a sequence of commands shares one process and
asks for the passphrase of encrypted keys once. Its line editing, history and completion are the
`Terminal` of `golang.org/x/term`, a dependency already, instead of a readline library; reverse
search and multi-line input are left out with it. The terminal is raw only while a line is
edited, so the commands that read stdin, such as the question of `cert sign` and the passphrase
prompt, work as on the command line.

Each CA of the hierarchy is a context, and the session starts on the CA of the directory it is
started in, so its commands name no `--ca-dir`. A context also holds option values, which
`parseArgs` gives a command for the options it is not given, so no command has code of its own
for them, and they count as given, for the checks that look at which options were given. The
values are kept in the root CA's `simple-ca.json`, since an issuing CA has no file of its own,
and they apply wherever the command runs, also on the command line, so a session and a shell
script of the same CA behave the same. A value is checked by the option that takes it, as the
group cannot know which command will take it.

`serve` is not run in a session: it blocks, and it sets process globals, the log stream, the
default `slog` handler and the trusted proxies, which the next commands would inherit. A script
stops at its first failing command, as a later line usually depends on an earlier one, and its
commands read no stdin, which holds the script.

## The key of a CA is RSA or EC P-256, and its algorithms follow the key

`ca create --key-type` gives a CA an RSA 4096 or an ECDSA P-256 key, chosen for each CA, so an
issuing CA may differ from its root. The key decides every signature of the CA: certificates and
CRLs are signed as Go's `crypto/x509` signs with that key, and the tokens and the JWTs of token
types are RS256 or ES256, with no setting of their own that could disagree with the key. P-256
alone is offered because ES256 is the one EC algorithm Google STS accepts, and Microsoft Entra
documents RS256 alone, so both kinds of CA serve a verifier.

`cert create` makes a key of the type of its CA unless `--key-type` says otherwise, so an EC
CA gives EC certificates without a flag. An ECDSA key cannot encipher keys (RFC 5480), so the
certificate of any EC key leaves out `keyEncipherment`, whatever its type or `--ku` names,
also for requests signed by the API, the form and ACME.

## Private keys are encrypted as PKCS#8 PBES2 by own code on the standard library

An encrypted key is the `ENCRYPTED PRIVATE KEY` of RFC 5958 with PBES2 (RFC 8018). This is the
form OpenSSL writes and reads, so `openssl pkey`, `openssl ca` and the servers a leaf key is
copied to read it with the passphrase. The legacy `Proc-Type` PEM encryption of
`x509.EncryptPEMBlock` is deprecated and weak, so it is not used. Go's standard library has
PBKDF2, AES-CBC and ASN.1, but no encoder of the format, and go-pkcs12 does not export its own,
so the structures and the padding are own code in `helpers.go` instead of a new dependency.

One passphrase serves every CA, so `serve` and the CRL timer need one secret. It comes from
`SIMPLE_CA_KEY_PASSWORD` or a file, which fits systemd credentials and container secrets. The
terminal prompt needs `golang.org/x/term`, since the standard library cannot turn echo off.

Only the start of a command may ask, through `keyPassphrase(true)`. Every other call passes
`false` and fails without a passphrase, so `serve` never blocks a request on a prompt, and a
command without a terminal never waits.

A key is written encrypted whenever the command knows the passphrase. A CA that has one is then
encrypted throughout without a flag on each command.

PBKDF2 with 600000 iterations takes a noticeable part of a second, so `loadKey` keeps each key it
read with the bytes of its file. `serve`, which loads the CA key for every request, derives the
key again only after the file changes.

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
refusal. An attempt is counted before its credential is checked, and once the free refusals are
used a client has one attempt checked at a time, so requests sent together get no more guesses
than requests sent in turn. A request without a credential counts as a refusal, since it is
audited as one and would otherwise fill the audit log unhindered; the pages ask for the token
before they call their API, so opening one counts nothing.

## The CA of a route is a kebab-case name

The `{ca}` part of a route names an issuing CA only when it is a kebab-case name, the form
`ca create` gives them, with a `ca_cert.pem` in its directory. A path value is unescaped by the
mux, so it can hold `/` and `..`; checking its form, and not what it must not start with, keeps
every route inside the root CA directory.

## index.txt is changed under a lock file and replaced at once

`serve`, its certificate page and the commands all add to `index.txt` and mark revocations in
it. Each change reads the file, changes it and writes it back, under `index.txt.lock`, made as
`tokens-db.json.lock` is, and the new file replaces the old one by a rename, so two processes do
not lose each other's entries and an interrupted write leaves the file as it was. A field with a
tab or a line end is never written, and a request whose subject holds a control character is
refused where it is read, since the subject is a field of the file.

## A token adds no usages, and no certificate outlives its CA

The types of a token say what its certificates are for, so the signing API refuses a key usage
or extended key usage the type does not have; `cert sign` and the certificate page, used by the
operator of the CA, add usages. A validity that ends after the certificate of the signing CA is
refused on every path, not shortened, so the caller learns the limit; an issuing CA made without
`--days` and `days.ca` ends with its root CA, since the default of a root CA would always end
after it.

## The ACME server limits what its clients make it keep

Anyone who reaches the server may register an account, so the accounts of a CA, the open orders
and contacts of an account, the names of an order and the unused nonces have limits, settings of
`acme` with defaults. An account stores only the members of its key that are read. The http-01
check follows a redirect only to the same name on the ports of HTTP and HTTPS, and tells the
client that a fetch failed, not why, so it cannot be used to probe the network of the server.

## A duration is a whole number with at most one unit

Tokens live for minutes to years, and Go's durations stop at hours, so a year had to be written
as `8760h`. A duration is a whole number of minutes, or a whole number with one unit, `h`, `d`,
`m` or `y`; a month is 30 days and a year 365 days, fixed lengths, so a duration does not depend
on the date it starts. One unit and no fractions keep each value readable at a glance, and the
same form is read everywhere: the options, the pages and the configuration files.

## The Debian package is built in Docker for the host's architecture

The package is built by `dpkg-buildpackage` in the Go image, which compiles the programs, so the
host needs Docker and Node.js only, and the package is for the architecture the Docker host runs.
Its `debian/changelog` is written from the newest `CHANGELOG.md` entry, which stays the one
history, and its units are those of `systemd/` with `/usr/bin` in place of `/usr/local/bin`, so
the units are kept in one place. The units are neither enabled nor started on install, since
they need a CA that `ca create` makes first. Purge removes the user `simple-ca` but leaves
`/etc/simple-ca`, since it holds the keys of the CA.

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

## The CA core is pkg/simpleca with a subpackage per domain, and the client code pkg/client

`simple-ca`, `simple-ca-lite` and `simple-ca-wif` share the code of a CA, so it is the public
package `pkg/simpleca`, under `pkg/`, split into a subpackage per domain. A program imports the
domains it runs and no others, so `simple-ca-lite` links no ACME, OIDC or token code, and each
package is read and tested alone. Each package imports only the packages of the rows before it,
so there are no import cycles:

| Package | Holds |
|---|---|
| `pkg/simpleca`, the base | the settings of `simple-ca.json` and their types, keys and the passphrase, the helpers, the audit log and `LockFile` |
| `jose`, `cert` | JWS, JWK and the signing of JWTs; the certificate types, CAs, certificates, requests, revocation, CRLs, `index.txt`, PKCS#12 and `openssl.cnf` |
| `tokens`, `acme` | the token store, setup codes, token types and the JWTs of federation; the ACME server with its handlers |
| `oidc` | the OIDC client, the profiles of `oidc-users.json` and the sign-in handlers |
| `cli` | the commands of the groups `ca`, `cert`, `crl` and `key` |

`Config` holds the sections of every domain by value, so their types stay in the base package,
which imports no subpackage. The logic over a section is a function of the package that owns
it, not a method on `Config`: `cert.Types`, `tokens.Types`, `tokens.Issuer`, `acme.Limits` and
`oidc.Resolved`. Only `cert` imports go-pkcs12.

`acme` and `oidc` take what belongs to `serve` through hooks, package globals that `main` sets
at its start, in an `init`: for both, the client address, which reads the trusted proxies of
`serve`, and for `oidc` also the JSON replies and errors of `serve`, the guard of refused
credentials and the sign-in page, which `main` renders with its templates and theme. `serve` is
one per process, so a global holds what a parameter would pass on every call, and the packages
need nothing of `main`.

Package `main` of `simple-ca` keeps what only it runs: the token and audit commands, the REPL,
`serve`, the signing API and the web UIs. The tests of a package's own functions are in the
package; those that run commands through the command table are in `cli`, and those of what
`main` keeps stay in `main`.

The client code that `request-cert`, `token-setup`, `request-token` and `simple-ca-wif` share,
the requests to `serve` and to the clouds and the keys of `federation.json`, is the package
`pkg/client`, so each program reads and writes `federation.json` with the same code.

## simple-ca-lite is a program of its own over cert and cli

A host that only makes and signs certificates, such as one keeping a root CA offline, needs no
server, tokens, pages or session. `simple-ca-lite` is a program of its own, `cmd/simple-ca-lite`,
rather than a build tag or a mode of `simple-ca`, so its archive and its Debian package hold one
small executable with nothing of `serve`, embedded files or serve-markdown, and a release builds
it as it builds the other programs. Its commands are the groups of `cli.CertGroups()`, the same
functions `simple-ca` runs, so the two have the same options, help, files and audit records, and
either works on the same CA. `simple-ca-mini.py` stays the program for a system with `openssl`
and Python alone.

The issuing CA names that the pages of `serve` take are refused by `cert`, so a CA made by
`simple-ca-lite` can be served by `simple-ca` later.

## The limit of a request body is set by its handler

Each handler that reads a request body sets its own limit, `http.MaxBytesReader` with a constant
beside it: the signing API, the setup code exchange, the forms, the pages, ACME and the OIDC
sign-in. A handler knows the largest body it accepts, as a setup code is short and a request with
a CSR is not, and a package has no limit of another package to depend on, so `acme` and `oidc`
need nothing of `main` or of each other for it.

## simple-ca-wif calls the Google REST APIs with Application Default Credentials or a given token

`simple-ca-wif` sets up the pool, the provider, the service account and the role bindings with
plain HTTPS requests to the Google REST APIs, on the Go standard library, so it adds no
dependency, as the Google SDK would. Its access token is the one given with `--access-token` or
`GOOGLE_OAUTH_ACCESS_TOKEN`, or else one of the Application Default Credentials file that
`gcloud auth application-default login` writes or `GOOGLE_APPLICATION_CREDENTIALS` names: the
refresh token of an `authorized_user`, or a JWT signed with the key of a `service_account`. The
metadata server is not used.

Each step reads what exists first and leaves it alone, so `google setup` can be run again. It
refuses what it would have to replace, such as a provider with another issuer, but the keys of an
existing provider are replaced when they differ from those of the CA, so running it again after
a key change uploads the new keys.
