# Changelog

## 1.17.3

fix: build.mjs dist --dpkg with the container CLI writes the Debian package to dist/ instead of dist/out.tar/.

- With the `container` CLI, the package is taken from the `out.tar/<os>_<arch>/` directory that
  `container build` writes, and copied to `dist/simple-ca_<version>_<arch>.deb`.

## 1.17.2

fix: build.mjs dist --dpkg builds the Debian package with the container CLI of macOS.

- With the `container` CLI, the package is built from a context of the files that
  `debian-package/Dockerfile.dockerignore` lists, which `container build` sends without the error
  "changes out of order".

## 1.17.1

fix: the local builds of build.mjs are for the architecture of the host alone, also with a Docker engine of another one.

- `build.mjs dist` writes the archives of `linux`, `darwin` and `windows` for the architecture of
  the host alone, instead of for both `amd64` and `arm64`.
- `build.mjs dist --dpkg`, `deb` and `docker` without a platform give the container engine the
  platform `linux/<arch>` of the host, so a `docker` context on a host of another architecture no
  longer builds a package or an image of that one.

## 1.17.0

feat: simple-ca-wif sets up Google workload identity federation from the CA host, with the pool, the provider, the token type, and the token, access and federation.json of a machine.

- `simple-ca-wif google setup` creates the workload identity pool and the OIDC provider with the
  issuer and the keys of the CA, through the Google REST APIs. It sets `federation.issuer` and
  the token type in `simple-ca.json`. Run again, it leaves alone what exists and uploads the keys
  of the CA when they differ.
- `simple-ca-wif google machine NAME` gives the principal of the machine its roles, or creates a
  service account that the principal may impersonate. It then makes the token of the machine, or
  a one-time setup code, and writes `federation.json`.
- `simple-ca-wif` calls Google with `--access-token`, `GOOGLE_OAUTH_ACCESS_TOKEN` or Application
  Default Credentials. It is in the release archives, the Debian package and the image.
- The CA core is the Go package `pkg/simpleca`, and the client code of `request-cert`,
  `token-setup` and `request-token` is `pkg/client`.
- `request-cert` and `token-setup` exchange a setup code as `request-token` does, with the same
  error messages.
- The example pool ID of the guides is `lab-pool`, since Google requires 4 to 32 characters.
- `context delete` of the last values leaves no empty `context` section in `simple-ca.json`.
- `release.mjs --no-tag` makes an internal release: it commits the newest entry on `dev`, and with
  `--push` pushes `dev` alone, without a tag and without moving `main`.
- `build.mjs dist` writes the archives of the release workflow for an internal release to
  `dist/`, versioned with the newest entry, and with `--dpkg` its Debian package, built with the
  `container` CLI on macOS when it is installed, else with `docker buildx`.

## 1.16.1

fix: the prompt of the session edits the line in the width of the terminal instead of 80 columns.

- The prompt of `simple-ca` without arguments takes the width and height of the terminal each
  time it is shown, so a line wider than 80 columns no longer wraps at column 80. On Linux and
  macOS it also follows a resize of the terminal while a line is edited.

## 1.16.0

feat: simple-ca without arguments runs a session of commands, at a prompt with history and completion on a terminal or as a script from stdin, whose contexts switch the CA and keep option values for each CA in simple-ca.json.

- `simple-ca` without arguments runs the commands of a session in one process. On a terminal it
  reads them at a prompt with line editing, a history in `~/.simple-ca_history` (or
  `SIMPLE_CA_HISTORY`) and Tab completion; otherwise it runs the lines of stdin as a script,
  stopping at the first failing line with its exit status. A line is split as a shell splits it,
  and every command but `serve` is accepted. The passphrase of encrypted keys is asked once per
  session, and the commands of a script read no stdin.
- Each CA of the hierarchy is a context: a session started in a root CA directory works on the
  root CA, one started in an issuing CA directory on that issuing CA, and the prompt names it.
  The group `context`, known in a session alone, lists the CAs (`list`), switches the CA of the
  commands (`use`), and keeps option values for each CA (`set`, `add`, `delete`, `show`).
- The option values of a CA are kept in the new section `context` of `simple-ca.json`, `values`
  for the root CA and `cas` for each issuing CA. A command on that CA takes them for the options
  it is not given, in a session and on the command line alike; an option on the line wins.
- `release.mjs --push` takes the name of a git remote, any that `git remote` lists, or `all` for
  every remote, in place of the fixed `github`, `gitea` and `all`; a name that is not a remote is
  refused with the list of remotes.

## 1.15.3

fix: the Gitea workflow publishes the Debian package in the Debian registry of Gitea, in noble/main and resolute/main.

- The new step Publish package of `.gitea/workflows/build.yml` uploads `simple-ca_X.Y.Z-1_amd64.deb`
  to the Debian registry of the owner `CI_OWNER` at `CI_URL`, with the token `CI_TOKEN`, in the
  component `main` of the distributions `noble` and `resolute`, so apt installs it from
  `CI_URL/api/packages/CI_OWNER/debian`. A version already in a distribution is skipped.

## 1.15.2

fix: the Gitea workflow builds the Debian package for amd64 and attaches it to a Gitea release of the tag, and release.mjs --push publishes on GitHub, Gitea or both.

- `release.mjs --push` takes where to publish: `github`, the remote `origin`, `gitea`, the remote
  `gitea`, or `all`, both. It pushes `dev`, `main` and the tag in one atomic push to each remote
  that does not have the tag yet, and a tag made by an earlier `--push` is pushed as it is, so
  `--push gitea` can follow `--push github`. An entry is refused as published when its tag is on
  every remote named. A bare `--push` is refused with the usage.

- The new `.gitea/workflows/build.yml` runs for a pushed tag `vX.Y.Z` or `vX.Y.Z-PRE`, not for
  `vX.Y.Z-N`, on the Gitea copy of the repository. It checks the formatting and runs `go vet`,
  and refuses a tag that is not semver, not on `main`, or not the version of the newest
  `CHANGELOG.md` entry.
- It builds `simple-ca_X.Y.Z-1_amd64.deb` with `./build.mjs deb` and a `docker-container` builder
  of buildx, creates the Gitea release of the tag with the tag's message as notes, a prerelease
  for `-PRE`, and attaches the package.

## 1.15.1

fix: the release workflow builds the Debian package for amd64 and arm64 and adds both to the release.

- The new job `deb` of `.github/workflows/build.yml` runs `./build.mjs deb` on an amd64 runner
  and on an arm64 runner, `ubuntu-24.04-arm`, each with a `docker-container` builder of buildx,
  and the release holds `simple-ca_X.Y.Z-1_amd64.deb` and `simple-ca_X.Y.Z-1_arm64.deb` beside
  the archives.

## 1.15.0

feat: request-jwt becomes request-token, with a subcommand for each token, the access token of a Google service account and the credential file of Google's client libraries and gcloud, and the workload identity guides no longer repeat each other.

- `request-jwt` is renamed `request-token`, in `cmd/request-token/`, the release archives, the
  container image and the Debian package, and takes a subcommand: `api CODE` exchanges a setup
  code for the api token, `jwt` prints the JWT, `google-wif` the federated access token of Google,
  `google-access-token` the access token of a service account, and `entra-id` the access token of
  Entra ID. `--setup-code` is replaced by `api`, and the options of another cloud are no longer
  accepted; `federation.json` keeps its keys, and each subcommand reads those it uses.
- `request-token google-access-token` impersonates the service account of `service_account`,
  `SIMPLE_CA_SERVICE_ACCOUNT` or `--service-account` with the federated access token, with the
  scope of `google_scope`, `cloud-platform` by default.
- `request-token google-cred-config` writes `cred.json`, the credential file of
  `GOOGLE_APPLICATION_CREDENTIALS` and `gcloud auth login --cred-file`, for the provider and the
  service account. Its JWT comes from `request-token jwt --google-executable`, the answer of an
  executable source, or with `--credential-source file` from the file `request-token jwt --output`
  renews.
- [Workload identity federation](docs/workload-identity.md) links the two cloud guides at its
  start, and no longer has the sections Google Cloud and Microsoft Entra, whose commands repeated
  those of the cloud guides.
- [Google Cloud](docs/workload-identity/google.md) is rewritten in six steps with `request-token`.
  It describes the principal of a subject template, the mapping of a claim to an attribute and
  the limit of 8 uploaded keys. The new step 5 gives the roles to the principal of the machine,
  or to a service account it impersonates with `roles/iam.workloadIdentityUser`. Step 6 shows the
  one `federation.json`, exchanges a setup code with `request-token api` and gets both access
  tokens. The section Application Default Credentials and gcloud uses `google-cred-config`, with
  each credential source on its own. Appendix A shows the requests of `request-token` with curl
  and jq, and Appendix B a test call.
- [Microsoft Entra ID](docs/workload-identity/entra.md) links the static files of the general
  guide instead of repeating their commands, and says that Microsoft does not trust a certificate
  of the CA itself. Its step 5 uses `request-token api` and `request-token entra-id`, and an
  appendix shows their requests with curl and jq.
- The general guide says that `federation` is a section of `simple-ca.json` of the root CA, whose
  issuing CAs share its token types.

## 1.14.2

fix: a validity is given in minutes, hours, days, months or years, such as 30, 8h, 180d, 6m or 1y, and ./build.mjs deb builds a Debian package of simple-ca.

- Every duration, the `--valid` and `--otc-valid` options of the token commands, the Valid for
  fields of the token page, and `valid`, `max_valid` and `keep_expired` of `simple-ca.json` and
  `oidc-users.json`, is a whole number of minutes, or a whole number with one unit, `h`, `d`, `m`
  of 30 days or `y` of 365 days, with optional spaces before the unit. `m` is months, no longer
  minutes, and Go durations such as `1h30m` or `90s` are refused; a value in minutes is written
  without a unit, such as `15`.
- Durations are shown in the largest unit that holds them whole, such as `1y`, `2d`, `8h` or
  `15` for 15 minutes. The validity a pending token keeps for its setup code is stored the same
  way; one stored by an earlier release is still read.
- `./build.mjs deb` builds `dist/simple-ca_X.Y.Z-N_<arch>.deb` in Docker, for the architecture
  of the Docker host: `N` is 1 for an entry `X.Y.Z` and `N` for an entry `X.Y.Z-N`, with the
  programs of `vX.Y.Z`; it is `X.Y.Z~rc-N` while `vX.Y.Z` is not tagged. The build fails when
  the page's browser files cannot be downloaded.
- The package installs `simple-ca`, `request-cert`, `token-setup`, `request-jwt` and
  `simple-ca-trust` in `/usr/bin`, and `simple-ca.service`, `simple-ca-crl.service` and
  `simple-ca-crl.timer`, which are not enabled on install.
- It makes the system user `simple-ca` and `/etc/simple-ca`; purge removes the user and leaves
  the CA directory.

## 1.14.1

fix: the /help/ and /docs/ pages are drawn by serve-markdown 3.5.4, whose page bundles DOMPurify 3.4.17.

- serve-markdown 3.5.4 in place of 3.5.2; its page bundles DOMPurify 3.4.17, which fixes the
  advisories GHSA-cg2g-xh64-v4q7, GHSA-mrv2-3pqr-j5jr and GHSA-c6gr-qvv4-5v3f.
- `assets/markdown.sha256` holds the SHA-256 of its assets archive.

## 1.14.0

feat: the findings of a security review are fixed, with limits of the ACME server in simple-ca.json and simple-ca-trust add --fingerprint.

- The routes of an issuing CA, `/NAME/...`, take only a kebab-case `NAME`; a name with an escaped
  `/` or `..`, which reached a CA directory outside the root CA, is `404 Not Found`.
- A request whose subject holds a control character is refused by the signing API, the signing
  form, the certificate page and `cert sign`, and so is such a CN by `cert create`; a CN with a
  line end and tabs added forged lines to `index.txt`.
- The signing API and form refuse a subject with more than one CN, and a CN that is not a string.
- `/api/sign` refuses an `eku` or `ku` the certificate type does not have: a token adds no
  usages to its types.
- No certificate is issued valid past its CA: `cert create`, `cert sign`, the signing API, the
  certificate page, ACME and `ca create --issuing-ca` refuse it, naming the most days allowed. An
  issuing CA made without `--days` and `days.ca` is valid as long as its root CA.
- `index.txt` is changed under the lock file `index.txt.lock` and replaced at once, so `serve`,
  the certificate page and the commands do not lose each other's entries.
- `serve` has read, write and idle timeouts, and answers with `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`; the token and certificate pages no
  longer answer an internal error with file paths.
- ACME: the new settings `acme.max_accounts` (1000), `max_orders` (50), `max_names` (100),
  `max_contacts` (10) and `max_nonces` (100000) limit what clients make the server keep; an
  account stores only its key, an RSA key of at most 8192 bits, and its contacts are checked when
  they change too.
- ACME: the http-01 check follows a redirect only to the same name on port 80 or 443, and a
  failed fetch or lookup no longer tells the client why; finalize refuses a request signed with
  the account key, and a certificate file that has a key beside it is not replaced.
- Refused credentials: an attempt is counted before it is checked, so requests sent together get
  no more guesses; a request without a credential counts as a refusal; a token `/token-describe`
  shows as expired, revoked, renewed or removed no longer forgets the refusals. The token,
  certificate and audit pages ask for the token before they call their API.
- OIDC: a discovery document whose endpoints are not `http` or `https` URLs is refused, and an
  unreachable provider no longer holds back the other requests of the sign-in.
- Private keys are written through a new file readable by the owner alone, so the wider mode of
  a file they replace is not kept; an encrypted key with more than 10000000 PBKDF2 iterations is
  refused.
- `simple-ca-trust add` prints the SHA-256 fingerprint of the root CA, and with the new option
  `--fingerprint` adds nothing unless the root CA has it, on Linux, Windows and macOS; the Linux
  version runs the command that rebuilds the trust store from the system directories, not from
  `PATH`.
- `request-cert`, `request-jwt`, `token-setup` and `examples/request-cert.mjs` make the key and
  token files they write as new files, wait at most 30 seconds for an answer, and the Go tools
  read at most 1 MiB of it.
- `build.mjs` checks the serve-markdown assets archive against the SHA-256 of
  `assets/markdown.sha256`.
- `go.mod` requires Go 1.27.3.

## 1.13.1

fix: cert list, cert show, ca show and the certificate page show whether the private key of a certificate or CA is encrypted.

- `cert list` has a `KEY` column: `ENC` for an encrypted key in the CA directory, `PLAIN` for an
  unencrypted one, `-` for none; the issuing CAs of a root CA show their `ca_key.pem`.
- `ca show` and `cert show` end with `Private key:`, `ENC`, `PLAIN` or `-`; `cert show` gives it
  for a file of one certificate named `NAME_cert.pem`.
- The certificate page has a Key column with a closed padlock for an encrypted key and an open one
  for an unencrypted key, and its Show dialog has the line Private key with the padlock.

## 1.13.0

feat: private keys are encrypted at rest with a passphrase, as PKCS#8 PBES2 files that OpenSSL reads, and the new commands key encrypt and key decrypt convert the keys of a CA.

- `SIMPLE_CA_KEY_PASSWORD`, or the file named by `SIMPLE_CA_KEY_PASSWORD_FILE`, is the passphrase
  of the private keys, one for every CA. A command that reads an encrypted key asks for it at its
  start when neither is set and the standard input is a terminal, and fails without it otherwise.
- With the passphrase known, `ca create`, `cert create` and the certificate page write the CA and
  certificate keys as `ENCRYPTED PRIVATE KEY` (PBKDF2-HMAC-SHA256, 600000 iterations,
  AES-256-CBC); without it they write unencrypted keys, as before.
- Every command and `serve` read encrypted keys, also those OpenSSL encrypts with PBES2, PBKDF2 and
  AES-CBC. `serve` gets the passphrase before it listens and does not start without it.
- `key encrypt` and `key decrypt` convert `ca_key.pem` and the `*_key.pem` files of the CA in
  `--ca-dir`, or with `--all` of the root CA and all its issuing CAs, and write the audit records
  `key.encrypt` and `key.decrypt`.
- The `--tls-key` of `serve` may be encrypted, and a key that does not match `--tls-cert` is
  refused at start.
- `golang.org/x/term` is a new dependency, for the prompt without echo.

## 1.12.5

fix: the menu of the guides groups the overview and the Google Cloud and Microsoft Entra ID walkthroughs of workload identity federation under one entry.

- The menu of `serve --docs` and of the repository's pages shows Workload identity federation as a
  group of Overview, Google Cloud and Microsoft Entra ID, in place of three entries of its own.

## 1.12.4

fix: the Google Cloud and Microsoft Entra ID walkthroughs of workload identity federation are guides in docs/workload-identity/, shown by serve --docs.

- The walkthroughs move from `examples/federation/` to `docs/workload-identity/google.md` and
  `docs/workload-identity/entra.md`. They are in the executable, and `serve --docs` lists them
  after Workload identity federation, which links them.
- `.serveignore` hides `examples/` again, and `bin/` in place of `build/`.

## 1.12.3

fix: examples/federation/entra.md sets up Microsoft Entra ID workload identity federation for one machine, as google.md does for Google Cloud, which request-jwt serves without the Node.js script.

- `examples/federation/entra.md` walks through the issuer published for Entra ID, the
  application with its federated credential and roles, the token of the machine, and the access
  token of `request-jwt` or curl; the guide and the menu of the pages link it.
- `examples/federation/google-access-token.mjs` is removed, as `request-jwt` does what it did;
  `google.md` no longer names it.

## 1.12.2

fix: ./build.mjs docker takes its registry from SIMPLE_CA_REGISTRY when --registry is not given.

- `./build.mjs docker` puts the image below the registry of `SIMPLE_CA_REGISTRY` when it is set
  and `--registry` is not given; `--registry` replaces it.

## 1.12.1

gap: tokens-db.json holds api tokens alone, a token with the new scope federate gets unstored JWTs from /api/federation-token, which request-jwt exchanges for Google and Entra ID access tokens, and a CA with an EC P-256 key signs ES256.

- `request-jwt`, a new Go command in `cmd/request-jwt/` beside `request-cert` and `token-setup`,
  in the release archives and the container image, gets a JWT from `/api/federation-token` with
  an api token with the scope `federate`, and prints it, or with `provider` the Google access
  token of its exchange at Security Token Service, or with `tenant_id` and `client_id` an Entra ID
  access token of the client credentials flow. Its settings `ca_url`, `token`, `token_file`,
  `provider`, `tenant_id`, `client_id` and `scope` come from `federation.json`, or the file of
  `--config`, replaced by `SIMPLE_CA_*` environment variables, replaced by options.

- A JWT of a token type, such as `google` or `azure`, is no longer a token of `tokens-db.json`.
  It is issued when asked for, recorded as `token.issue` in the audit log, and never stored; it
  has no `scope`, and simple-ca refuses a JWT with an issuer or an audience.
- The scope `federate` and `token create --federate-type TYPE`, with `--audience` and `--claim`,
  make an api token that gets new JWTs of that type at `POST /api/federation-token`, or
  `/NAME/api/federation-token` of an issuing CA, with an empty body: the token decides the JWT.
  The JWT is valid for the new `valid` of the type, `1h` by default, never after the token
  expires. A token with the scope `federate` and no token type gets no JWTs, and grants the scope
  on the token page, also a token of an OIDC profile with `federate`.
- `token issue --token-type TYPE NAME` prints one unstored JWT on the CA host.
- The issuer and the token types are the new `federation` section of `simple-ca.json`,
  `federation.issuer` and `federation.types`, in place of `tokens.issuer` and `token_types`, which
  are refused.
- `token create --token-type`, `tokens.token_type` of `simple-ca.json`, the `api` token type, the
  `simple_ca_token` claim and the `token_type` of the OIDC profiles are gone. Entries of 1.12.0
  with a token type load without it.
- `token list` and the token page show the token type of a token with the scope `federate` as
  Federates, and the token page creates such tokens and filters by them. On the token page, the
  token type opens a dialog of the token type, the audience and the claims, and a type based on a
  built-in type shows it, as `gcp-wif (google)`. The name of a token opens a dialog of the token
  as JSON. Its create dialog shows the name, the
  validity, the scopes and the clients first, then the Signing and Federation groups only for
  the scopes chosen, hidden otherwise.
- The list of a chooser in a dialog of the pages is no longer cut off by the edge of the dialog:
  it opens below the chooser, or above it where there is more room, and closes when the dialog
  scrolls.
- `token describe` and the signed-in dialog of the pages show the certificates of a token with
  the scope `sign` alone, and `token list` and the token page show `-` in place of the count for
  the others.
- The index page has no Sign a request button; its Sign Form Link column gives the URL of the
  signing form of each CA whose key is on the server, with a button copying it to the clipboard.
- The guide [Workload identity federation](docs/workload-identity.md) describes the scope
  `federate`, and the discovery document and the key set published as static files for Microsoft
  Entra ID, which has no upload of keys, and `examples/federation/google.md` sets up Google Cloud for one machine, step by step.
- `ca create --key-type ec` gives a CA an ECDSA P-256 key, `rsa` (RSA 4096) by default, chosen
  for each CA. Its certificates and CRLs are signed `ecdsa-with-SHA256`, and its tokens and the
  JWTs of its token types ES256; `token jwks` and `jwks.json` give its EC key, and the discovery
  document names ES256. The `ca.create` audit record names the `key_type`.
- `cert create --key-type rsa|ec` makes the key of the certificate, of the type of the CA key by
  default. A certificate of an EC key, also of a request signed by `cert sign`, the signing API,
  the signing form or ACME, has no `keyEncipherment` key usage.

## 1.12.0

feat: token types give a token the JWT that Google and Microsoft Entra workload identity federation exchange, with the JWKS from token jwks and serve.

- `token create --token-type` picks the token type: `api`, the default, `google`, with the
  audience given by `--audience` and a validity of at most 24 hours, or `azure`, with the audience
  `api://AzureADTokenExchange`. `token_types` of `simple-ca.json` redefines them or adds types,
  with an audience, a subject template of `{name}` and `{ca}`, a longest validity and claims.
- `--audience` replaces the audience of the type, and `--claim NAME=VALUE` adds claims to the JWT.
- A token with an audience carries the issuer `tokens.issuer` of `simple-ca.json`, or
  `ca_publish_base_url`, followed by `/NAME` for an issuing CA. `tokens.token_type` sets the
  default type, also for the profiles of the OIDC sign-in.
- Every JWT names the CA key in its header with `kid`, the RFC 7638 thumbprint. A JWT whose
  subject is not the token name carries the name in `simple_ca_token`, and simple-ca accepts it.
- `token jwks` prints the JSON Web Key Set of a CA, for `gcloud ... --jwk-json-path`. `serve`
  publishes `/.well-known/openid-configuration` and `/jwks.json` of the root CA, and of each
  issuing CA below `/NAME/`, when the CA has an issuer.
- `token create --cert-type` replaces `--type`, which stays accepted. `token list` heads the
  certificate types of a token `CERT TYPES`, and `token describe`, the token page and its
  signed-in dialog label them `Cert types`.
- `token list`, `token describe`, the token page and its signed-in dialog show the token type,
  issuer, audience, subject and claims; the token page creates typed tokens and filters by token type. The
  `token.create` and `token.renew` audit records name the token type and audience.
- The new guide [Workload identity federation](docs/workload-identity.md) sets up Google Cloud
  and Microsoft Entra.
- `./build.mjs` writes the executables to `bin/` in place of `build/`, and `clean` removes
  `bin/`.

## 1.11.5

fix: the certificate page offers a PKCS#12 file with a random password to download, also after Create a certificate.

- A certificate whose key is in the CA directory has a Download button, left of Revoke. It makes
  the PKCS#12 file of the certificate, as `cert pfx` does, with a new random password; a dialog
  shows the password once and offers the file, which the server does not keep.
- Create a certificate ends with the same dialog for the new certificate and its key.
- `POST /certificates/api/certs/pfx` returns the file and the password, `GET .../api/certs` tells
  with `has_key` which certificates have a key, and `POST .../api/certs` returns the `serial`.

## 1.11.4

fix: the signing forms and the setup and describe pages have a Cancel button in place of their links.

- Cancel returns to the page of `serve` the page was opened from, also after a refused request
  or an OIDC sign-in, or to the index page; it does not use the history of the browser.
- The links "All CAs", "Set up a token" and "Describe a token" are no longer on the signing forms,
  also not on a form of a CA that signs no requests; "All CAs" and "Set up a token" are no longer
  on the setup and describe pages. The setup page has Close in place of Cancel once the token is
  shown.
- The Show button of a certificate on the certificate page stands at the right of its row, after
  Revoke, so it keeps its place whether the certificate can be revoked or not.
- An error on the token, certificate and audit pages goes away with the next request that
  succeeds, such as showing another certificate; it stayed until the page was loaded again. A
  message such as "CRL written." stays.
- The token, certificate and audit pages no longer link to themselves at the top; each links to
  the other two.
- With `--webui`, the index page shows "Signed in as NAME" with Sign out when the tab keeps the
  token of a page, as the token, certificate and audit pages do; a token refused as invalid is
  forgotten.

## 1.11.3

fix: the audit page shows the time, event, CA, actor, way and client at first, and the lists of the pickers are as wide as their widest choice.

- The audit page starts with the columns Time, Event, CA, Actor, Via and Client; the Columns picker
  shows the columns of the other keys of the records. The columns shown are kept in the address as
  `?columns=` while they differ from these, in place of the hidden ones as `?hide=`.
- An open picker list was as wide as its button, so with a scrollbar that takes width, such as
  that of the Columns picker of the audit page, its longer choices were cut, as "Setup ...". The
  list now grows to its widest choice, within the window, and keeps room for the scrollbar.
- The Info dialog of a CA on the index page no longer has a "Sign a request" button; the row of
  the CA keeps it.

## 1.11.2

fix: the Columns picker of the audit page reads All, Some or None, in place of the names of every column shown.

- The collapsed Columns picker named every column shown, which made it as wide as the page; it
  now reads All, Some or None.

## 1.11.1

gap: the audit page has a Columns picker that hides and shows its columns, headed in words.

- The Columns picker of the audit page chooses the columns shown, several at a time; the hidden
  ones are kept in the address as `?hide=`.
- The columns of the keys of the records are headed by their words, such as Setup Code and OIDC
  User, in place of `setup_code` and `oidc_user`.

## 1.11.0

feat: the APIs match the commands, a page describes a token, and a release has one archive per platform.

- **Breaking:** `/api/sign` needs `type`, `name` and `days`, and takes `ku` and `eku`, as
  `cert sign` takes `--type`, the request file name, `--days`, `--ku` and `--eku`.
  `request-cert` gets `--days` and `--name`, and it and the example clients send `server` and 365
  days by default, as `cert sign` defaults them, and the CN as the name.
- **Breaking:** the APIs of the token and certificate pages take no defaults: a token create needs
  `valid`, `scopes` and, for the scope `sign`, `types`; a renew needs `valid`. A field a request
  does not use is refused. The pages fill in the defaults of the commands.
- **Breaking:** `tokens.localhost` of `simple-ca.json` is gone; `--localhost` and the box of the
  token page are never a default. A profile of `oidc-users.json` still sets `localhost`.
- The renew question of the token page has "Valid for", filled with the validity `token renew`
  keeps.
- A certificate signed at `/api/sign`, on the signing form or by an ACME client is written as
  `NAME_cert.pem` beside `index.txt`, without a key, which stays with the client. The Show button
  of the certificate page failed for these with "no certificate file of the CA directory holds
  the certificate". Certificates signed before this release have no file, and cannot be shown.
- `cert sign`, the sign of the certificate page, the signing API and ACME replace the file of an
  earlier certificate of the name, which `index.txt` still lists, and refuse the name `ca`, whose
  file is the CA certificate.
- `cert create` of a certificate whose cert and key exist fails, with the message the API answers
  with `409`; `cert revoke` of a revoked certificate fails, with the message of the API.
- The errors of the APIs name the value, not a command option, such as `the validity in days must
  be a positive integer` in place of `--days must be a positive integer`.
- A token of another CA of the server is refused with an error naming both CAs, in place of
  `invalid token`.
- A request without a token to the signing API, the signing form, the pages or the new page is
  recorded as `auth.refused` in the audit log.
- The new page `/token-describe`, "Describe a token", shows the attributes of a token pasted into
  it, as `token describe` does, with its CA; the pages link it beside "Set up a token".
- `GET /NAME/api/sign` answers `405 Method Not Allowed` with `Allow: POST`, as `GET /api/sign`
  does.
- `examples/token_setup.py` leaves out a path of the URL, as `token-setup` does.
- `./build.mjs` writes the executables to `build/`, and `clean` removes `build/` in place of the
  files of the root directory, so it no longer removes `simple-ca-mini.py`.
- A release has one archive for each platform, `simple-ca-X.Y.Z-<goos>-<goarch>`, holding
  `simple-ca`, `request-cert`, `token-setup` and `simple-ca-trust`, in place of the separate
  `simple-ca-trust` archives of macOS and Windows; the Linux version of `simple-ca-trust`, which
  had no release archive, is now in the Linux archives.

## 1.10.3

fix: the audit page shows the audit log of the server, with the records of all its CAs in one list, in place of those of one CA chosen.

- The audit page has no CA selector. Its list has a CA column and a CA filter, so a refused request
  to any CA shows with the rest; an issuing CA token still sees the records of its own CA alone.
- `GET /audit/api/entries` takes no `ca` and answers with the records the token sees.

## 1.10.2

fix: request-cert and the example clients take the URL of the CA, and add /api/sign themselves.

- `request-cert`, `examples/request_cert.py`, `examples/request-cert.mjs` and
  `examples/request-cert.sh` take `CA_URL`, such as `https://pki.example.com` for the root CA or
  `https://pki.example.com/servers` for the issuing CA `servers`, in place of the URL of its API,
  which gave `405 Method Not Allowed`. A URL ending in `/api/sign` still works.

## 1.10.1

fix: the container image builds again, with token-setup in its build context.

- `.dockerignore` lets `cmd/token-setup` into the build of the `Dockerfile`, which failed with
  `"/cmd/token-setup": not found`.

## 1.10.0

feat: the new command token-setup exchanges a setup code for its token, beside request-cert in the release archives and the container image.

- `token-setup [--url URL] [--token-file NEW_FILE] CODE` prints the token, or writes it to the new
  file, mode 0600. The server is `--url` or `SIMPLE_CA_URL`, and a path of the URL is left out, so
  the URL of an issuing CA works too; the file is also `SIMPLE_CA_TOKEN_FILE`.
- An answer without a token is reported with its status and text, also a page of a proxy in front
  of `serve`.

## 1.9.8

fix: a token whose setup code has expired can be renewed, the new example token_setup.py exchanges a setup code for its token, and the examples exchanging one with curl print the answer of a refused exchange, in place of a jq error or the word null as the token.

- `token renew` and the Renew button of the token page take a token whose setup code has expired,
  with a new code or a JWT; the token keeps the validity it was to have from the old code. A code
  that has not expired is still revoked first.
- `examples/token_setup.py` exchanges a setup code and prints the token.
- The examples of `/help/` and `docs/signing-api.md` keep the answer of the server and read the
  token from it. An answer without a token, an error or a page of a proxy, is printed; `token.txt`
  is not left behind, and `TOKEN` stays empty.

## 1.9.7

fix: "Documentation" moves below the pages of serve, beside "Signing help", the version and the theme button, and both links open in a new tab.

- With `serve --docs`, "Documentation" shows below the index page, the token, certificate and
  audit pages, the signing forms and `/token-setup`, in place of the link at the top of the index
  page.
- "Signing help" and "Documentation" open in a new browser tab, which leaves the page they are on
  as it is.

## 1.9.6

fix: the pages of serve --docs show the title of the guide in the browser tab, in place of its file name.

- Each guide in `docs/` has its title in its front matter, as `help/index.md` has, in place of its
  first heading. The page shows the title in its top row.

## 1.9.5

fix: "Signing help" moves below the pages of serve, beside the version and the theme button, and "Set up a token" is also on the token, certificate and audit pages and the signing forms.

- "Signing help" shows below the index page, the token, certificate and audit pages, the signing
  forms and `/token-setup`, in place of the links at the top of the index page and "How to sign"
  on the signing forms.
- The token, certificate and audit pages and the signing forms link to "Set up a token".

## 1.9.4

fix: the audit page shows each key of the records in a column of its own, in place of a single Details column.

- The table has a column for each key of the records shown, so the columns follow the search and
  the filters; a record without a key shows `-` in its column.

## 1.9.3

fix: the Details column of the audit page lists the keys of a record with their values, a pair on each line, in place of the raw key=value text.

- Each key of a record that has no column of its own shows on a line with its value, and a record
  without such keys shows `-`.

## 1.9.2

fix: the pages of serve keep a token refused for the scope of a page, which still opens the other pages of the browser tab.

- A token without the scope of the token, certificate or audit page, or not allowed from the
  client, no longer signs the tab out: the page asks for another token, and the pages the token
  opens still open with it. An invalid token is forgotten.
- A token from a setup code or an OIDC sign-in without the scope of the page is kept in the same
  way.

## 1.9.1

fix: the tests are split from main_test.go into a test file beside each source file they test, and the tests of the audit log and of theme.json no longer print the output of the commands and the errors they cause on purpose.

- The tests of `main_test.go` are in a test file for each source file they test, such as
  `ca_test.go`, `api_test.go` and `audit_test.go`; `main_test.go` keeps `TestMain`, the shared
  helpers and the tests of the command line.
- The audit test drops what the commands it runs print, such as `Token deploy revoked`.
- The `theme.json` test silences the errors it causes with a broken and an invalid file.

## 1.9.0

feat: the commands and serve write an audit log of every change to a CA and every credential handed out or refused, which serve also sends to the systemd journal or its standard error, audit list reads, and the audit page of serve --webui shows; serve logs everything in the format of the audit records, and logs requests only with --request-log.

- Each record is a line of `key=value` pairs, written by Go's `log/slog`, with the time first.
  The record names the event, the CA, the way the change was made (`via`), the actor and, for
  `serve`, the client.
  - The events are `ca.create`, `cert.issue`, `cert.revoke`, `cert.pfx` and `crl.write`;
    `token.create`, `token.renew`, `token.revoke`, `token.purge`, `token.setup` and
    `token.oidc`; and `auth.refused` and `auth.held`.
  - A record holds no token, setup code, ID token, key or password.
- The records of the root CA and its issuing CAs go to `audit.log` in the root CA directory,
  mode 0600, which `audit.file` of `simple-ca.json` moves. The file is opened for each record,
  so `logrotate` can rename it; a record that cannot be written is reported on the standard error.
- `serve` also sends each record to the systemd journal when it runs under systemd, each key a
  field such as `SIMPLE_CA_EVENT`, and to the standard error otherwise, where container runtimes
  collect it. The journal is used on Linux alone.
- `audit list` prints the records, filtered by `--event`, `--ca`, `--actor`, `--since` and
  `--until`.
- The new token scope `audit` opens the audit page of `serve --webui` at `/audit/`. It shows the
  newest records of a CA with a search and filters of the event and the way, from
  `GET /audit/api/entries`. `audit` cannot be the name of an issuing CA.
- The new guide `docs/audit.md` describes the records, the outputs, `audit list` and the page.
- `serve` logs its start, its pages, warnings and errors as records of the same format, such as
  `event=serve.start` and `event=serve.error`, in place of free-text lines, and no longer adds
  a line of its own beside the audit record of a change. In the journal, errors and warnings
  have their priority.
- `serve` logs each request, as `event=http.request` with the method, path, status and client,
  only with `--request-log` or `serve.request_log` of `simple-ca.json`; it is off by default.
- The certificate page no longer makes `serve` print the output of the commands, such as the
  fields of a new certificate, and signs a request without a temporary file.
- `docs/configuration.md` lists `oidc.reuse_token`, and the colours of `/oidc-callback` and the
  audit page in its table of `theme.json`.
- The form creating a token on the token page chooses the scopes and the certificate types in
  multi-select dropdowns in place of rows of check boxes; `*` chosen stands alone.
- `systemd/simple-ca.service` allows Unix sockets, so `serve` reaches the systemd journal.
- `simple-ca-mini.py` is in the repository again, unchanged at version 1.3.0, with its guide
  and its systemd unit.
- The guides are corrected against the code, among them:
  - `token renew` refuses a token waiting for its setup code, and `token list` and
    `token describe` show the OIDC user;
  - a client is held back from its 6th refused credential;
  - the names `tokens`, `certificates` and `audit` are refused as issuing CA names;
  - a CA without its key on the server can still revoke its certificates on the certificate page;
  - the `--days` defaults of `simple-ca.json`;
  - the audit page, its scope and `audit.log` in the guides of the pages, systemd and Docker;
  - the status codes of the APIs, and the clients `X-Forwarded-For` names;
  - the macOS behaviour and version of `simple-ca-trust`, and what `build.mjs clean` and
    `release.mjs` do.

## 1.8.5

fix: Enter in a field of a question of the token and certificate pages answers it with its action, in place of Cancel.

- Enter in "Code valid for" or "Code usable from" of the renew question, or in "Validity in
  days" of the question writing the CRL, closed the question as Cancel did. It now renews the
  token or writes the CRL; Cancel still closes it without doing so.

## 1.8.4

fix: the dialogs of the pages of serve no longer close on a click beside them, which a text selection dragged out of a field was taken for.

- Selecting the text of a field with the mouse, such as "Code valid for" of the form creating a
  token, closed the dialog when the pointer was released beyond its edge. The dialogs of the
  index page and of the token and certificate pages now close only with their Close or Cancel
  button, or with Escape.

## 1.8.3

fix: the theme CSS is written without a temporary string, and a test decodes the signed certificate without one.

- The CSS of the colours of `theme.json` writes each selector straight into its buffer, as it
  writes each colour; the CSS is unchanged.
- The cross-CA token test reads the certificate the signing API answers with by `fmt.Append`.

## 1.8.2

gap: serve holds back a client whose tokens, setup codes or ID tokens are refused repeatedly, the Status and Scope filters of the token and certificate lists take several values, and the labels of the pages are short.

- `serve` counts the credentials it refuses with `401 Unauthorized` for each client, an IPv6
  client by its /64. This covers the signing API, the signing forms, `/api/token-setup`,
  `/token-setup`, `/api/oidc-token` and the API of the token and certificate pages.
  - After 5 refusals in a row, the client is held back for 1 second, doubling with each further
    refusal up to 15 minutes.
  - While held back, it gets `429 Too Many Requests` with `Retry-After`, without its credential
    being checked.
  - An accepted credential, or an hour without a refusal, forgets the refusals.
- The labels and notes of the pages are short, without explanations, such as "One-time setup
  code" for "One-time setup code: hand out a code, exchanged once for the token". This covers:
  - the token and certificate forms and the renew dialog;
  - the scopes and the certificate types;
  - the sign-in dialog, the signing forms, `/token-setup`, the CA bundle of the index page;
  - the notes about a CA whose key is not on the server.
- The certificate form has no line of the name rules below the subject. "Valid for, in days" is
  "Validity in days".
- The renew dialog and the form creating a token show "Code valid for" and "Code usable from"
  only while "One-time setup code" is checked, so a renewal or a token without a setup code shows
  no code fields.
- The attributes of a token made by the OIDC sign-in, in "Your token" of the token and
  certificate pages and in `token describe`, show the OIDC user and the OIDC issuer as two
  values, in place of "USER of ISSUER". "Your token" is as wide as the dialog showing a token
  once, so an issuer URL fits on one line.
- The "Sign in with" button of the signing forms is beside "Sign and download", in place of
  below the token field.
- Status, of both lists, and Scope, of the token list, take one value or more, ticked in their
  picker, which stays open while they are ticked. Status shows the items of any status ticked,
  and Scope the tokens having every scope ticked. The address keeps the values separated by
  commas, such as `?status=expired,revoked`.
- A filter picker, such as Made by of the token list, showed a long choice, "OIDC sign-in",
  cut short in its list. It is now as wide as its longest choice. On a screen too narrow for
  that, it is as wide as the line.
- The examples of the guides fit in 100 columns:
  - the JSON examples of the guides and the JSON files of `examples/oidc/` have one key per
    line, and one item per line in an array of more than one;
  - long shell commands are continued on the next line.
- The end of `docs/docker.md` is a paragraph again, no longer shown as code.

## 1.8.1

gap: the token and certificate lists have a search and filters, and an OIDC sign-in asks before it replaces the active token of its user, which with oidc.reuse_token it can take again instead.

- The token list has a search over the name, OIDC user, status, scopes, types, domains, IP
  addresses, clients and certificate serials of a token. Its filters pick the status (active,
  waiting for a setup code, expired or revoked), a scope, and whether the OIDC sign-in made the
  token.
- The certificate list has a search over the subject, serial number, status and revocation
  reason, and a filter of the status: valid, expired or revoked.
- A search shows the items holding every word of it, in any letter case, with a count of those
  shown. The search and the filters are kept in the address of the page, so a reload or a link
  keeps them.
- The links between the token and the certificate page keep the CA shown, in place of opening
  the other page at the root CA.

- A sign-in with an active token stops on `/oidc-callback`. It names the token, with its issue
  time and expiry, and offers Replace it or Cancel. Replacing the token stops it working in
  scripts and other browsers. An expired or revoked token is replaced without asking.
- `POST /api/oidc-token` then answers `409 Conflict` with `active`, the CA, name, issue time and
  expiry of the token. It makes nothing and leaves the ID token unused, so the same ID token is
  sent again with `"replace": true`.
- With `"reuse_token": true` in the `oidc` section of `simple-ca.json`, the question also offers
  Use the current token. That answers with the active token unchanged, for `"reuse": true`.
  `GET /api/oidc` reports `reuse_token`.

## 1.8.0

feat: serve hands out tokens to the users of an OIDC provider, generic, Keycloak or Entra ID, who sign in on the token and certificate pages, the signing forms and /token-setup and get the token profile oidc-users.json gives their user, group or role.

- The `oidc` section of `simple-ca.json` sets up the sign-in: `provider` (`generic`, `keycloak`
  or `entra`), `issuer`, `client_id`, `scopes`, `label`, and the `user_claim`, `groups_claim`
  and `roles_claim` of the ID token, whose defaults come from the provider.
- The pages sign in as a public client with the authorization code flow and PKCE. The redirect
  URI is `/oidc-callback` of `serve`, which redeems the code in the browser.
- `POST /api/oidc-token` exchanges the ID token for the token of its user, checked against the
  JWKS of the provider. `GET /api/oidc` answers with the settings of the sign-in.
- `oidc-users.json` in the root CA directory holds the token profiles, each with its CA and the
  settings of the `tokens` section, and the rules giving them to users and groups. The first
  matching rule wins; without one, a role named like a profile gives that profile.
- A token made by the sign-in is named after its user, such as `alice-example-com`, and is made
  anew on each sign-in. `token list`, `token describe` and the token page show its OIDC user, and
  renewing it keeps the user.
- The sign-in dialog of the token and certificate pages, the signing forms and `/token-setup`
  have a "Sign in with" button when the sign-in is set up. The token fills the token field of a
  signing form, and `/token-setup` shows it once.
- `serve` refuses to start with OIDC settings or an `oidc-users.json` it cannot use.
- The new guide `docs/oidc.md` covers setting up a generic provider, Keycloak and Entra ID, and
  `examples/oidc/` holds examples for each.

## 1.7.2

fix: the pages of serve widen with the screen beyond the width of a tablet.

- The index page and the token and certificate pages take 11/12 of a screen from 1280 pixels
  wide and 5/6 from 1536 pixels, up to 2560 pixels, in place of at most 1024 pixels.
- The signing forms and `/token-setup` take 3/4 of a screen from 1280 pixels wide and 2/3 from
  1536 pixels, up to 1920 pixels, in place of at most 768 pixels.

## 1.7.1

gap: the API of the token and certificate pages answers with structured data alone, which the pages lay out, the sign-in dialog has no theme button, and serve refuses an empty --address.

- `GET /certificates/api/certs/show` answers with `certificate`, the content of the certificate
  as fields, such as `not_after`, `key` and `ip_addresses`, in place of `fields`, the lines of
  `cert show` as label and text pairs. Its subject and issuer are type and value pairs, and its
  key IDs and fingerprint hex without colons.
- `GET /tokens/api/cas` and `GET /certificates/api/cas` answer with `user_token`, the signed-in
  token as a token of `GET /tokens/api/tokens`, in place of `user_attributes`, label and text
  pairs. A token of `GET /tokens/api/tokens` has `issued`, `certs` lists the serials of its
  certificates in place of their count, and `ips` and `clients` are the prefixes as stored.
- A CA of `/api/cas` has `id`, `subject`, the type and value pairs of its subject, `has_key`, and
  `theme`, the colours of its `theme.json`, in place of the CSS; `role`, `label` and `name` are
  gone. A certificate of `GET /certificates/api/certs` has `subject` as type and value pairs, in
  place of `name`, the one-line `subject` and `subject_attributes`.
- The theme button is below the token and certificate pages alone, not in their sign-in dialog.
- `serve --address ""` is a usage error, "--address must not be empty; 0.0.0.0 is all
  interfaces", before `serve` looks for the CA.

## 1.7.0

feat: token create --otc and token renew --otc hand out a one-time setup code, exchanged once at /api/token-setup or on the sign-in of the token and certificate pages for the token.

- `token create --otc` prints a one-time setup code, such as `K7QF-M2XA-JP4D-W5ZR`, instead of
  the token, which waits for it with no JWT. `--otc-valid` sets how long the code can be
  exchanged, 15 minutes by default, and `--otc-network` the clients it is exchanged from. Only
  the SHA-256 of the code is kept in `tokens-db.json`.
- `serve` exchanges a code once at `POST /api/token-setup` for the token, valid for its
  `--valid` from then on, and its scopes; an unknown, used or expired code is `401`, a client outside
  `--otc-network` `403`.
- The sign-in of the token and certificate pages takes a token or a setup code; a code is
  exchanged, and the token it gives is shown once, signing in once its dialog is closed. A token
  without the scope of the page is shown once too, saying so, and the page then asks for another.
  The sign-in dialog links to the index page, All CAs, to leave without signing in.
- The token page creates a token with a setup code and shows the code once; a token waiting for
  its code is marked `setup code`, and is revoked, which cancels the code, but not renewed.
- `token renew --otc`, with `--otc-valid` and `--otc-network`, and the renew question of the token
  page renew a token with a setup code in place of its JWT: the old JWT stops working at once,
  and the new one is made when the code is exchanged.
- `token list` shows `setup until TIME` or `setup expired` for a token waiting for its code;
  `token renew` refuses it, and `token revoke` cancels its code.
- The page `/token-setup`, "Set up a token" on the index page, exchanges a setup code in a
  browser and shows the token once, with a Copy button and the attributes of the token.
- `token describe NAME` prints the attributes of a token of the CA: its status, issue time,
  scopes, types, domains, IP addresses, clients, setup code and certificates.
  `token describe --token-file FILE` or `--stdin` describes a token itself from its JWT, and with
  `--ca-dir` also checks its signature and reads the rest from the `tokens-db.json` of that CA.
- "Signed in as NAME" on the token and certificate pages opens a dialog of the attributes of the
  signed-in token, as `token describe` prints them.
- Every page of `serve` has a theme button below it, and in the sign-in dialog of the token and
  certificate pages, an icon of a screen, a sun or a moon, which goes through system, light and
  dark; the browser keeps the choice for all the pages.
- `theme.json` in a CA directory, of the root CA or of an issuing CA, sets colours of the pages of
  `serve` about that CA, by role, such as `head` and `action`, for the light and the dark theme,
  so the pages of one CA are told apart from those of another; a CA without it keeps the built-in
  colours. The index page and `/token-setup` take those of the root CA, a signing form those of
  its CA, and the token and certificate pages those of the CA chosen. `serve` refuses to start
  with an unknown role or a value that is not a colour. The guide of the configuration lists the
  roles in a table, with their built-in light and dark colours and those of an example, as hex
  values. `examples/themes/` holds five themes, ember, forest, violet, crimson and ocean, each a
  `theme.json`.
- `demo_ca.png`, at the top of the README, shows the index page of `serve --webui` with its links,
  version and theme button.
- The signing form takes a setup code in place of a token: the code signs that one certificate,
  with the limits of its token, which is revoked once the certificate is issued, so it never
  leaves `serve`; a refused request leaves the code usable. `/api/sign` takes tokens only.
- `request-cert` and the clients of `examples/` take a setup code with `--setup-code CODE`: they
  exchange it at `/api/token-setup` of the server of `API_URL`, request the certificate with the
  token, and write the token to `--token-file` or `SIMPLE_CA_TOKEN_FILE`, a new file, when it is
  given, for later requests.
- The help of `serve` at `/help/` shows how to exchange a setup code with `curl`, the page or
  `request-cert`, and how to sign one certificate with a code on the form.
- Every page of `serve`, the index page, the signing form and the token and certificate pages,
  shows the version of `simple-ca` below its content, and `serve` prints it at start,
  `simple-ca v1.7.0 serving the CAs of DIR`, followed by the URL of each page on a line of its
  own: `Index page:`, and with `--webui` `Token page:` and `Certificate page:`.
- `./build.mjs build` and `./build.mjs trust` build the Go programs of a newest `CHANGELOG.md`
  entry that is not tagged yet as its release candidate, such as `v1.7.0-rc`, in place of the
  version Go derives from git.

## 1.6.1

fix: the token and certificate pages link to the index page and to each other, simple-ca.service runs serve with --webui, and the guides show the pages over HTTP, with HTTPS as an option.

- The token and certificate pages link to the index page, All CAs, and to each other, as the
  index page links to them.
- `systemd/simple-ca.service` runs `serve --webui`, so the token and certificate pages are on
  port 8080 of the host.
- `docs/systemd.md` shows the first token, with the scopes `tokens` and `certs`, and, for HTTPS,
  the certificate of the host and a drop-in naming it in `SIMPLE_CA_TLS_CERT` and
  `SIMPLE_CA_TLS_KEY`.
- `docs/serve.md` and `docs/signing-api.md` describe plain HTTP as the normal case of the pages,
  and HTTPS with `--tls-cert` and `--tls-key` as an option where the network is not trusted.
- `examples/compose.yaml` runs `serve --webui` with Docker Compose, the CA directory in a named
  volume; `docs/docker.md` shows how to create the CAs and the first token with it.
- `kubernetes/kubernetes.yaml` runs `serve --webui` in Kubernetes on a persistent volume claim,
  with an init container of the image `kubernetes/Dockerfile` builds, which creates the CAs the
  claim lacks; `docs/docker.md` describes them, and making a token with `kubectl exec`.

## 1.6.0

feat: serve --webui serves the token and certificate pages, which replace token webui and cert webui, tokens have the scopes sign, tokens and certs, and SIMPLE_CA_TLS_CERT and SIMPLE_CA_TLS_KEY name the HTTPS files.

- `token webui` and `cert webui` are removed. `serve --webui` serves the token page at
  `/tokens/` and the certificate page at `/certificates/`, with their APIs below `api/` of each,
  and the index page links to them. Over plain HTTP beyond the loopback address, `serve` warns
  that their tokens can be read on the network. `tokens` and `certificates` cannot be issuing CA
  names.
- `token create --scope SCOPE`, which may be specified multiple times, `sign` by default or
  `tokens.scopes` of `simple-ca.json`, gives a token its scopes: `sign` for the signing API and
  the signing form, `tokens` for the token page and `certs` for the certificate page. `--type`,
  `--domain`, `--ip` and `--localhost` belong to `sign` and are refused without it. A token in
  `tokens-db.json` without scopes has the scope `sign`.
- `--scope *` gives a token every scope, and `--type *` lets it sign every certificate type of
  `simple-ca.json`, also one added later, `server` by default; `*` is given alone. The token page
  has a `*` box for each, and a token with the scope `*` can give every scope.
- The pages ask for a token with their scope instead of a key printed at the start, show whose
  it is and sign out. A root CA token opens every CA, an issuing CA token only its own CA. A
  token is accepted from the clients it allows, behind the trusted proxies of `serve`. Changes
  are logged with the token's name.
- The token page creates tokens with `sign` and the scopes of its own token, and renews, revokes
  and removes only the tokens whose scopes it has; it has a Scopes column and scope checkboxes.
- `/api/sign` and the signing form refuse a token without `sign` with `403 Forbidden`.
- `token list` has a SCOPES column.
- `serve` takes the certificate and the key of HTTPS from `SIMPLE_CA_TLS_CERT` and
  `SIMPLE_CA_TLS_KEY` without `--tls-cert` and `--tls-key`.
- The help of the commands, the labels, questions and messages of the web pages, and the guides
  of the signing API are worded more plainly.
- The certificate page shows each certificate by the CN of its subject, with a popup of the
  subject attributes, and a token of an issuing CA opens the page on its own CA.

## 1.5.14

gap: token webui and cert webui serve their pages over HTTPS with --tls-cert and --tls-key.

- `token webui` and `cert webui` take `--tls-cert` and `--tls-key`, as `serve` does, and serve
  the page and its API over HTTPS with them, without the warning about plain HTTP; the two are
  given together.

## 1.5.13

fix: the ACME guide shows how to get, renew and revoke a certificate of serve with lego, and systemd units renew it daily.

- `docs/acme.md` goes step by step through getting a certificate of an issuing CA with lego 5:
  the CAs and `acme.domains`, `serve` over HTTPS with a certificate of a CA the clients trust or
  of its own CA, whose root CA certificate lego is given with `LEGO_CA_CERTIFICATES`, the
  `http-01` and `dns-01` challenges, the files lego writes, renewal, and revocation with the CRL
  that publishes it.
- `examples/simple-ca-lego.sh` gets or renews the certificate of its host with lego, from the
  settings of the environment, and `systemd/simple-ca-lego.service` and
  `systemd/simple-ca-lego.timer` run it daily, with the settings of `/etc/simple-ca-lego.env`;
  `docs/acme.md` describes their installation.

## 1.5.12

fix: token webui and cert webui show a CA by the CN of its subject, with a popup of its attributes, and the token page shows no stray null.

- The pages of `token webui` and `cert webui` show a CA by the CN of its subject, or the whole
  subject without one, whose popup lists the attributes of the subject, as the index page of
  `serve` does; `/api/cas` gives each CA its `name` and `subject_attributes`.
- The token page of a CA without tokens no longer shows the word `null` above its Create button.

## 1.5.11

fix: the container image runs as the user and group 1000, the first user of Ubuntu, and /data belongs to them.

- The image runs as uid and gid 1000, on `gcr.io/distroless/static-debian13`, instead of
  `nonroot`, 65532, of its `:nonroot` tag, and its `/data` belongs to 1000:1000, so a host
  directory of the first user of an Ubuntu host is writable at `/data` without `--user`.

## 1.5.10

fix: the /help/ and /docs/ pages of serve are drawn by serve-markdown 3.5.2, which fixes a rendering bug.

- `serve` draws its `/help/` and `/docs/` pages with the `render` package and the browser files
  of serve-markdown 3.5.2, in place of 3.5.0, which fixes a bug in their rendering.

## 1.5.9-2

update: the README shows the index page of simple-ca serve, and a documentation or packaging release is pushed to main without a tag, which nothing builds.

- `README.md` opens with `demo_ca.png`, the index page of `serve` for a root CA and one
  subordinate CA.
- `./release.mjs --push` of a version `X.Y.Z-N`, a later release of the same code with changes to
  the documentation or the packaging alone, moves `main` to `dev` and pushes them without a tag,
  so nothing is built; the entry goes into the notes of the next tagged release. The release
  workflow also skips such a tag made by hand; a prerelease such as `vX.Y.Z-rc.1` is still built.

## 1.5.9

fix: build.mjs docker pushes the image it builds with --push.

- `./build.mjs docker` runs `docker buildx build` without `--load`, and `--push` pushes
  `simple-ca:X.Y.Z` and `simple-ca:latest`, below the registry `--registry` names.

## 1.5.8

fix: build.mjs docker builds the image of simple-ca as simple-ca:X.Y.Z and simple-ca:latest, below the registry --registry names.

- `./build.mjs docker [--registry REGISTRY] [<goos>/<goarch>]` builds the `Dockerfile` with
  `docker buildx build`, tagged with the version of the newest `CHANGELOG.md` entry and `latest`,
  below `REGISTRY` when it is given, with that version as `VERSION`, and loads the image into the
  local images.

## 1.5.7

fix: the index page of serve lists the CAs, with the details of each in a dialog opened by its Info button.

- The index page lists the CAs with their name, the CN of the subject, or the whole subject
  without one, whose popup lists the attributes of the subject, their role, Root CA or
  Subordinate CA, in place of root CA or issuing CA and its name, and expiry, an Info button and,
  for a CA that signs requests, a link to its signing form; the Info button opens a dialog of the
  details and the files of the CA, as the cert webui shows a certificate, and `/#NAME`, where
  `/NAME` redirects, opens the dialog of the issuing CA `NAME`.

## 1.5.6

fix: the /help/ page of serve shows how to request a certificate with request-cert first, and the signing form chooses the certificate type with the dropdown of the web pages.

- `/help/` shows `request-cert` first: where to get it, the command, the files it writes and its
  options; the commands of `openssl`, `curl` and `jq` follow, for certificates with IP addresses
  or a request made elsewhere.
- The signing form of `serve` chooses the certificate type with the dropdown of `token webui` and
  `cert webui`, in place of the browser's own; `serve` serves its scripts below `/assets/webui/`.
  Each type is shown with what its certificates are for, such as `server: TLS server and TLS
  client` or `none: no key usages`, and the empty choice reads "Default: the token's first type".
- A request of a type the token does not allow is refused with the types the token allows, and
  the advice to choose one of them or the default, its first type.

## 1.5.5

fix: the releases carry request-cert beside simple-ca, and simple-ca-trust for macOS and Windows.

- The release archives `simple-ca-X.Y.Z-<goos>-<goarch>` hold `request-cert`, the Go client of
  the signing API, beside `simple-ca`, with the release as its version.
- The release workflow builds `simple-ca-trust` for macOS, amd64 and arm64, with Swift on
  GitHub's Xcode 27 image, and for Windows, amd64 and arm64, with .NET, and publishes them as
  `simple-ca-trust-X.Y.Z-darwin-<arch>.tar.gz` and `simple-ca-trust-X.Y.Z-windows-<arch>.zip`;
  each prints the release as its version. The Windows one runs on the installed .NET 10 runtime.
- `./build.mjs trust` gives the Windows `simple-ca-trust.exe` the version in the
  `InformationalVersion` environment variable, else `dev`.

## 1.5.4

gap: simple-ca-trust add and remove take the root CA certificate or a CA bundle with --file, instead of --ca-dir.

- `simple-ca-trust add --file FILE` and `remove --file FILE` take the root CA certificate or a CA
  bundle, PEM or DER, under any name, instead of `ca_bundle.pem` of the CA in `--ca-dir`; the
  two options cannot be given together.

## 1.5.3

fix: build.mjs trust writes the project file of the Windows simple-ca-trust, which builds again, running on the installed .NET runtime or self-contained with --self-contained.

- `./build.mjs trust` writes `trust/windows/simple-ca-trust.csproj`, which is not in the
  repository, before building the Windows `simple-ca-trust.exe`, which failed with MSB1003
  without it.
- `./build.mjs trust --self-contained` builds a Windows `simple-ca-trust.exe` carrying the .NET
  runtime; without it, the executable runs on the .NET 10 runtime installed on the machine.

## 1.5.2

fix: the Windows simple-ca-trust builds with the .NET SDK alone, on any host, and runs on the installed .NET runtime.

- The Windows `simple-ca-trust.exe` is published as a single file running on the .NET 10 runtime
  installed on the machine, instead of a native executable whose build needs Visual Studio's C++
  tools; `dotnet publish --self-contained` makes one carrying the runtime.
- `./build.mjs trust windows/<goarch>` builds it on any host with the .NET 10 SDK.

## 1.5.1

fix: simple-ca builds without a Go workspace, go.sum holding the checksums of serve-markdown's render package.

- `go.sum` holds the checksums of `github.com/skoszewski/serve-markdown/v3` v3.5.0 and of
  `go.yaml.in/yaml/v3`, which the release workflow, `go install` and the `Dockerfile` need; the
  release workflow of 1.5.0 failed at `go vet` for their lack, and published nothing.

## 1.5.0

feature: serve shows the clients of the signing API how to request a certificate at /help/, and serve --docs the guides at /docs/, drawn by serve-markdown's render package; token webui and cert webui manage the tokens and the certificates on web pages, and token renew renews a revoked or expired token, which is kept until purged; simple-ca-trust adds the CAs to the trust store of Windows, macOS or Linux.

- `serve` shows `help/index.md`, embedded in the executable, as a page at `/help/`: what a client
  needs, and how to make a key and a request with `openssl`, send it with `curl` and `jq`, save
  and check the certificate, what the errors mean, and the signing form. `/help` redirects to
  `/help/`. The index page links to it as "Signing help", and the signing forms as "How to sign".
- `serve --docs` shows the guides of `docs/`, embedded in the executable, at `/docs/`, with a menu
  of the guides in the order of the README; `/docs/` opens `usage.md`, and the index page links to
  it as "Documentation". An executable built without the page's browser files refuses `--docs`.
- The page needs the browser files of serve-markdown's page: `./build.mjs assets` downloads them
  from the serve-markdown release `go.mod` names into `assets/markdown/`, `build`, `test` and
  `check` do so when they are missing, and the release workflow and the `Dockerfile` embed them.
  An executable built without them, as `go install` builds it, has no `/help/` page.
- `ca create --issuing-ca help` and `--issuing-ca docs` are refused, being the routes of the pages.
- `token webui` serves a web page managing the tokens of the root CA and its issuing CAs, one CA
  at a time, chosen in a selector: it lists them, creates a token in a dialog with the options of
  `token create` and the defaults of `simple-ca.json`, and renews, revokes and removes tokens. It
  listens on `127.0.0.1:8081` by default. It prints the URL of the page with a random key as its
  `?key=` query, valid until it stops. The page draws everything from the JSON API of
  `token webui` below `/api/`, which takes the key in `Authorization: Bearer KEY` and refuses any
  request without it; the page reads the key from the URL, or asks for it. A new or renewed
  token is shown once, in a dialog with a Copy button, and leaves the page when the dialog
  closes; renewing a token still accepted, revoking and removing ask in a dialog.
- `cert webui` serves a web page managing the certificates of the root CA and its issuing CAs,
  one CA at a time, as `token webui` does the tokens, on `127.0.0.1:8082` by default: it lists
  the certificates and the CRL of a CA, shows the fields of a certificate as `cert show` does,
  creates a certificate and signs a request in a dialog with the options of `cert create` and
  `cert sign`, revokes a certificate for a reason, and writes the CRL. It writes the files to the CA directory as the commands do, and offers none to download.
- `token revoke` keeps the token in `tokens-db.json` without its JWT ID, expired at once, instead
  of removing it; an entry without a JWT ID is a revoked token. Its JWT is refused as revoked,
  and `token list` and the page show `revoked` in place of the expiry. The name stays taken until
  the token is purged.
- `token renew NAME` renews a token, revoked, expired or not: it gets a new JWT ID and is valid
  from now, for `--valid`, else as long as it was before or, revoked, for the default validity of
  `token create`, with what it allowed; the JWT it had is refused from then on.
- A revoked or expired token stays in `tokens-db.json`, to be renewed, until `token purge` removes
  it for good: `token purge` removes every revoked and expired token, and `token purge NAME` one of
  them; `serve` no longer removes expired tokens on its own. With `tokens.keep_expired` in
  `simple-ca.json`, such as `720h`, `serve` removes the tokens expired, or revoked, for longer than
  that, on start and every 5 minutes.
- `token list` and `token webui` show a single IP address of a token as the address, such as
  `127.0.0.1`, rather than as the prefix `127.0.0.1/32`; `tokens-db.json` keeps the prefix.
- The index page and the signing forms follow the light or dark theme of the browser, as the
  `/help/` and `/docs/` pages do.
- `simple-ca-trust add` adds the root CA of the CA in `--ca-dir`, read from `ca_bundle.pem` of
  the root CA, to the trusted roots and its issuing CAs to the intermediate CAs of the user, or
  of the machine with `--machine`; `remove` removes them and `list` lists them. It is written for each platform with
  its own toolset: .NET in `trust/windows/`, Swift in `trust/macos/` and Go in
  `cmd/simple-ca-trust/` for Linux, which adds the CAs as trust anchors. `./build.mjs` builds the
  Linux version with the rest, and `./build.mjs trust [<goos>/<goarch>]` the version of the host,
  or of the platform named, skipping one the host's toolchains cannot build; the releases do not
  carry it yet.
- `serve`, `token webui` and `cert webui` run the same HTTP server: each logs every request to
  the standard error, including those of unknown paths, which `serve` did not log, and an empty
  `--address` is an error of all three.
- The request field of the signing form, like the text fields of `token webui` and `cert webui`,
  is not autocorrected, capitalized or spell-checked by the browser.
- `./build.mjs` on Windows writes `simple-ca.exe`, which Windows runs, in place of `simple-ca`.
- The Go client of the signing API moves from `examples/request-cert/` to `cmd/request-cert/`, a
  command of the module: `go run ./cmd/request-cert` runs it, and
  `go install github.com/skoszewski/simple-ca/cmd/request-cert@latest` installs it.
- `request-cert` takes options: `--token-file`, `--type` and `--out-dir`, each replacing its
  environment variable, `--version`, and `-h` for the usage; wrong arguments print the usage and
  exit with 2. The token is read only from `SIMPLE_CA_TOKEN` or the token file, never from the
  command line.
- `./build.mjs build` also builds `request-cert`, named as `simple-ca` is: `request-cert`,
  `request-cert.exe` on Windows, or `request-cert-<goos>-<goarch>`; `clean` removes it.
- The Docker image holds `request-cert` in `/usr/local/bin`, beside `simple-ca`; it runs with
  `--entrypoint request-cert`.

## 1.4.0

feature: signing API tokens allow any name, IP addresses and localhost, are limited to client addresses behind trusted proxies, and take defaults from simple-ca.json; issuing CA, type and token names are kebab-case, and ca create takes --ca-url.

- `token create --domain '*'` makes a token that allows any DNS name, and any email domain for
  user types.
- `token create --ip` allows IP address SANs, and a CN that is an IP address, for the server name
  rules: an address, such as `192.0.2.10`, a prefix, such as `10.0.0.0/8`, or `*` for any
  address, repeated for more.
- `token create --localhost` allows `localhost` certificates, with the IP SAN `127.0.0.1`. A
  token takes at least one `--domain`, `--ip` or `--localhost`.
- `token create --host ADDRESS` and `--network PREFIXES`, a comma-separated list, limit the
  client addresses a token is accepted from; a request from another address is
  `403 Forbidden`. `--host 192.168.1.4 --domain '*'` signs any name for 192.168.1.4 alone.
- `serve --trusted-proxy`, or `serve.trusted_proxies` of `simple-ca.json`, names the proxies
  whose `X-Forwarded-For` header gives the client of the signing API: the last address in it that
  is not a trusted proxy. The header of any other peer is not read.
- `tokens` of `simple-ca.json` holds the defaults of `token create`, `valid`, `types`, `domains`,
  `ips`, `localhost`, `hosts` and `networks`, each replaced by the option of the same name.
- `tokens-db.json` keeps the prefixes of a token in `ips` and `clients`, and `token list` shows
  them in the `IPS` and `CLIENTS` columns; the `STATUS` column is gone, and an expired token not
  purged yet is marked `(expired)` after its expiry time.
- The names of issuing CAs (`ca create --issuing-ca`, also in `simple-ca-mini.py`), of the
  certificate types of `simple-ca.json` and of tokens are kebab-case: words of lower-case letters
  and digits joined by hyphens, such as `lab-servers`, `web-server` and `web-deploy`; other names
  are refused.
- `ca create --ca-url URL`, in `simple-ca` and `simple-ca-mini.py`, sets the base URL of the AIA
  and CRL Distribution Point extensions; its former name, `--ca-publish-base-url`, is still
  accepted and no longer listed in the help.

## 1.3.0

update: simple-ca and simple-ca-mini group their commands under ca, cert, crl and token, a Dockerfile builds an image of simple-ca, and the documentation is in docs/.

- The commands of `simple-ca` are `simple-ca GROUP COMMAND`, and the old names are refused:
  `make-ca` is `ca create`, `info` is `ca show` for a CA and `cert show FILE` for a file,
  `make-cert` is `cert create`, `sign` is `cert sign`, `make-pfx` is `cert pfx`, `revoke-cert`
  is `cert revoke`, `list` is `cert list`, `make-crl` is `crl create`, and `make-token`,
  `list-tokens`, `revoke-token` and `purge-tokens` are `token create`, `token list`,
  `token revoke` and `token purge`; `serve` stays.
- `simple-ca GROUP` and `simple-ca GROUP -h` list the commands of a group.
- `simple-ca-mini.py` has `ca create`, `cert create`, `cert pfx` and `serve`, in place of
  `make-ca`, `make-cert` and `make-pfx`.
- `systemd/simple-ca-crl.service` runs `simple-ca crl create --all`; an installed copy of the
  unit is replaced with this one.
- `Dockerfile` builds an image of `simple-ca` on distroless, run as a non-root user, with the CA
  directory `/data` on a volume; it runs `serve` on port 8080 by default.
- The README holds the overview, installation and a quick start; the guides are in `docs/`:
  `usage.md`, `directory-layout.md`, `configuration.md`, `serve.md`, `acme.md`,
  `signing-api.md`, `examples.md` (the former `examples/README.md`), `systemd.md`, `docker.md`,
  `simple-ca-mini.md` and `development.md`.

## 1.2.0

feature: serve signs certificate signing requests at /api/sign and on the /sign page for JWT tokens made with make-token.

- `serve` signs a CSR sent as JSON in a `POST` to `/api/sign` (root CA) or `/NAME/api/sign`
  (issuing CA `NAME`), authenticated by a bearer token of that CA, and returns the certificate
  and its chain as JSON; the certificate is recorded in `index.txt`.
- A token allows certificate types and domains: the CN, DNS names and email domains of the
  request must be a domain of the token or below one; other subject attributes and other SANs
  are refused.
- `make-token` creates a token, a JWT signed with the CA key, valid for `--valid`, one hour by
  default, and records it in `tokens-db.json` of the CA directory; `list-tokens` lists the tokens
  and `revoke-token` revokes one by removing it from `tokens-db.json`.
- `purge-tokens` removes the expired tokens from `tokens-db.json`; `serve` removes those of all
  its CAs when it starts and every 5 minutes.
- The commands and `serve` change `tokens-db.json` under the lock file `tokens-db.json.lock`.
- `/sign` and `/NAME/sign` are a form that takes a pasted CSR, a certificate type and a token,
  and downloads the signed certificate as `NAME_cert.pem`; for a CA without tokens or without
  its key, the page says so in place of the form.
- The index page shows the signing API URL of each CA with tokens, and links to its form.
- `examples/` holds clients of the signing API in Python, Node.js, Go and the shell, which make
  an EC P-256 key and a request and write the key, the certificate and its chain; they read the
  token from `SIMPLE_CA_TOKEN` or from the file `SIMPLE_CA_TOKEN_FILE` names.
- `/NAME` and `/NAME/` of an issuing CA redirect to its section of the index page, `/#NAME`,
  instead of `404 Not Found`.

## 1.1.0

feature: simple-ca-mini.py, a Python 3 version of simple-ca driving the openssl command.

- `simple-ca-mini.py` creates root and issuing CAs (`make-ca`), server, user and none
  certificates (`make-cert`) and PKCS#12 bundles (`make-pfx`) in the directory layout of
  `simple-ca`, using the Python standard library and `openssl`.
- `simple-ca-mini.py serve` serves the CA certificates, as PEM and DER, and the CA bundle over
  HTTP, with an index page of the CAs.
- `systemd/simple-ca-mini.service` runs `simple-ca-mini serve` for a CA in `/etc/simple-ca`.
- `docs/simple-ca-mini.md` describes Simple CA Mini, and the README points to it.

## 1.0.3

fix: make-cert and sign write safe certificate file names, and release.mjs publishes with --push only.

- `make-cert` names the files of a user certificate after its whole CN, and replaces each run of
  characters other than letters, digits, `-` and `_` with one `_`: `Alice Example` is written as
  `Alice_Example_cert.pem`; a CN that gives no file name, such as `...`, is refused.
- `sign` names the certificate after the request file by the same rule: `my web.v2.csr` is
  written as `my_web_v2_cert.pem`; a request file that gives no name, such as `+.csr`, is refused.
- `release.mjs` only commits the newest entry, with its summary line as the message, which marks
  the entry as released; the next change needs a new entry.
- `release.mjs --push` tags `dev`, moves `main` and pushes `dev`, `main` and the tag; the release
  notes are the entries since the last tagged one. `--no-push` and `-m` are gone.

## 1.0.2

fix: the releases have no Debian packages, and the release workflow runs no tests.

- The Debian packages are dropped: the releases hold the executables alone, and
  `./build.mjs package` is gone.
- The release workflow checks the formatting and runs `go vet`, without running the tests.

## 1.0.1

fix: release.mjs no longer runs the build and the tests.

- `release.mjs` commits, tags and pushes without running `build.mjs check`; the release workflow
  checks the sources.

## 1.0.0

feature: initial release

- `make-ca` creates a root CA or an issuing CA, each with an empty first CRL; `--write-conf`
  writes an `openssl ca` configuration.
- `make-cert` issues server, user and none certificates, with hostname, IP, email and numeric
  OID SANs; `--ku` and `--eku` add key usages and extended key usages to those of the type.
- `sign` signs a CSR, copying only its subject and SANs, after confirmation or with `--force`.
- `make-pfx` writes a PKCS#12 bundle encrypted with AES-256.
- `revoke-cert` and `make-crl` revoke certificates, with an optional `--reason`, and write CRLs
  with the reason codes; `make-crl --all` writes the CRLs of a root CA and all its issuing CAs.
- `info` shows a CA or the certificates of a file, and `list` the certificates a CA issued.
- `serve` serves the CA certificates, CRLs and the CA bundle, as PEM and P7B, over HTTP or HTTPS,
  with an index page of the CAs.
- `serve` is an ACME server for each CA, with the http-01 and dns-01 challenges, for the names
  under `acme.domains` of `simple-ca.json`.
- `simple-ca.json` holds the publish base URL for AIA and CRL Distribution Point extensions,
  default validity periods, and certificate types.
- The certificates are recorded in an OpenSSL-compatible `index.txt`, shared with `openssl ca`.
- systemd units for `serve` and for a daily `make-crl` of every CA in `/etc/simple-ca`.
- Release builds for Linux, macOS and Windows on amd64 and arm64, and Debian packages for amd64
  and arm64.
