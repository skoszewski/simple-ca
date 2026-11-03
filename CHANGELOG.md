# Changelog

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
