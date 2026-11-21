---
title: OIDC sign-in
---

`serve` can hand out tokens to the users of an OpenID Connect provider, next to
[setup codes](signing-api.md#one-time-setup-codes): a user signs in at the provider, and `serve`
makes the user's token from the profile `oidc-users.json` gives the user. A profile can also give
the user a user certificate named after the user, from the page `/self-cert` or from
`request-cert`; see [User certificates](#user-certificates). Generic OIDC providers, Keycloak and
Microsoft Entra ID are supported.

The sign-in is offered as a "Sign in with LABEL" button on:

- the token page `/tokens/`, the certificate page `/certificates/` and the audit page `/audit/`,
  in the dialog asking for the token; the token of the sign-in signs in, when it has the scope of
  the page;
- the index page `/`, with `--webui`, in the same dialog, opened by its Login button; the token of
  the sign-in signs in, and the index page links to the pages;
- the signing forms `/sign` and `/NAME/sign`, where the token of the sign-in fills the token
  field, and the request and the type are kept while the browser is at the provider;
- `/token-setup`, which shows the token once, with a Copy button, for scripts and the signing
  API.

## How it works

The pages are a public client of the provider: the authorization code flow with PKCE (S256), and
no client secret.

1. The page gets the settings of the sign-in from `GET /api/oidc` and sends the browser to the
   authorization endpoint of the provider, with a new `state`, `nonce` and PKCE challenge kept in
   the browser tab.
2. The provider sends the browser back to `/oidc-callback` of `serve`, the one redirect URI to
   register. The page there checks the `state` and redeems the code at the token endpoint of the
   provider from the browser, a cross-origin request the provider must allow. It checks that the
   `nonce` of the ID token is the one it sent.
3. The page sends the ID token to `POST /api/oidc-token`. `serve` checks it against the JWKS of
   the provider and gives the user a profile of `oidc-users.json`. It then makes the user's token
   in the CA of that profile and answers with it. The browser goes back to the page the sign-in
   started on, which takes the token.

The token is a token of `tokens-db.json` like any other. `token list`, `token describe` and the
token page show the OIDC user it was made for, and it is renewed, revoked and removed as any
token. A user has one token in the CA of the user's profile. A sign-in makes a new one, with a
new JWT, which refuses the JWT the user had.

When the user's token is still active, neither expired nor revoked, the sign-in stops on
`/oidc-callback` and asks first. It names the token, when it was issued and until when it is
valid, since replacing it stops it working wherever it is used, in scripts and in other
browsers. The choices are:

- **Replace it** - makes the new token;
- **Use the current token** - with `reuse_token` set, gives the active token again, unchanged,
  so another browser shares it;
- **Cancel** - goes back to the page with nothing changed.

An expired or revoked token is replaced without asking. A revoked token is made again at the
next sign-in, so to take a user's access away, take the user out of `oidc-users.json`, or the
role or the group out of the provider.

The sign-in needs a secure context in the browser, for the PKCE challenge: the pages over HTTPS,
or on `localhost` or `127.0.0.1`. Entra ID accepts a redirect URI over plain HTTP only for
`localhost`.

## simple-ca.json

The `oidc` section of [simple-ca.json](configuration.md) turns the sign-in on:

```json
{
  "oidc": {
    "provider": "entra",
    "issuer": "https://login.microsoftonline.com/TENANT-ID/v2.0",
    "client_id": "00001111-aaaa-2222-bbbb-3333cccc4444"
  }
}
```

- `provider` - `generic` (the default), `keycloak` or `entra`; it gives the defaults of the
  label and the claims.
- `issuer` - the issuer of the provider, an HTTP or HTTPS URL. `serve` reads
  `ISSUER/.well-known/openid-configuration`, which must name the same issuer, and the JWKS it
  points to. Without `issuer`, the sign-in is off and `/api/oidc` answers `404 Not Found`.
- `client_id` - the client ID of the public client.
- `scopes` - the scopes the pages ask for; `openid`, `profile` and `email` by default, and
  `openid` is always asked for.
- `label` - the text after "Sign in with" on the button.
- `user_claim` - the claim naming the user, or a list of claims, the first one present naming the
  user.
- `groups_claim` and `roles_claim` - the claims holding the groups and the roles of the user, one
  or a list.
- `reuse_token` - `true` offers "Use the current token" when a user signs in with an active
  token, which gives that token again in place of a new one; off by default.
- `email_claim` and `name_claim` - the claims giving the email address and the CN of a user
  certificate, one or a list, the first one present giving the value.
- `cli_client_id` - the client ID of the public client of `request-cert`, another client than
  `client_id`, with a loopback redirect URI and the device authorization grant. Without it,
  `request-cert --oidc` and `--oidc-device` are refused.
- `cli_scopes` - the scopes `request-cert` asks for; those of `scopes` by default, and `openid` is
  always asked for. It needs `cli_client_id`.

A claim is a dotted path into the ID token, such as `realm_access.roles`, and the segment
`CLIENT_ID` stands for the client ID the ID token was issued for, `client_id` or
`cli_client_id`. A claim is a string or a list of strings.

| `provider` | `label` | `user_claim` | `groups_claim` | `roles_claim` | `email_claim` | `name_claim` |
|---|---|---|---|---|---|---|
| `generic` | `OIDC` | `sub` | `groups` | `roles` | `email` | `name` |
| `keycloak` | `Keycloak` | `preferred_username` | `groups` | `realm_access.roles`, `resource_access.CLIENT_ID.roles` | `email` | `name` |
| `entra` | `Entra ID` | `preferred_username` | `groups` | `roles` | `email`, `preferred_username` | `name` |

`serve` accepts an ID token signed with RS256, ES256, ES384, ES512 or EdDSA by a key of the JWKS
of the provider. Its `iss` must be the issuer. It is issued for its `azp`, or, without one, for
the client ID its `aud` holds; that client must be `client_id`, or `cli_client_id`, and `aud`
must hold it. It must have a subject, must not have expired, and its `iat` must be present and at
most 2 minutes ahead of the clock of `serve`. An ID token of `client_id` must have a `nonce`; one
of `cli_client_id` may lack it, as an ID token of the device authorization grant does. An ID token
gives one token, and is refused after that; it is known by its `nonce`, or by its SHA-256 without
one. The JWKS is fetched again
for a key it does not have, at most once a minute.

## oidc-users.json

The file in the root CA directory giving the users their tokens. Without it, every user is
refused, and a setting not described here is an error.

```json
{
  "profiles": [
    {
      "name": "ca-admin",
      "token": {
        "valid": "8h",
        "scopes": [
          "tokens",
          "certs"
        ]
      }
    },
    {
      "name": "web-signer",
      "ca": "servers",
      "token": {
        "scopes": ["sign"],
        "domains": ["lab.example.org"]
      }
    },
    {
      "name": "cert-viewer",
      "ca": "servers",
      "token": {
        "scopes": ["certs"],
        "networks": ["192.168.1.0/24"]
      }
    }
  ],
  "rules": [
    {
      "users": ["alice@example.com"],
      "profile": "ca-admin"
    },
    {
      "groups": ["web-team"],
      "profile": "web-signer"
    }
  ]
}
```

A profile gives a token, a certificate, or both:

- `name` - a **kebab-case** name, such as `ca-admin`; a role of the same value gives the profile.
- `ca` - the issuing CA of the token, empty or left out for the root CA. Its key must be in its
  directory. The certificate names its CA itself, with `certificate.ca`.
- `token` - the settings of the token, those of the `tokens` section of `simple-ca.json`:
  `valid`, `scopes`, `types`, `domains`, `ips`, `hosts` and `networks`, and `localhost`, as
  `token create --localhost` gives it. A setting left out takes its value from the `tokens`
  section, as for `token create`; `localhost` has no default. `keep_expired` is not a setting of a
  profile. A profile has no token type of
  [workload identity federation](workload-identity.md): with the scope `federate`, its token gets
  no JWTs, and grants the scope `federate` to the tokens its user creates on the token page.
- `certificate` - the settings of the user certificate, described in
  [User certificates](#user-certificates). A profile gives a certificate when `certificate` names
  its `ca`, and then gives its token the scope `self-cert` too. A profile that gives a certificate
  and has no `token` gives a token of the scope `self-cert` alone; one that gives no certificate
  and has no `token` gives a token of the defaults of the `tokens` section.

A rule gives its `profile` to the users of `users`, compared with the user claim, and to the
members of `groups`, compared with the groups claim.

A user gets:

1. the profile of the first rule, in the order of the file, naming the user or one of the user's
   groups;
2. without such a rule, the first profile, in the order of the file, whose name is one of the
   user's roles; a role naming no profile is ignored;
3. without either, no token: `/api/oidc-token` answers `403 Forbidden`.

The name of the token is the user claim in lower case, each run of other characters than letters
and digits turned into a hyphen: `alice@example.com` gets the token `alice-example-com`. A token
of that name in that CA that was not made for the same user is not replaced, and the sign-in is
refused with `409 Conflict`. The token is accepted only from the clients of its `hosts` and
`networks`, and the sign-in from another client is refused with `403 Forbidden`.

`serve` refuses to start with an `oidc` section or an `oidc-users.json` it cannot use. This
covers an unknown provider, a missing client ID, an unknown CA, a profile name that is not
kebab-case or is given twice, a rule without users and groups or naming an unknown profile, a
token that `token create` would refuse, a certificate without `types`, of an unknown type or a type
that `user_ekus` or the user name rules keep out, negative days, or an email domain that is not a
domain name, and a `user_ekus` rule that is not valid. Both files are read on each sign-in, so a
change applies without a restart.

`examples/oidc/` holds a `simple-ca.json` and an `oidc-users.json` for each provider, in
`generic/`, `keycloak/` and `entra/`; the Entra ID one gives its profiles by app roles alone,
apart from one user.

## User certificates

A profile with `certificate` gives its users a user certificate of themselves. The subject comes
from the ID token: the CN from `name_claim`, left out without it, and the `emailAddress`, which is
also the email address SAN, from `email_claim`. When the user sends a CSR, only its public key is
used; its subject, its SANs and its other extensions are not. Each sign-in issues a new
certificate, and the certificates issued before stay valid until they expire or are revoked.
Servers, and certificates renewed without a person, are given their certificates by tokens or
setup codes of the [signing API](signing-api.md), not by the OIDC sign-in.

```json
{
  "user_ekus": {
    "and": [
      {"allow": ["clientAuth", "emailProtection", "codeSigning", "1.3.6.1.4.1.99999.20"]},
      {"or": [{"require": ["clientAuth"]}, {"require": ["emailProtection"]}]},
      {"not": {"require": ["serverAuth"]}}
    ]
  },
  "profiles": [
    {
      "name": "staff",
      "certificate": {
        "ca": "people",
        "types": ["person", "user"],
        "days": 30,
        "email_domains": ["example.com"]
      }
    }
  ],
  "rules": [
    {
      "groups": ["staff"],
      "profile": "staff"
    }
  ]
}
```

The `certificate` section of a profile:

- `ca` - required: the CA that signs the certificates, an issuing CA, or `""` for the root CA,
  apart from the `ca` of the token. Without it, the profile gives no certificate, and `serve`
  logs so at startup;
- `types` - the certificate types the profile offers, one or more types of `simple-ca.json`,
  built-in or of its `types` section. Each has the user name rules, at least one extended key
  usage, and extended key usages that meet `user_ekus`;
- `days` - the validity in days, `days.cert` of `simple-ca.json` by default, else 365;
- `email_domains` - the domains of the email address, with their subdomains; any domain without
  them.

`user_ekus`, at the top of `oidc-users.json`, is the rule on the extended key usages of every type
of `types`. It is a node, an object of exactly one key:

| Key | Value | Holds when |
|---|---|---|
| `require` | a list of extended key usages | the type has every one of them |
| `allow` | a list of extended key usages | the type has no other one |
| `and` | a list of nodes | every node holds |
| `or` | a list of nodes | a node holds |
| `not` | a node | the node does not hold |

An extended key usage is a name, such as `clientAuth`, or a numeric OID, as in the `types` of
`simple-ca.json`, and a name is the same usage as its OID. A usage the type must not have is
`not` of `require`. `allow` admits the usages it names alone, so a usage that no rule names keeps
a type out. The lists are not empty, and the nodes are nested at most 8 levels deep. Without
`user_ekus`, the rule is `{"allow": ["clientAuth", "emailProtection", "codeSigning"]}`, which
the built-in type `user` meets and `server` does not. The example admits types of `clientAuth`
or `emailProtection`, with `codeSigning` and the OID `1.3.6.1.4.1.99999.20` besides, and no
`serverAuth`.

A profile that gives a certificate gives its tokens the scope `self-cert`, beside the scopes of
`token`, and a profile of a certificate alone gives a token of `self-cert` alone, with the
validity, hosts and networks of the `tokens` section of `simple-ca.json`. The OIDC sign-in alone
grants `self-cert`: `token create` and the token page refuse it, `token.scopes` of a profile may
not name it, and the scope `*` does not stand for it. The sign-in records in the token the
profile, the email address of `email_claim`, when it is an email address and `email_verified` is
not `false`, and the name of `name_claim`; `token describe` shows them. A token of `self-cert`
gets user certificates of that email address and that name alone, at `/api/self-cert`, for as
long as it is valid and its profile gives a certificate.

A certificate is refused with `403 Forbidden` when the token has no recorded email address, when
the email address is not in `email_domains`, when the profile no longer gives a certificate, and
when the request names a type the profile does not offer. A profile of several types needs the
type of the request; without it, the answer is `409 Conflict` with the types. The certificate is
stored in the directory of the CA of `certificate.ca` as `NAME-SERIAL_cert.pem`, with `NAME` the
name of the user's token, recorded in the token as a certificate of the signing API is, and logged
with the token, the OIDC user and the client.

There are three ways to get it, all with a token of `self-cert`.

- **The page `/self-cert`**, "Get my certificate", which the index page links to, with `--webui`,
  once the user has signed in there with OIDC and the token has `self-cert`. The page uses that
  token, with no sign-in of its own, and asks for the sign-in on the index page without it. The
  user chooses to have the key generated, of the type of the CA key, `ec` or `rsa`, or uploads or
  pastes a CSR. A generated key is returned in a PKCS#12 file, with a random password shown once,
  and `serve` keeps no copy of it. The page also shows the certificate with its chain, and asks
  for the type for a profile of several types.
- **`request-cert --oidc SERVE_URL`**, for a machine where the certificate is used, such as a
  server, or where `serve` runs without `--webui`. It signs the user in with the client of
  `cli_client_id`: the authorization code flow with PKCE, the browser sent back to
  `http://127.0.0.1:PORT` on a free port of the machine. It opens the browser at the sign-in URL
  and prints the URL, or only prints it with `--no-browser`, and waits 5 minutes for the browser
  to come back.
- **`request-cert --oidc-device SERVE_URL`**, the device authorization grant of the same client:
  it prints the verification URL and the code to enter there, on any device, and polls the
  provider until the user has signed in. The provider must name a
  `device_authorization_endpoint` in its discovery document.

`request-cert` exchanges the ID token at `/api/oidc-token` for a token of its own, `NAME-cli`, of
the scope `self-cert` alone, valid for 10 minutes and replaced at its next sign-in, so the token
the browser holds is not touched. It then makes an EC P-256 key and requests the certificate at
`/api/self-cert` with that token, and writes `NAME_key.pem`, `NAME_cert.pem` and
`NAME_chain.pem` to `--out-dir`, `NAME` being `--name`, else the local part of the email address
of the ID token. `SERVE_URL` is the URL of `serve`, such as `https://pki.example.com:8443`; the
profile gives the CA. `--type` names the type, among those of the profile, and is needed when it
offers several. `--token-file`, `--setup-code`, `--days` and a CN are refused with these options.

```sh
request-cert --oidc --out-dir ~/.certs https://pki.example.com:8443
request-cert --oidc-device --type person --name laptop https://pki.example.com:8443
```

The client of `request-cert` is another public client of the provider than that of the pages, as
described for each provider below. Its roles are its own: a Keycloak client role, in
`resource_access.CLIENT_ID.roles`, or an Entra ID app role, gives a profile only through the
client it is assigned on.

## Requests and responses

`GET /api/oidc` answers with the settings the pages sign in with, or `404 Not Found` when the
sign-in is off, `500 Internal Server Error` when `simple-ca.json` cannot be read, and
`502 Bad Gateway` when the discovery document of the provider cannot be read:

```json
{
  "provider": "keycloak",
  "label": "Keycloak",
  "client_id": "simple-ca",
  "scopes": [
    "openid",
    "profile",
    "email"
  ],
  "authorization_endpoint": "https://sso.example.com/realms/lab/protocol/openid-connect/auth",
  "token_endpoint": "https://sso.example.com/realms/lab/protocol/openid-connect/token",
  "redirect_path": "/oidc-callback",
  "reuse_token": false
}
```

With `cli_client_id`, the answer also has `cli_client_id`, `cli_scopes` and `email_claim`, and
`device_authorization_endpoint` when the provider has one, the settings `request-cert` signs in
with.

`POST /api/oidc-token` takes a JSON body of at most 64 KiB, `{"id_token": "eyJ..."}`, and
answers as [/api/token-setup](signing-api.md#setup-code-exchange) does:
`{"ca": "servers", "name": "alice-example-com", "token": "eyJ...", "scopes": ["sign", "self-cert"],
"user": "alice@example.com"}`. An ID token of `cli_client_id`, of a profile that gives a
certificate, gives the token `alice-example-com-cli` of the scope `self-cert` alone, valid for 10
minutes, which replaces the one before it without asking; it takes no `replace` or `reuse`.

When the user has an active token there, the answer is `409 Conflict` naming it, and nothing is
made:

```json
{
  "error": "the token alice-example-com of this user is active",
  "active": {
    "ca": "servers",
    "name": "alice-example-com",
    "issued": "2026-11-03T21:10:00Z",
    "expires": "2026-11-04T05:10:00Z"
  }
}
```

The ID token is not used up by that answer, so the same body can be sent again with one of:

- `"replace": true`, which makes the new token;
- `"reuse": true`, which, with `reuse_token`, answers with the active token instead.

Any other error is `{"error": "..."}` with the status:

- `400 Bad Request` - a body that is not a JSON object with a non-empty `id_token` and no other
  keys than `id_token`, `replace` and `reuse`, `reuse` without `reuse_token`, or `replace` and
  `reuse` together;
- `401 Unauthorized` - an ID token `serve` does not accept, one used before, or one of
  `client_id` without a nonce;
- `403 Forbidden` - a user without a user claim or a profile, an ID token of `cli_client_id` of a
  profile that gives no certificate, a user claim that makes no kebab-case token name, or a
  client the token of the profile is not accepted from;
- `404 Not Found` - the sign-in is off;
- `409 Conflict` without `active` - the name of the token belongs to another token;
- `413 Request Entity Too Large` - a body larger than 64 KiB;
- `415 Unsupported Media Type` - a body that is not `application/json`;
- `500 Internal Server Error` - `simple-ca.json` cannot be read;
- `429 Too Many Requests` - a client held back after refused ID tokens, as described in
  [Refused credentials](signing-api.md#refused-credentials).

Every token made is logged with the OIDC user and the client.

`POST /api/self-cert` takes a token of the scope `self-cert` as its bearer token, and a JSON body
of at most 64 KiB with a CSR, `{"csr": "-----BEGIN CERTIFICATE REQUEST-----..."}`, or
`{"generate": true}`, with an optional `"key_type"`, `ec` or `rsa`, the type of the CA key without
it. `"type"` names one of the types of the profile, and is needed when it offers several. It
answers with the certificate of the user the token was made for:

```json
{
  "ca": "people",
  "name": "alice-example-com",
  "type": "person",
  "serial": "5F3A...",
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "chain": "-----BEGIN CERTIFICATE-----..."
}
```

`chain` is the certificate followed by the certificate of its CA when that CA is an issuing CA.
With `generate`, the answer adds `file`, the name of the PKCS#12 file, `password`, its password,
and `pfx`, the file in base64. A profile of several types and a request without `type` give
`409 Conflict` with `{"error": "...", "types": ["person", "user"]}`. Any other error is
`{"error": "..."}` with the status:

- `400 Bad Request` - a body that is not one of these, such as one with `id_token`, a CSR that
  does not parse, `csr` and `generate` together or neither, or `key_type` without `generate`;
- `401 Unauthorized` - no token, or one `serve` does not accept, such as an expired or revoked
  one;
- `403 Forbidden` - a token without the scope `self-cert`, or used from a client it does not
  allow, and the refusals of [User certificates](#user-certificates);
- `404 Not Found` - the sign-in is off;
- `413`, `415`, `429` and `500` as for `/api/oidc-token`.

## Generic provider

Register a public client for the authorization code flow with PKCE (S256), without a client
secret. Register `https://pki.example.com:8443/oidc-callback` as its redirect URI, the origin of
`serve` followed by `/oidc-callback`. Allow the origin of `serve`,
`https://pki.example.com:8443`, to call the token endpoint (CORS). Then set `issuer` and
`client_id`, and the claims of the provider when they differ from those of `generic`.

For `request-cert`, register a second public client, without a client secret, with the redirect
URI `http://127.0.0.1`, any port of which the provider must accept (RFC 8252), and the device
authorization grant when the provider offers it. Set its client ID as `cli_client_id`.

## Keycloak

In the admin console of the realm:

1. Clients, Create client: an OpenID Connect client with the client ID `simple-ca`.
2. Capability config: Client authentication off, which makes it a public client, and Standard
   flow on.
3. Login settings: Valid redirect URIs `https://pki.example.com:8443/oidc-callback`, and Web
   origins `https://pki.example.com:8443`, which lets the browser redeem the code.
4. Advanced: Proof Key for Code Exchange Code Challenge Method `S256`.
5. For the groups, add a Group Membership mapper to the dedicated scope of the client, with the
   token claim name `groups` and Add to ID token on. With Full group path on, the groups are paths
   such as `/web-team`, and the rules must name them so.
6. For the roles, check that the mappers of the realm roles and the client roles, in the `roles`
   client scope of the client, add their claims to the ID token, and turn on Add to ID token
   where they do not. The roles are then in `realm_access.roles` and
   `resource_access.simple-ca.roles`.

```json
{
  "oidc": {
    "provider": "keycloak",
    "issuer": "https://sso.example.com/realms/lab",
    "client_id": "simple-ca"
  }
}
```

A realm role or a client role named like a profile, such as `web-signer`, gives that profile.

For `request-cert`, create a second public client, such as `simple-ca-cli`, with Standard flow on
and PKCE `S256` as above, the Valid redirect URI `http://127.0.0.1`, which allows any port, no Web
origins, and the OAuth 2.0 device authorization grant turned on in its capabilities for
`--oidc-device`. Add the same mappers to its dedicated scope, and set
`"cli_client_id": "simple-ca-cli"`. Its client roles are in `resource_access.simple-ca-cli.roles`.

## Entra ID

In the Microsoft Entra admin center:

1. Entra ID, App registrations, New registration, for the accounts of this organizational
   directory only.
2. Authentication, Add a platform, Single-page application, with the redirect URI
   `https://pki.example.com:8443/oidc-callback`. The redirect URI must be of the single-page
   application type, which lets the browser redeem the code with PKCE.
3. The issuer is `https://login.microsoftonline.com/TENANT-ID/v2.0`, with the Directory (tenant)
   ID of the Overview, and the client ID is its Application (client) ID.

```json
{
  "oidc": {
    "provider": "entra",
    "issuer": "https://login.microsoftonline.com/TENANT-ID/v2.0",
    "client_id": "00001111-aaaa-2222-bbbb-3333cccc4444"
  }
}
```

For `request-cert`, register a second application:

1. App registrations, New registration, for the accounts of this organizational directory only.
2. Authentication, Add a platform, Mobile and desktop applications, with the redirect URI
   `http://127.0.0.1`; Entra ID ignores its port. The portal refuses a plain HTTP `127.0.0.1`
   redirect URI, so add it to `replyUrlsWithType` in the Manifest, with the type
   `InstalledClient`.
3. Authentication, Allow public client flows, Yes, for the device code flow of `--oidc-device`.
4. Token configuration, Add optional claim, ID, `email`, for the email address of the
   certificate; without it, `preferred_username` gives it.
5. Set its Application (client) ID as `cli_client_id`, and assign its app roles to the users of
   the certificates.

### App roles

App roles name the profiles directly: the ID token of a user carries the roles of the user in its
`roles` claim, and a role whose value is the name of a profile gives that profile.

1. App registrations, the application, App roles, Create app role: a display name, the allowed
   member types Users/Groups, and the value, the name of a profile such as `web-signer`. A
   value cannot contain spaces, and must be kebab-case to name a profile.
2. Enterprise apps, the application, Users and groups, Add user/group: the users, or groups, and
   the role. Assigning a group to a role needs Microsoft Entra ID P1 or higher; a user can be
   assigned without it.

A user without a role assignment has no `roles` claim and is matched by the rules alone. Roles
have no overage limit, unlike groups, which makes them the way to match Entra ID users.

```json
{
  "profiles": [
    {
      "name": "ca-admin",
      "token": {
        "valid": "8h",
        "scopes": [
          "tokens",
          "certs"
        ]
      }
    },
    {
      "name": "web-signer",
      "ca": "servers",
      "token": {
        "valid": "1h",
        "scopes": ["sign"],
        "domains": ["lab.example.org"]
      }
    },
    {
      "name": "cert-viewer",
      "ca": "servers",
      "token": {
        "valid": "8h",
        "scopes": ["certs"]
      }
    }
  ],
  "rules": [
    {
      "users": ["alice@example.com"],
      "profile": "ca-admin"
    }
  ]
}
```

### Groups

The `groups` claim is added in Token configuration, Add groups claim. It holds the object IDs of
the groups, not their names, so a rule names a group by its object ID. A user in more than 200
groups gets no `groups` claim, but an overage claim instead; `serve` logs it, and the user is
matched by no group. Assigning only the groups of the application, or app roles, avoids the
overage. With "Emit groups as role claims", the `roles` claim holds the groups in place of the app
roles.
