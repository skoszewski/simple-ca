---
title: OIDC sign-in
---

`serve` can hand out tokens to the users of an OpenID Connect provider, next to
[setup codes](signing-api.md#one-time-setup-codes): a user signs in at the provider, and `serve`
makes the user's token from the profile `oidc-users.json` gives the user. Generic OIDC providers,
Keycloak and Microsoft Entra ID are supported.

The sign-in is offered as a "Sign in with LABEL" button on:

- the token page `/tokens/`, the certificate page `/certificates/` and the audit page `/audit/`,
  in the dialog asking for the token; the token of the sign-in signs in, when it has the scope of
  the page;
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

A claim is a dotted path into the ID token, such as `realm_access.roles`, and the segment
`CLIENT_ID` stands for the client ID. A claim is a string or a list of strings.

| `provider` | `label` | `user_claim` | `groups_claim` | `roles_claim` |
|---|---|---|---|---|
| `generic` | `OIDC` | `sub` | `groups` | `roles` |
| `keycloak` | `Keycloak` | `preferred_username` | `groups` | `realm_access.roles`, `resource_access.CLIENT_ID.roles` |
| `entra` | `Entra ID` | `preferred_username` | `groups` | `roles` |

`serve` accepts an ID token signed with RS256, ES256, ES384, ES512 or EdDSA by a key of the JWKS
of the provider. Its `iss` must be the issuer and its `aud` must hold the client ID. Its `azp`,
when present, must be the client ID too. It must have a subject and a `nonce`, must not have
expired, and its `iat` must be present and at most 2 minutes ahead of the clock of `serve`. Its
`nonce` gives one token: an ID token that has given a token is refused after that. The JWKS is
fetched again for a key it does not have, at most once a minute.

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

A profile is a token profile:

- `name` - a **kebab-case** name, such as `ca-admin`; a role of the same value gives the profile.
- `ca` - the issuing CA of the tokens, empty or left out for the root CA. Its key must be in its
  directory.
- `token` - the settings of the token, those of the `tokens` section of `simple-ca.json`:
  `token_type`, `valid`, `scopes`, `types`, `domains`, `ips`, `hosts` and `networks`, and
  `localhost`, as `token create --localhost` gives it. A setting left out takes its value from the
  `tokens` section, as for `token create`; `localhost` has no default. `keep_expired` and `issuer`
  are not settings of a profile. A `token_type` with an audience gives the user a token for
  [workload identity federation](workload-identity.md); its audience and claims are those of the
  type.

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
kebab-case or is given twice, a rule without users and groups or naming an unknown profile, and a
token that `token create` would refuse. Both files are read on each sign-in, so a change applies
without a restart.

`examples/oidc/` holds a `simple-ca.json` and an `oidc-users.json` for each provider, in
`generic/`, `keycloak/` and `entra/`; the Entra ID one gives its profiles by app roles alone,
apart from one user.

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

`POST /api/oidc-token` takes a JSON body of at most 64 KiB, `{"id_token": "eyJ..."}`, and
answers as [/api/token-setup](signing-api.md#setup-code-exchange) does:
`{"ca": "servers", "name": "alice-example-com", "token": "eyJ...", "scopes": ["sign"]}`.

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
- `401 Unauthorized` - an ID token `serve` does not accept, or one used before;
- `403 Forbidden` - a user without a user claim or a profile, a user claim that makes no
  kebab-case token name, or a client the token of the profile is not accepted from;
- `404 Not Found` - the sign-in is off;
- `409 Conflict` without `active` - the name of the token belongs to another token;
- `415 Unsupported Media Type` - a body that is not `application/json`;
- `500 Internal Server Error` - `simple-ca.json` cannot be read;
- `429 Too Many Requests` - a client held back after refused ID tokens, as described in
  [Refused credentials](signing-api.md#refused-credentials).

Every token made is logged with the OIDC user and the client.

## Generic provider

Register a public client for the authorization code flow with PKCE (S256), without a client
secret. Register `https://pki.example.com:8443/oidc-callback` as its redirect URI, the origin of
`serve` followed by `/oidc-callback`. Allow the origin of `serve`,
`https://pki.example.com:8443`, to call the token endpoint (CORS). Then set `issuer` and
`client_id`, and the claims of the provider when they differ from those of `generic`.

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
