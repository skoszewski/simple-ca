---
title: simple-ca.json
---

The settings of the root CA and its issuing CAs, in the root CA directory; a command working with
an issuing CA reads the file of its root CA. The file is optional: `ca create --ca-url`
writes it, and it can be written or edited by hand. A setting not described here is an error.

```json
{
  "ca_publish_base_url": "http://pki.example.com",
  "days": {
    "cert": 90,
    "crl": 7
  },
  "types": {
    "device": {
      "key_usage": ["digitalSignature"],
      "ext_key_usage": [
        "clientAuth",
        "1.3.6.1.4.1.99999.10"
      ]
    },
    "person": {
      "names": "user",
      "key_usage": [
        "digitalSignature",
        "keyEncipherment"
      ],
      "ext_key_usage": []
    },
    "user": {
      "key_usage": [
        "digitalSignature",
        "contentCommitment",
        "keyEncipherment"
      ]
    }
  },
  "acme": {
    "domains": [
      "example.com",
      "lab.example.org"
    ],
    "days": 30
  },
  "audit": {
    "file": "/var/log/simple-ca/audit.log"
  },
  "serve": {
    "trusted_proxies": [
      "127.0.0.1",
      "10.0.0.0/8"
    ],
    "request_log": true
  },
  "tokens": {
    "valid": "8h",
    "domains": ["lab.example.org"],
    "networks": ["192.168.1.0/24"],
    "keep_expired": "720h"
  },
  "oidc": {
    "provider": "keycloak",
    "issuer": "https://sso.example.com/realms/lab",
    "client_id": "simple-ca"
  }
}
```

- `ca_publish_base_url` - base URL for the AIA and CRL Distribution Point extensions.
- `acme` - the [ACME](acme.md) server of `serve`:
  - `domains` - the domains whose names and the names below them it issues certificates for;
    without them, `serve` has no ACME server;
  - `days` - the validity of its certificates, 90 days by default.
- `days` - defaults for `--days`: `ca`, `cert`, `crl`.
- `audit` - the [audit log](audit.md):
  - `file` - its path, absolute or relative to the root CA directory; `audit.log` by default.
- `oidc` - the [OIDC sign-in](oidc.md) of the pages of `serve`: `provider`,
  `issuer`, `client_id`, `scopes`, `label`, `user_claim`, `groups_claim`, `roles_claim` and
  `reuse_token`; the users get their tokens from the profiles of `oidc-users.json` in the root CA
  directory.
- `serve` - the settings of [serve](serve.md):
  - `trusted_proxies` - the addresses and prefixes of the proxies whose `X-Forwarded-For` header
    names the client of every request to `serve`, such as of the [signing API](signing-api.md),
    the pages, the setup code exchange, the OIDC sign-in and ACME; `serve --trusted-proxy`
    replaces them;
  - `request_log` - `true` logs each request, `false` by default; `serve --request-log` sets it.
- `tokens` - the defaults of [token create](signing-api.md#token-create-list-renew-revoke-and-purge);
  the option of the same name overrides each: `valid`, a duration such as `8h`, `scopes`,
  `types`, `domains`, `ips`, `localhost`, `hosts`, and `networks`, a list of prefixes. `--host`
  and `--network` together replace both `hosts` and `networks`. `types`, `domains`, `ips` and
  `localhost` apply only to tokens with the scope `sign`; `scopes` and `types` may be `["*"]`,
  every scope or every type. `keep_expired`, a duration such as `720h`, is how long `serve` keeps
  an expired or revoked token before removing it; without it, such tokens stay until
  `token purge` removes them.
- `types` - certificate types for `cert create --type` and `cert sign --type`, by **kebab-case**
  name: words of lower-case letters and digits joined by hyphens, such as `web-server`. A type
  named `server`, `user` or `none` redefines the built-in type, and any other name defines a new
  type. Each type has:
  - `names` - the name rules of the subject and SANs, `server` or `user`, as described under
    [cert create](usage.md#cert-create); a new type has the server rules without it;
  - `key_usage` - its key usages;
  - `ext_key_usage` - its extended key usages, names or numeric OIDs.

  The names are those of `--ku` and `--eku`. A field left out keeps its value of the built-in
  type, none for a new type, and `[]` gives the type none. `--ku` and `--eku` add to the usages of
  the type.

# theme.json

The colours of the pages of [serve](serve.md) about one CA, in place of the built-in ones, so the
pages of one CA are told apart from those of another, such as a production root CA from its
issuing CAs, or a lab CA from a production one. The file is optional, and each CA directory, of
the root CA or of an issuing CA, has its own: a CA without it keeps the built-in colours, also
when its root CA has one.

```json
{
  "light": {
    "head": "#7c2d12",
    "head-link": "#fdba74",
    "action": "#c2410c",
    "action-hover": "#ea580c"
  },
  "dark": {
    "head": "#431407",
    "action": "#c2410c"
  }
}
```

`light` is for the light theme and `dark` for the dark theme, each mapping roles to CSS colours:
a hex colour such as `#7c2d12`, a function such as `rgb()`, `hsl()` or `oklch()`, or a colour
name. A role left out keeps its built-in colour, and a setting not described here is an error.

| Page | Colours |
|---|---|
| the index page, `/token-setup`, `/oidc-callback` | those of the root CA |
| `/sign`, `/NAME/sign` | those of the CA of the form |
| the token and certificate pages | those of the CA chosen in their selector, changing with it |
| the audit page | those of the root CA, or of its own CA for an issuing CA token |

`serve` refuses to start with an unknown role or a value that is not a colour in the
`theme.json` of any CA, and the pages read the colours on each request, so a change shows
without a restart.

```sh
cp examples/themes/crimson.json /etc/simple-ca/theme.json
```

The root CA of `/etc/simple-ca` takes the red colours, and its issuing CAs keep theirs.

## Theme colours

The roles of `theme.json`, with their built-in colours and those of the example above, an orange
header and orange buttons. The built-in colours are those of the Tailwind CSS palette, which
defines them in OKLCH; their hex values here are the sRGB colours a browser draws for them.

| Role | Colours | Light, built in | Dark, built in | Light, example | Dark, example |
|---|---|---|---|---|---|
| `page` | background of the page | `#f1f5f9` | `#020618` | | |
| `ink` | text | `#0f172b` | `#f1f5f9` | | |
| `muted` | quieter text | `#62748e` | `#90a1b9` | | |
| `card` | card holding the content | `#ffffff` | `#0f172b` | | |
| `line` | lines of the card and its tables | `#e2e8f0` | `#1d293d` | | |
| `head` | header of the card | `#0f172b` | `#1d293d` | `#7c2d12` | `#431407` |
| `head-ink` | text of the header | `#f1f5f9` | `#f8fafc` | | |
| `head-muted` | quieter text of the header | `#cad5e2` | `#cad5e2` | | |
| `head-link` | links of the header | `#74d4ff` | `#74d4ff` | `#fdba74` | |
| `link` | other links | `#0069a8` | `#00bcff` | | |
| `accent` | band of the CA bundle | `#f0f9ff` | `#0d2037` | | |
| `accent-line` | edge of the band | `#b8e6fe` | `#1d293d` | | |
| `accent-title` | title of the band | `#052f4a` | `#dff2fe` | | |
| `accent-ink` | text of the band | `#024a70` | `#b8e6fe` | | |
| `action` | main buttons | `#0069a8` | `#0069a8` | `#c2410c` | `#c2410c` |
| `action-hover` | main buttons under the pointer | `#0084d1` | `#0084d1` | `#ea580c` | |
| `action-ink` | text of the main buttons | `#ffffff` | `#ffffff` | | |
| `solid` | buttons of the CA files | `#0f172b` | `#f1f5f9` | | |
| `solid-hover` | those buttons under the pointer | `#314158` | `#cad5e2` | | |
| `solid-ink` | text of those buttons | `#ffffff` | `#0f172b` | | |
| `subtle` | badges of a role, background under the pointer | `#f1f5f9` | `#1d293d` | | |
| `subtle-ink` | text of those badges | `#45556c` | `#cad5e2` | | |
| `field` | form fields | `#ffffff` | `#1d293d` | | |
| `field-line` | edges of the form fields | `#cad5e2` | `#45556c` | | |
| `good` | badges of success, such as the days left | `#d0fae5` | `#002c22` | | |
| `good-ink` | text of those badges | `#007a55` | `#5ee9b5` | | |
| `warn` | warnings | `#fffbeb` | `#461901` | | |
| `warn-line` | edges of the warnings | `#fee685` | `#7b3306` | | |
| `warn-ink` | text of the warnings | `#7b3306` | `#fee685` | | |
| `bad` | errors, and badges such as expired or revoked | `#fef2f2` | `#460809` | | |
| `bad-line` | edges of the errors | `#ffc9c9` | `#82181a` | | |
| `bad-ink` | text of the errors and those badges | `#9f0712` | `#ffc9c9` | | |

An empty example cell keeps the built-in colour.

`examples/themes/` holds five themes, each a `theme.json` to copy into a CA directory. They
colour the header, its links, the other links, the main buttons and the band of the CA bundle,
for the light and the dark theme:

| File | Colour | Light header | Dark header | Buttons |
|---|---|---|---|---|
| `examples/themes/ember.json` | orange | `#7c2d12` | `#431407` | `#c2410c` |
| `examples/themes/forest.json` | green | `#14532d` | `#052e16` | `#15803d` |
| `examples/themes/violet.json` | purple | `#4c1d95` | `#2e1065` | `#6d28d9` |
| `examples/themes/crimson.json` | red, such as for a production CA | `#7f1d1d` | `#450a0a` | `#b91c1c` |
| `examples/themes/ocean.json` | teal | `#134e4a` | `#042f2e` | `#0f766e` |

```sh
cp examples/themes/forest.json /etc/simple-ca/servers/theme.json
```
